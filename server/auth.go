package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"artemis/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash" // legacy single-user password (only used for first-start migration to rbac_users)
	// defaultSessionTTL is the default session (JWT) lifetime, and also the "idle timeout" window:
	// during active use the backend slides the renewal (see requireAuth); once idle longer than this
	// the token expires and re-login is required. Can be overridden via the auth.session_ttl_minutes setting (minutes).
	defaultSessionTTL = 60 * time.Minute
	sessionTTLKey     = "auth.session_ttl_minutes"
	keyChars          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type ctxKey int

const accessCtxKey ctxKey = 1

// authClaims carries the user id (Subject) + username + the password version at issue time (token_version).
// Ver makes "change-password/disable immediately logs out" work: it is compared against the current token_version in the DB on validation, and rejected if they differ.
type authClaims struct {
	Username string `json:"usr"`
	Ver      int    `json:"ver"`
	jwt.RegisteredClaims
}

// CurrentAccess reads the current logged-in user's RBAC authorization profile from the request context (injected by requireAuth).
func CurrentAccess(r *http.Request) *db.RBACAccess {
	acc, _ := r.Context().Value(accessCtxKey).(*db.RBACAccess)
	return acc
}

// loadOrCreateJWTKey reads / generates the 32-byte HS256 signing key.
func loadOrCreateJWTKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, jwtKeyFilename)
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// sessionTTL reads the session-lifetime (minutes) setting, falling back to the default when unset/invalid.
func (s *Server) sessionTTL() time.Duration {
	if s.m != nil && s.m.pg != nil {
		if m := s.m.pg.GetInt(sessionTTLKey, 0); m > 0 {
			return time.Duration(m) * time.Minute
		}
	}
	return defaultSessionTTL
}

// signJWT issues an HS256 token with the default session TTL (tests use this).
func signJWT(key []byte, userID, username string) (string, error) {
	return signJWTTTL(key, userID, username, 0, defaultSessionTTL)
}

// signJWTTTL issues an HS256 token that expires after ttl, stamped with the user's
// current token_version (ver) so a later password change / disable invalidates it.
func signJWTTTL(key []byte, userID, username string, ver int, ttl time.Duration) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, authClaims{
		Username: username,
		Ver:      ver,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}).SignedString(key)
}

// parseJWT validates and returns the claims.
func parseJWT(tokenStr string, key []byte) (*authClaims, bool) {
	var c authClaims
	t, err := jwt.ParseWithClaims(tokenStr, &c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return nil, false
	}
	return &c, true
}

// extractToken reads the JWT from Authorization: Bearer, artemis_token cookie, or ?token=.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artemis_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// requireAuth validates the JWT + resolves user/permissions and injects them into the context. /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		claims, ok := parseJWT(extractToken(r), s.jwtKey)
		if !ok {
			writeErr(w, 401, "non autorizzato o token scaduto")
			return
		}
		// Resolve the authorization profile (for RBAC enforcement and management); reject if the account is disabled or the token version is stale.
		if s.m != nil && s.m.pg != nil && claims.Subject != "" {
			acc, err := s.m.pg.ResolveRBACAccess(claims.Subject)
			if err == nil && acc != nil {
				if !acc.User.Enabled {
					writeErr(w, 403, "account disattivato")
					return
				}
				// token version check: after a password change / disable, token_version is incremented; an old
				// token whose Ver lags is invalidated, forcing a re-login.
				if claims.Ver != acc.User.TokenVersion {
					writeErr(w, 401, "sessione di accesso non più valida, effettua di nuovo l'accesso")
					return
				}
				// Sliding renewal (= idle timeout): once the token is past the halfway point and still actively
				// used, issue a new token via the X-Refresh-Token response header for the frontend to swap in; if
				// idle longer than the session lifetime it expires naturally and requires re-login.
				if claims.ExpiresAt != nil {
					ttl := s.sessionTTL()
					if rem := time.Until(claims.ExpiresAt.Time); rem > 0 && rem < ttl/2 {
						if fresh, err := signJWTTTL(s.jwtKey, claims.Subject, claims.Username, acc.User.TokenVersion, ttl); err == nil {
							w.Header().Set("Access-Control-Expose-Headers", "X-Refresh-Token")
							w.Header().Set("X-Refresh-Token", fresh)
						}
					}
				}
				r = r.WithContext(context.WithValue(r.Context(), accessCtxKey, acc))
				// Permission enforcement. Safety valves: unmapped routes pass through; admin (full rights) is never blocked; the rbac.enforce switch defaults to true.
				if s.m.pg.GetBool("rbac.enforce", true) {
					if perm := permissionForRequest(r.Method, r.URL.Path); perm != "" && !acc.Permissions[perm] {
						writeErr(w, 403, "permessi insufficienti: "+perm)
						return
					}
				}
			}
		}
		h.ServeHTTP(w, r)
	})
}

// bootstrapRBAC, on first start, migrates the legacy single-user password into the built-in admin and seeds roles/permissions (idempotent).
func (s *Server) bootstrapRBAC() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	legacyHash, _, _ := s.m.pg.GetSetting(authPassKey)
	if err := s.m.pg.BootstrapRBAC(legacyHash); err != nil {
		log.Printf("[rbac] bootstrap 失败: %v", err)
		return
	}
	if strings.TrimSpace(legacyHash) != "" {
		log.Printf("[rbac] 多用户权限就绪（已迁移旧密码为内置 admin）")
	} else {
		log.Printf("[rbac] 多用户权限就绪")
	}
}

// GET /api/auth/status: whether it is already initialized (a platform user exists).
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	needs, err := pg.RBACNeedsBootstrap()
	if err != nil {
		writeErr(w, 500, "query fallita")
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": !needs})
}

// POST /api/auth/init: set the admin password on first start (creates the built-in admin).
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ip := clientIP(r)
	// fail-closed: if the init-guard query errors, always reject; never treat a query failure as
	// "not initialized" and allow setting the password (otherwise a query failure could be used to reset the admin credentials).
	needs, err := pg.RBACNeedsBootstrap()
	if err != nil {
		pg.RecordAudit("", "auth", "init", "fail", ip, "query della guardia di inizializzazione fallita (rifiutata)", nil)
		writeErr(w, 503, "servizio temporaneamente non disponibile")
		return
	}
	if !needs {
		pg.RecordAudit("", "auth", "init", "fail", ip, "piattaforma già inizializzata, reimpostazione della password rifiutata", nil)
		writeErr(w, 403, "già inizializzato")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "formato della richiesta non valido")
		return
	}
	if msg := validatePasswordStrength(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "crittografia della password fallita")
		return
	}
	if err := pg.BootstrapRBAC(string(hash)); err != nil {
		writeErr(w, 500, "inizializzazione fallita: "+err.Error())
		return
	}
	_ = pg.SetSetting(authPassKey, string(hash)) // kept for compatibility
	ver := 0
	if u, e := pg.GetRBACUserByID("admin"); e == nil && u != nil {
		ver = u.TokenVersion
	}
	tok, err := signJWTTTL(s.jwtKey, "admin", "admin", ver, s.sessionTTL())
	if err != nil {
		writeErr(w, 500, "generazione del token fallita")
		return
	}
	pg.RecordAudit("admin", "auth", "init", "success", ip, "inizializzazione della password amministratore al primo avvio", nil)
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password: change the current logged-in user's password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	claims, ok := parseJWT(extractToken(r), s.jwtKey)
	if !ok {
		writeErr(w, 401, "non autorizzato")
		return
	}
	u, err := pg.GetRBACUserByID(claims.Subject)
	if err != nil {
		writeErr(w, 401, "utente non trovato")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "formato della richiesta non valido")
		return
	}
	if msg := validatePasswordStrength(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	ip := clientIP(r)
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.OldPassword)); err != nil {
		pg.RecordAudit(u.Username, "auth", "change_password", "fail", ip, "password attuale errata", nil)
		writeErr(w, 401, "password attuale errata")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "crittografia della password fallita")
		return
	}
	// UpdateRBACUserPassword increments token_version, invalidating all old tokens including the one in this request.
	if err := pg.UpdateRBACUserPassword(u.ID, string(newHash)); err != nil {
		writeErr(w, 500, "salvataggio fallito: "+err.Error())
		return
	}
	pg.RecordAudit(u.Username, "auth", "change_password", "success", ip, "modifica password riuscita", nil)
	// Issue a fresh token to the caller with the new version, to avoid "getting kicked out right after changing your own password"; old tokens on other devices still become invalid.
	fresh := ""
	if nu, e := pg.GetRBACUserByID(u.ID); e == nil && nu != nil {
		fresh, _ = signJWTTTL(s.jwtKey, nu.ID, nu.Username, nu.TokenVersion, s.sessionTTL())
	}
	writeJSON(w, 200, map[string]any{"ok": true, "token": fresh})
}

// POST /api/auth/login: validate username/password and return a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "formato della richiesta non valido")
		return
	}
	ip := clientIP(r)
	uname := strings.TrimSpace(req.Username)
	// Brute-force protection: check the lock state across both IP and account dimensions. On a lock
	// hit, return 429 immediately and do no credential comparison (bcrypt itself is CPU-intensive, so
	// blocking first also mitigates "mass attempts saturating CPU/connections").
	if locked, retry := s.loginLimiter.locked(ip, uname); locked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		pg.RecordAudit(uname, "auth", "login_locked", "fail", ip,
			fmt.Sprintf("blocco anti brute force attivato, raffreddamento residuo %ds", int(retry.Seconds())), nil)
		writeErr(w, 429, fmt.Sprintf("tentativi troppo frequenti, account/origine temporaneamente bloccati, riprova tra %d secondi", int(retry.Seconds())))
		return
	}
	u, err := pg.GetRBACUserByUsername(req.Username)
	if err != nil || u == nil || !u.Enabled {
		reason := "nome utente o password errati"
		if u != nil && !u.Enabled {
			reason = "account disattivato"
		}
		s.registerLoginFailure(pg, ip, uname)
		pg.RecordAudit(uname, "auth", "login_failed", "fail", ip, reason, nil)
		log.Printf("[auth] 登录失败 用户=%q ip=%s 原因=%s", uname, ip, reason)
		writeErr(w, 401, reason)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		s.registerLoginFailure(pg, ip, u.Username)
		pg.RecordAudit(u.Username, "auth", "login_failed", "fail", ip, "password errata", nil)
		log.Printf("[auth] 登录失败 用户=%q ip=%s 原因=密码错误", u.Username, ip)
		writeErr(w, 401, "nome utente o password errati")
		return
	}
	tok, err := signJWTTTL(s.jwtKey, u.ID, u.Username, u.TokenVersion, s.sessionTTL())
	if err != nil {
		writeErr(w, 500, "generazione del token fallita")
		return
	}
	s.loginLimiter.reset(ip, u.Username) // a successful login resets the failure count for this IP+account
	pg.RecordAudit(u.Username, "auth", "login", "success", ip, "accesso riuscito", nil)
	log.Printf("[auth] 登录成功 用户=%q ip=%s", u.Username, ip)
	writeJSON(w, 200, map[string]any{"token": tok})
}

// registerLoginFailure records one failure into the limiter; if it triggers a lock, it writes an audit entry so it is visible on the logs page.
func (s *Server) registerLoginFailure(pg *db.DB, ip, username string) {
	if s.loginLimiter.fail(ip, username, s.loginPolicy()) {
		pg.RecordAudit(username, "auth", "login_locked", "fail", ip, "numero di tentativi falliti oltre la soglia, bloccato temporaneamente", nil)
		log.Printf("[auth] 暴力破解锁定 用户=%q ip=%s", username, ip)
	}
}

// validatePasswordStrength returns an empty string = passed, otherwise = the reason shown to the user.
// Rules: length 8-128, at least two character classes (letters / digits / symbols), and not a single repeated character.
func validatePasswordStrength(pw string) string {
	if len(pw) < 8 {
		return "la password deve avere almeno 8 caratteri"
	}
	if len(pw) > 128 {
		return "password troppo lunga (massimo 128 caratteri)"
	}
	var hasLetter, hasDigit, hasOther bool
	allSame := true
	for i, r := range pw {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
		if i > 0 && rune(pw[i]) != rune(pw[0]) {
			allSame = false
		}
	}
	if allSame {
		return "la password non può essere un singolo carattere ripetuto"
	}
	classes := 0
	for _, b := range []bool{hasLetter, hasDigit, hasOther} {
		if b {
			classes++
		}
	}
	if classes < 2 {
		return "la password deve contenere almeno due tipi di caratteri (lettere / numeri / simboli)"
	}
	return ""
}

// clientIP extracts the client IP (prefers X-Forwarded-For / X-Real-IP, falls back to RemoteAddr).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}
