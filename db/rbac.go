package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Multi-user RBAC data layer (OpenArtemis platform permissions, based on PostgreSQL + a modular design).

const (
	RBACRoleAdmin    = "admin"
	RBACRoleOperator = "operator"
	RBACRoleAuditor  = "auditor"
	RBACRoleViewer   = "viewer"

	RBACScopeAll      = "all"
	RBACScopeAssigned = "assigned"
	RBACScopeOwn      = "own"
)

// RBACPermissions: the platform permission catalog (module:action), defined by OpenArtemis's actual modules.
var RBACPermissions = map[string]string{
	"auth:self":       "Gestire le proprie sessioni e password",
	"dashboard:read":  "Visualizzare la panoramica della dashboard",
	"task:read":       "Visualizzare task / catena di esplorazione / sessioni",
	"task:write":      "Creare / controllare task, inviare guida alla conversazione",
	"task:delete":     "Eliminare i task",
	"finding:read":    "Visualizzare i rilievi di vulnerabilità",
	"finding:write":   "Creare / aggiornare i rilievi di vulnerabilità",
	"finding:delete":  "Eliminare i rilievi di vulnerabilità",
	"traffic:read":    "Visualizzare le registrazioni del traffico",
	"asset:read":      "Visualizzare asset / aziende",
	"asset:write":     "Creare / importare / sincronizzare asset",
	"asset:delete":    "Eliminare asset",
	"llm:read":        "Visualizzare la configurazione LLM",
	"llm:write":       "Gestire la configurazione LLM e i modelli",
	"agent:read":      "Visualizzare la configurazione Agent",
	"agent:write":     "Gestire Agent / prompt / trigger",
	"mcp:read":        "Visualizzare i servizi MCP",
	"mcp:write":       "Gestire i servizi MCP",
	"skill:read":      "Visualizzare le skill",
	"skill:write":     "Creare / aggiornare le skill",
	"skill:delete":    "Eliminare le skill",
	"tool:read":       "Visualizzare gli strumenti",
	"tool:write":      "Gestire gli strumenti / strumenti personalizzati",
	"intercept:read":  "Visualizzare le regole di intercettazione / approvazioni",
	"intercept:write": "Gestire le regole di intercettazione / gestire le approvazioni",
	"log:read":        "Visualizzare i log del backend / audit",
	"config:read":     "Visualizzare la configurazione di sistema",
	"config:write":    "Modificare la configurazione di sistema",
	"knowledge:read":   "Visualizzare la knowledge base / ricerca",
	"knowledge:write":  "Creare / aggiornare documenti della knowledge base, configurare l'embedder",
	"knowledge:delete": "Eliminare documenti della knowledge base",
	"report:read":      "Visualizzare / scaricare report, modelli e impostazioni dei report",
	"report:write":     "Generare report, gestire modelli e impostazioni dei report",
	"report:delete":    "Eliminare report / modelli",
	"rbac:read":       "Visualizzare utenti / ruoli / permessi",
	"rbac:write":      "Gestire utenti / ruoli / permessi",
}

// RBACUser is a platform account.
type RBACUser struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"display_name"`
	PasswordHash string    `json:"-"`
	Enabled      bool      `json:"enabled"`
	IsBuiltin    bool      `json:"is_builtin"`
	TokenVersion int       `json:"-"` // bumped on password change/deactivation; written when signing a JWT, compared on verification, invalidated on mismatch
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RBACRole is a role (a permission set + a resource scope).
type RBACRole struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Scope       string    `json:"scope"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RBACAccess is a user's resolved authorization profile.
type RBACAccess struct {
	User        RBACUser        `json:"user"`
	Roles       []RBACRole      `json:"roles"`
	Permissions map[string]bool `json:"permissions"`
	Scope       string          `json:"scope"`
}

func newRBACID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func mergeScope(a, b string) string {
	if a == RBACScopeAll || b == RBACScopeAll {
		return RBACScopeAll
	}
	if a == RBACScopeAssigned || b == RBACScopeAssigned {
		return RBACScopeAssigned
	}
	return RBACScopeOwn
}

// RBACNeedsBootstrap reports whether there are no platform users yet (first startup needs to migrate/create admin).
func (d *DB) RBACNeedsBootstrap() (bool, error) {
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM rbac_users`).Scan(&n); err != nil {
		return false, err
	}
	return n == 0, nil
}

// BootstrapRBAC idempotently seeds the permission catalog + 4 system roles + grants;
// if there are no users and adminHash is passed, it uses it to create the built-in admin account (migrated from the old single-user password).
func (d *DB) BootstrapRBAC(adminHash string) error {
	now := time.Now()
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Permission catalog (upsert desc; drop stale keys)
	for key, desc := range RBACPermissions {
		if _, err := tx.Exec(`INSERT INTO rbac_permissions(key, description) VALUES ($1,$2)
			ON CONFLICT (key) DO UPDATE SET description=EXCLUDED.description`, key, desc); err != nil {
			return err
		}
	}
	rows, err := tx.Query(`SELECT key FROM rbac_permissions`)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		if _, ok := RBACPermissions[k]; !ok {
			stale = append(stale, k)
		}
	}
	rows.Close()
	for _, k := range stale {
		tx.Exec(`DELETE FROM rbac_role_permissions WHERE permission_key=$1`, k) //nolint:errcheck
		tx.Exec(`DELETE FROM rbac_permissions WHERE key=$1`, k)                 //nolint:errcheck
	}

	// System roles
	sysRoles := []RBACRole{
		{ID: RBACRoleAdmin, Name: "Amministratore", Description: "Permessi di amministrazione globale", Scope: RBACScopeAll, IsSystem: true},
		{ID: RBACRoleOperator, Name: "Operatore", Description: "Può eseguire i flussi di lavoro di sicurezza quotidiani, non può gestire account e configurazione principale", Scope: RBACScopeAssigned, IsSystem: true},
		{ID: RBACRoleAuditor, Name: "Revisore", Description: "Visualizzazione in sola lettura di audit, monitoraggio e asset", Scope: RBACScopeAll, IsSystem: true},
		{ID: RBACRoleViewer, Name: "Utente in sola lettura", Description: "Visualizzazione in sola lettura delle risorse autorizzate", Scope: RBACScopeAssigned, IsSystem: true},
	}
	for _, r := range sysRoles {
		if _, err := tx.Exec(`INSERT INTO rbac_roles(id,name,description,scope,is_system,created_at,updated_at)
			VALUES ($1,$2,$3,$4,true,$5,$5)
			ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, scope=EXCLUDED.scope, is_system=true, updated_at=EXCLUDED.updated_at`,
			r.ID, r.Name, r.Description, r.Scope, now); err != nil {
			return err
		}
	}

	// System role grants: deterministic rebuild
	if _, err := tx.Exec(`DELETE FROM rbac_role_permissions WHERE role_id IN ($1,$2,$3,$4)`,
		RBACRoleAdmin, RBACRoleOperator, RBACRoleAuditor, RBACRoleViewer); err != nil {
		return err
	}
	for key := range RBACPermissions {
		// admin: everything
		if _, err := tx.Exec(`INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES ($1,$2) ON CONFLICT DO NOTHING`, RBACRoleAdmin, key); err != nil {
			return err
		}
		isRead := strings.HasSuffix(key, ":read")
		switch {
		case key == "auth:self":
			for _, rid := range []string{RBACRoleOperator, RBACRoleAuditor, RBACRoleViewer} {
				tx.Exec(`INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES ($1,$2) ON CONFLICT DO NOTHING`, rid, key) //nolint:errcheck
			}
		case isRead:
			// All :read go to operator/auditor/viewer: read-only/operator roles can [view] every page
			// (including report management / logs & audit / system config / user management / LLM), they just cannot act on them.
			// (this case comes before rbac/config/llm below, so those modules' read also go through here.)
			for _, rid := range []string{RBACRoleOperator, RBACRoleAuditor, RBACRoleViewer} {
				tx.Exec(`INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES ($1,$2) ON CONFLICT DO NOTHING`, rid, key) //nolint:errcheck
			}
		case strings.HasPrefix(key, "rbac:"), strings.HasPrefix(key, "config:"), strings.HasPrefix(key, "llm:"):
			// Platform-management (rbac/config/llm) write/delete: admin only (granted above); operator also may not
			// manage accounts / core config / LLM. read here was already matched by isRead above, so only write/delete remain -> grant to no non-admin role.
		default:
			// Feature write/delete: grant to operator (+ admin)
			tx.Exec(`INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES ($1,$2) ON CONFLICT DO NOTHING`, RBACRoleOperator, key) //nolint:errcheck
		}
	}

	// First startup: if there are no users, create the built-in admin (migrate the old password)
	var userCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM rbac_users`).Scan(&userCount); err != nil {
		return err
	}
	if userCount == 0 && strings.TrimSpace(adminHash) != "" {
		id := "admin"
		if _, err := tx.Exec(`INSERT INTO rbac_users(id,username,display_name,password_hash,enabled,is_builtin,created_at,updated_at)
			VALUES ($1,'admin','Amministratore',$2,true,true,$3,$3)`, id, adminHash, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO rbac_user_roles(user_id,role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, RBACRoleAdmin); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func scanRBACUser(row interface{ Scan(...any) error }) (*RBACUser, error) {
	var u RBACUser
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Enabled, &u.IsBuiltin, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

const rbacUserCols = `id,username,display_name,password_hash,enabled,is_builtin,token_version,created_at,updated_at`

func (d *DB) GetRBACUserByUsername(username string) (*RBACUser, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" {
		return nil, sql.ErrNoRows
	}
	return scanRBACUser(d.QueryRow(`SELECT `+rbacUserCols+` FROM rbac_users WHERE username=$1`, username))
}

func (d *DB) GetRBACUserByID(id string) (*RBACUser, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, sql.ErrNoRows
	}
	return scanRBACUser(d.QueryRow(`SELECT `+rbacUserCols+` FROM rbac_users WHERE id=$1`, id))
}

// ResolveRBACAccess resolves a user's roles + permissions + combined scope.
func (d *DB) ResolveRBACAccess(userID string) (*RBACAccess, error) {
	u, err := d.GetRBACUserByID(userID)
	if err != nil {
		return nil, err
	}
	acc := &RBACAccess{User: *u, Permissions: map[string]bool{}, Scope: RBACScopeOwn}
	rows, err := d.Query(`SELECT r.id,r.name,r.description,r.scope,r.is_system,r.created_at,r.updated_at
		FROM rbac_roles r JOIN rbac_user_roles ur ON ur.role_id=r.id WHERE ur.user_id=$1 ORDER BY r.is_system DESC, r.name`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r RBACRole
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Scope, &r.IsSystem, &r.CreatedAt, &r.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		acc.Roles = append(acc.Roles, r)
		acc.Scope = mergeScope(acc.Scope, r.Scope)
	}
	rows.Close()
	prows, err := d.Query(`SELECT DISTINCT rp.permission_key FROM rbac_role_permissions rp
		JOIN rbac_user_roles ur ON ur.role_id=rp.role_id WHERE ur.user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer prows.Close()
	for prows.Next() {
		var k string
		if err := prows.Scan(&k); err != nil {
			return nil, err
		}
		acc.Permissions[k] = true
	}
	return acc, prows.Err()
}

func (d *DB) ListRBACUsers() ([]RBACUser, error) {
	rows, err := d.Query(`SELECT ` + rbacUserCols + ` FROM rbac_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RBACUser
	for rows.Next() {
		u, err := scanRBACUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (d *DB) ListRBACUserRoleIDs(userID string) ([]string, error) {
	rows, err := d.Query(`SELECT role_id FROM rbac_user_roles WHERE user_id=$1 ORDER BY role_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (d *DB) CreateRBACUser(username, displayName, passwordHash string, enabled bool, roleIDs []string) (*RBACUser, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" || passwordHash == "" {
		return nil, errors.New("nome utente e password obbligatori")
	}
	id := newRBACID()
	now := time.Now()
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO rbac_users(id,username,display_name,password_hash,enabled,is_builtin,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,false,$6,$6)`, id, username, strings.TrimSpace(displayName), passwordHash, enabled, now); err != nil {
		return nil, err
	}
	for _, rid := range roleIDs {
		if rid = strings.TrimSpace(rid); rid != "" {
			if _, err := tx.Exec(`INSERT INTO rbac_user_roles(user_id,role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, rid); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetRBACUserByID(id)
}

func (d *DB) UpdateRBACUser(userID, displayName string, enabled *bool, roleIDs *[]string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("ID utente mancante")
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if enabled != nil {
		// Bump token_version+1 when deactivating an account to immediately invalidate its issued tokens (without waiting for natural expiry).
		bump := ""
		if !*enabled {
			bump = ",token_version=token_version+1"
		}
		if _, err := tx.Exec(`UPDATE rbac_users SET display_name=$1,enabled=$2`+bump+`,updated_at=now() WHERE id=$3`, strings.TrimSpace(displayName), *enabled, userID); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`UPDATE rbac_users SET display_name=$1,updated_at=now() WHERE id=$2`, strings.TrimSpace(displayName), userID); err != nil {
			return err
		}
	}
	if roleIDs != nil {
		if _, err := tx.Exec(`DELETE FROM rbac_user_roles WHERE user_id=$1`, userID); err != nil {
			return err
		}
		for _, rid := range *roleIDs {
			if rid = strings.TrimSpace(rid); rid != "" {
				if _, err := tx.Exec(`INSERT INTO rbac_user_roles(user_id,role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, userID, rid); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}

func (d *DB) UpdateRBACUserPassword(userID, passwordHash string) error {
	if strings.TrimSpace(userID) == "" || passwordHash == "" {
		return errors.New("parametri mancanti")
	}
	// token_version+1: changing the password invalidates all JWTs previously issued to this user (old tokens are rejected on the next request).
	_, err := d.Exec(`UPDATE rbac_users SET password_hash=$1,token_version=token_version+1,updated_at=now() WHERE id=$2`, passwordHash, userID)
	return err
}

func (d *DB) DeleteRBACUser(userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" || userID == "admin" {
		return errors.New("questo utente non può essere eliminato")
	}
	_, err := d.Exec(`DELETE FROM rbac_users WHERE id=$1 AND is_builtin=false`, userID)
	return err
}

// ----- Roles -----

func (d *DB) ListRBACRoles() ([]RBACRole, error) {
	rows, err := d.Query(`SELECT id,name,description,scope,is_system,created_at,updated_at FROM rbac_roles ORDER BY is_system DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RBACRole
	for rows.Next() {
		var r RBACRole
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Scope, &r.IsSystem, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) GetRBACRoleByID(id string) (*RBACRole, error) {
	var r RBACRole
	err := d.QueryRow(`SELECT id,name,description,scope,is_system,created_at,updated_at FROM rbac_roles WHERE id=$1`, strings.TrimSpace(id)).
		Scan(&r.ID, &r.Name, &r.Description, &r.Scope, &r.IsSystem, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (d *DB) ListRBACRolePermissionKeys(roleID string) ([]string, error) {
	rows, err := d.Query(`SELECT permission_key FROM rbac_role_permissions WHERE role_id=$1 ORDER BY permission_key`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// UpsertRBACRole creates/updates a custom role (system roles cannot be changed).
func (d *DB) UpsertRBACRole(id, name, description, scope string, permKeys []string) (*RBACRole, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("il nome del ruolo non può essere vuoto")
	}
	if scope != RBACScopeAll && scope != RBACScopeAssigned && scope != RBACScopeOwn {
		scope = RBACScopeAssigned
	}
	if id == RBACRoleAdmin || id == RBACRoleOperator || id == RBACRoleAuditor || id == RBACRoleViewer {
		return nil, errors.New("i ruoli di sistema non possono essere modificati")
	}
	if strings.TrimSpace(id) == "" {
		id = newRBACID()
	}
	now := time.Now()
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO rbac_roles(id,name,description,scope,is_system,created_at,updated_at)
		VALUES ($1,$2,$3,$4,false,$5,$5)
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, scope=EXCLUDED.scope, updated_at=EXCLUDED.updated_at`,
		id, name, strings.TrimSpace(description), scope, now); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM rbac_role_permissions WHERE role_id=$1`, id); err != nil {
		return nil, err
	}
	for _, k := range permKeys {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		if _, ok := RBACPermissions[k]; !ok {
			return nil, errors.New("permesso sconosciuto: " + k)
		}
		if _, err := tx.Exec(`INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, k); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetRBACRoleByID(id)
}

func (d *DB) DeleteRBACRole(id string) error {
	id = strings.TrimSpace(id)
	if id == RBACRoleAdmin || id == RBACRoleOperator || id == RBACRoleAuditor || id == RBACRoleViewer {
		return errors.New("i ruoli di sistema non possono essere eliminati")
	}
	_, err := d.Exec(`DELETE FROM rbac_roles WHERE id=$1 AND is_system=false`, id)
	return err
}
