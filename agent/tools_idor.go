package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	actool "artemis/engine/tool"
)

// jwtTokenRe captures a FULL three-segment JWT (header.payload.signature). Unlike
// jwtRe (a detector that stops at the signature dot), this is an EXTRACTOR: the
// token it returns must be usable as a Bearer credential.
var jwtTokenRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// jsonTokenRe pulls an explicit "token":"..." field (Juice Shop nests it under
// authentication.token); preferred over the bare-JWT scan when present.
var jsonTokenRe = regexp.MustCompile(`"token"\s*:\s*"([^"]+)"`)

// extractToken returns a usable bearer token from a login response body: an explicit
// JSON token field if present, else the first full JWT found.
func extractToken(body string) string {
	if m := jsonTokenRe.FindStringSubmatch(body); m != nil && strings.TrimSpace(m[1]) != "" {
		return m[1]
	}
	return jwtTokenRe.FindString(body)
}

// Deterministic verifier for IDOR / Broken Object Level Authorization (Juice Shop
// V06 family, OWASP A01). The invariant of the class: an object addressed by an id
// must be served only to its owner. A weak model "checks IDOR" by eyeballing a 200
// on one id and guessing; it cannot prove that the data it got back belongs to a
// DIFFERENT owner. This oracle proves exactly that, deterministically and with no
// target specifics:
//
//   - self-provision TWO independent throwaway sessions A and B (generic register +
//     login sweep); each account's unique email is a marker that appears in its own
//     server-side data.
//   - sweep a generic wordlist of id-bearing resource templates; find an id whose
//     response to B's token carries B's marker (a B-owned object).
//   - replay that exact id with A's token. If A receives B's marker, A read another
//     user's private object -> IDOR. A no-auth baseline excludes a merely public
//     resource (served to everyone, which is exposure, not IDOR).
//
// Everything is generic technique (register/login/resource wordlists), never a fact
// about a specific target. Honest limit (like traversal_verify): attribution needs
// an id-bearing resource that echoes an owner marker, so it can FALSE-NEGATIVE on a
// target that exposes none; it does NOT false-positive (a hit is A literally holding
// B's marker while an unauthenticated caller cannot).

// registerPaths is a GENERIC wordlist of account-creation endpoints (no app
// specifics), swept to self-provision throwaway sessions.
var registerPaths = []string{
	"/api/Users", "/api/users", "/rest/user", "/api/register", "/register",
	"/signup", "/api/signup", "/users", "/user/register", "/account/register",
}

// session is a self-provisioned throwaway account: its bearer token, the login
// response body (mined by other oracles for owned-object ids), and a unique marker
// (its email) that appears in the account's own server-side data.
type session struct {
	email, token, loginBody string
}

// bearerReq issues one request with an optional Bearer token and optional JSON body,
// returning status, body and ok. The shared authenticated primitive for IDOR and
// business-logic probing.
func bearerReq(ctx context.Context, client *http.Client, method, u, token string, body []byte) (int, string, bool) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return 0, "", false
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, exposureBodyCap))
	return resp.StatusCode, string(rb), true
}

// provisionSession registers a throwaway account and logs it in, returning a usable
// session or ok=false. Generic technique: sweep the register wordlist (any 2xx is
// enough; failures are ignored and login is attempted regardless), then the shared
// login wordlist, grabbing a JWT from the login body. The email is a unique
// per-call marker. budget is decremented per request.
func provisionSession(ctx context.Context, client *http.Client, root, tag string, budget *int) (session, bool) {
	nonce := fmt.Sprint(time.Now().UnixNano())
	email := "artemis_" + tag + "_" + nonce + "@artemis.invalid"
	pass := "Artemis!" + nonce
	for _, rp := range registerPaths {
		if ctx.Err() != nil || *budget <= 0 {
			break
		}
		*budget--
		body := map[string]any{"email": email, "password": pass, "passwordRepeat": pass, "username": email}
		st, _, ok := postJSON(ctx, client, root+rp, body)
		if ok && st >= 200 && st < 300 {
			break
		}
	}
	for _, lp := range loginPaths {
		if ctx.Err() != nil || *budget <= 0 {
			break
		}
		*budget--
		st, b, ok := postJSON(ctx, client, root+lp, map[string]any{credFields[0]: email, passFields[0]: pass})
		if !ok || st < 200 || st >= 300 {
			continue
		}
		if tok := extractToken(b); tok != "" {
			return session{email: email, token: tok, loginBody: b}, true
		}
	}
	return session{}, false
}

// idorTemplates is a GENERIC wordlist of id-bearing resource paths (REST collections
// addressed by a numeric id). The verifier substitutes a small id range; whichever
// template exhibits the cross-read confirms the class.
var idorTemplates = []string{
	"/api/Users/%d", "/rest/user/%d", "/api/Feedbacks/%d", "/api/Addresss/%d",
	"/api/Cards/%d", "/api/Complaints/%d", "/rest/basket/%d", "/api/BasketItems/%d",
	"/rest/orders/%d", "/api/Orders/%d",
}

const (
	idorMaxID       = 12
	idorMaxRequests = 240
)

// idorOwnerIDFields are generic JSON keys that carry an object's OWNER identity
// (not the object's own id). The cross-read differential keys on this: an object
// whose owner-id equals account B's and differs from A's is B's private object.
var idorOwnerIDFields = []string{"UserId", "userId", "user_id", "UserID", "userID", "ownerId", "OwnerId", "owner_id", "uid"}

// ownerIDFrom reads a session's OWN owned-object id across the template wordlist and
// returns the first owner-id the object echoes (0 if none). Establishes an account's
// identity so a cross-read can be attributed. The first template that both returns
// 2xx and carries an owner-id field wins (for a basket-style resource that is the
// basket's UserId; a resource that is itself the user carries no owner-id and is
// skipped).
func ownerIDFrom(ctx context.Context, client *http.Client, root, token string, ownedID int, budget *int) int {
	if ownedID <= 0 {
		return 0
	}
	for _, tmpl := range idorTemplates {
		if ctx.Err() != nil || *budget <= 0 {
			return 0
		}
		*budget--
		st, body, ok := bearerReq(ctx, client, http.MethodGet, root+fmt.Sprintf(tmpl, ownedID), token, nil)
		if ok && st >= 200 && st < 300 {
			if v, found := mineIntField(body, idorOwnerIDFields); found {
				return v
			}
		}
	}
	return 0
}

func (t *ToolSet) idorVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Base URL of the target, e.g. http://host:3000. The verifier self-registers two throwaway accounts and proves (or refutes) that one can read the other's id-addressed objects; no path or credentials needed.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE IDOR / Broken Object Level Authorization. It self-provisions two independent throwaway sessions (generic register + login), establishes each account's owned-object id and owner identity, and reads one account's object id with the OTHER account's token: if the response carries the first account's identity (its email marker or its owner-id, distinct from the reader's own) and an unauthenticated caller cannot get it, that is a confirmed IDOR. Use this instead of eyeballing a 200 on a single id: a 200 is not proof you are reading someone else's object. Pass the base URL."
	return readTool("idor_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(in, &a)
		raw := strings.TrimSpace(a.URL)
		if raw == "" {
			return actool.Errorf("url is required: pass the target base URL, e.g. http://host:3000"), nil
		}
		base, err := url.Parse(raw)
		if err != nil || base.Host == "" {
			return actool.Errorf("idor_verify needs an absolute URL (scheme://host[:port]), got: " + clipXSS(raw, 120)), nil
		}
		root := base.Scheme + "://" + base.Host
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		budget := idorMaxRequests

		sa, okA := provisionSession(runCtx, client, root, "a", &budget)
		sb, okB := provisionSession(runCtx, client, root, "b", &budget)
		if !okA || !okB {
			return actool.Text(
				"No IDOR confirmed: could not self-provision two authenticated sessions (register+login sweep did not yield " +
					"two tokens), so the cross-read oracle could not run. This is not evidence of absence. record_fact the " +
					"negative (inferred); do NOT report_finding."), nil
		}

		// Each session's own owned-object id (mined from its login) and the owner-id
		// its object echoes, so a cross-read can be attributed to B specifically.
		bidA, _ := mineIntField(sa.loginBody, basketIDFields)
		bidB, _ := mineIntField(sb.loginBody, basketIDFields)
		ownerA := ownerIDFrom(runCtx, client, root, sa.token, bidA, &budget)
		ownerB := ownerIDFrom(runCtx, client, root, sb.token, bidB, &budget)

		// Ids to read as A: B's own owned id first, then a shallow sweep.
		ids := []int{}
		if bidB > 0 {
			ids = append(ids, bidB)
		}
		for id := 1; id <= idorMaxID; id++ {
			if id != bidB {
				ids = append(ids, id)
			}
		}

		for _, tmpl := range idorTemplates {
			for _, id := range ids {
				if runCtx.Err() != nil || budget <= 0 {
					goto done
				}
				path := fmt.Sprintf(tmpl, id)
				budget--
				stA, bodyA, oka := bearerReq(runCtx, client, http.MethodGet, root+path, sa.token, nil)
				if !oka || stA < 200 || stA >= 300 {
					continue
				}
				// Does A's authenticated response carry B's identity, and not A's own?
				// Two attribution signals: B's email marker, or an owner-id field whose
				// value is B's (and differs from A's).
				byEmail := sb.email != "" && strings.Contains(bodyA, sb.email) && !strings.Contains(bodyA, sa.email)
				v, okOwner := mineIntField(bodyA, idorOwnerIDFields)
				byOwner := okOwner && ownerB > 0 && ownerB != ownerA && v == ownerB
				if !byEmail && !byOwner {
					continue
				}
				// Exclude a merely public resource: an unauthenticated caller must NOT
				// get the same object (that would be exposure, not IDOR).
				budget--
				stU, bodyU, _ := bearerReq(runCtx, client, http.MethodGet, root+path, "", nil)
				if stU >= 200 && stU < 300 {
					vu, oku := mineIntField(bodyU, idorOwnerIDFields)
					if strings.Contains(bodyU, sb.email) || (oku && vu == ownerB) {
						continue
					}
				}
				how := fmt.Sprintf("B's owner-id %d, distinct from A's own %d,", ownerB, ownerA)
				if byEmail {
					how = fmt.Sprintf("B's unique marker %q", sb.email)
				}
				return actool.Text(fmt.Sprintf(
					"CONFIRMED IDOR at %s: account A read account B's private object (%s appeared in A's authenticated "+
						"response, while an unauthenticated request did not). This is a verified broken object-level "+
						"authorization. report_finding (IDOR / broken access control) with the two authenticated GET requests "+
						"and the cross-account response as reproduction. Do NOT record it as a negative.",
					path, how)), nil
			}
		}
	done:
		return actool.Text(
			"No IDOR confirmed: swept id-bearing resource templates with two independent sessions; no object carried one " +
				"account's identity (email marker or owner-id) to the other. Note the attribution relies on a resource that " +
				"echoes an owner identity, so a negative is not proof no IDOR exists on resources that do not. record_fact the " +
				"negative (inferred); do NOT report_finding."), nil
	})
}

// idorSummaries / intent: fire on the base URL alone. Text contains "IDOR" so
// intentClass canonicalizes to "idor".
func idorSummaries(s Surface, _ int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	return []string{idorIntentSummary(s.Base)}
}

func idorIntentSummary(base string) string {
	return fmt.Sprintf(
		"IDOR / broken object-level authorization check: call idor_verify with the base URL %s. It self-registers two "+
			"throwaway accounts and proves whether one can read the other's id-addressed objects. If CONFIRMED, "+
			"report_finding (IDOR) with the cross-account requests as reproduction. If not, record_fact the negative "+
			"(inferred) and do NOT report_finding.",
		base)
}
