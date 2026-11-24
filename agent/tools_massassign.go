package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	actool "artemis/engine/tool"
)

// Deterministic verifier for mass assignment of a privileged field (Juice Shop V05,
// OWASP A08/A01). The invariant: a registration/update endpoint must bind only the
// fields it intends; a client must not be able to set a privileged attribute (role,
// admin flag) by adding it to the request body. A weak model guesses from a 200;
// this oracle proves it with a differential:
//
//   - register a BASELINE account with no privileged field, read the default value
//     the server assigns to a privileged attribute (e.g. role=customer).
//   - register an ATTACK account that ALSO sends a privileged value for that
//     attribute. If the created object comes back carrying the privileged value we
//     sent (and the baseline did not), the server mass-assigned it: confirmed.
//
// Generic technique (field-name wordlist + canonical privileged values), never a
// target fact. Honest limit: relies on the created object echoing the attribute; if
// the endpoint hides it, this false-negatives (never false-positives, since a
// confirm requires the privileged value we sent to come back).

// privFields maps a privileged attribute name to the canonical elevated value to try
// and a matcher for "is this response value actually privileged".
var privStringFields = []struct {
	field, attack string
	privValues    []string
}{
	{"role", "admin", []string{"admin", "administrator", "superadmin", "root"}},
}

var privBoolFields = []string{"isAdmin", "admin", "isDeluxe", "deluxe"}

// jsonStrField / jsonBoolField read a top-level-ish field value out of a JSON body
// by key (tolerant of nesting via a simple regex, enough for a verdict).
func jsonStrField(body, key string) (string, bool) {
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `"\s*:\s*"([^"]*)"`)
	if m := re.FindStringSubmatch(body); m != nil {
		return m[1], true
	}
	return "", false
}

func jsonBoolTrue(body, key string) bool {
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `"\s*:\s*true\b`)
	return re.MatchString(body)
}

// registerWith posts a registration with the given extra fields merged into the
// standard body, sweeping the register wordlist until one accepts (2xx). Returns the
// response body of the accepted registration, or ok=false.
func registerWith(ctx context.Context, client *http.Client, root, email, pass string, extra map[string]any, budget *int) (string, bool) {
	for _, rp := range registerPaths {
		if ctx.Err() != nil || *budget <= 0 {
			break
		}
		body := map[string]any{"email": email, "password": pass, "passwordRepeat": pass, "username": email}
		for k, v := range extra {
			body[k] = v
		}
		*budget--
		st, b, ok := postJSON(ctx, client, root+rp, body)
		if ok && st >= 200 && st < 300 {
			return b, true
		}
	}
	return "", false
}

const massassignMaxRequests = 60

func (t *ToolSet) massassignVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Base URL of the target, e.g. http://host:3000. The verifier self-registers accounts and checks whether a privileged field (role/admin) can be set via the registration body; no path or credentials needed.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE mass assignment of a privileged field. It registers a baseline account to learn the default value of a privileged attribute (e.g. role), then registers another account that also sends a privileged value for it; if the created object comes back carrying the value the client sent (and the baseline did not), the endpoint mass-assigned a field it should not. Use this instead of guessing from a 200. Pass the base URL."
	return readTool("massassign_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
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
			return actool.Errorf("massassign_verify needs an absolute URL (scheme://host[:port]), got: " + clipXSS(raw, 120)), nil
		}
		root := base.Scheme + "://" + base.Host
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		runCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		budget := massassignMaxRequests
		nonce := fmt.Sprint(time.Now().UnixNano())
		pass := "Artemis!" + nonce

		// Baseline registration (no privileged fields).
		baseBody, ok := registerWith(runCtx, client, root, "artemis_mabase_"+nonce+"@artemis.invalid", pass, nil, &budget)
		if !ok {
			return actool.Text(
				"No mass assignment confirmed: could not self-register a baseline account (register sweep did not accept), " +
					"so the oracle could not run. record_fact the negative (inferred); do NOT report_finding."), nil
		}

		// String privileged fields (e.g. role): compare baseline default vs attack echo.
		for _, pf := range privStringFields {
			if runCtx.Err() != nil || budget <= 0 {
				break
			}
			baseVal, _ := jsonStrField(baseBody, pf.field)
			attackBody, aok := registerWith(runCtx, client, root, "artemis_ma_"+pf.field+"_"+nonce+"@artemis.invalid", pass, map[string]any{pf.field: pf.attack}, &budget)
			if !aok {
				continue
			}
			got, present := jsonStrField(attackBody, pf.field)
			if !present {
				continue
			}
			isPriv := false
			for _, pv := range pf.privValues {
				if strings.EqualFold(got, pv) {
					isPriv = true
					break
				}
			}
			if isPriv && !strings.EqualFold(got, baseVal) {
				return actool.Text(fmt.Sprintf(
					"CONFIRMED mass assignment: registering with %q=%q returned a created account whose %q is %q, while a "+
						"baseline registration defaulted it to %q. The endpoint bound a privileged field from the request body. "+
						"report_finding (mass assignment / broken access control, high) with both registration requests and the "+
						"responses as reproduction. Do NOT record it as a negative.",
					pf.field, pf.attack, pf.field, got, baseVal)), nil
			}
		}

		// Boolean privileged flags (e.g. isAdmin:true): confirmed if the echo carries
		// the flag true where the baseline did not.
		for _, bf := range privBoolFields {
			if runCtx.Err() != nil || budget <= 0 {
				break
			}
			if jsonBoolTrue(baseBody, bf) {
				continue // baseline already true: not a usable signal
			}
			attackBody, aok := registerWith(runCtx, client, root, "artemis_mb_"+bf+"_"+nonce+"@artemis.invalid", pass, map[string]any{bf: true}, &budget)
			if !aok {
				continue
			}
			if jsonBoolTrue(attackBody, bf) {
				return actool.Text(fmt.Sprintf(
					"CONFIRMED mass assignment: registering with %q=true returned a created account carrying %q=true, while a "+
						"baseline registration did not. The endpoint bound a privileged flag from the request body. report_finding "+
						"(mass assignment / privilege escalation, high) with both registration requests and responses as "+
						"reproduction. Do NOT record it as a negative.", bf, bf)), nil
			}
		}

		return actool.Text(
			"No mass assignment confirmed: a privileged value sent in the registration body (role/admin flags) was not " +
				"reflected in the created account, or the account did not echo the attribute. Note this relies on the created " +
				"object echoing the field. record_fact the negative (inferred); do NOT report_finding."), nil
	})
}

// massassignSummaries / intent: fire on the base URL. Text contains "mass assignment"
// so intentClass canonicalizes to "massassign".
func massassignSummaries(s Surface, _ int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	return []string{massassignIntentSummary(s.Base)}
}

func massassignIntentSummary(base string) string {
	return fmt.Sprintf(
		"Mass assignment check: call massassign_verify with the base URL %s. It self-registers a baseline account then one "+
			"that also sends a privileged field (role=admin / isAdmin=true), and confirms if the created account carries the "+
			"privileged value. If CONFIRMED, report_finding (mass assignment). If not, record_fact the negative (inferred) and "+
			"do NOT report_finding.",
		base)
}
