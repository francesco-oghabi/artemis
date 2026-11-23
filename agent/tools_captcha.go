package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	actool "artemis/engine/tool"
)

// Deterministic verifier for the "CAPTCHA answer returned to the client" class
// (Juice Shop V18, OWASP A04 Insecure Design): a CAPTCHA endpoint that ships the
// expected answer in its own response is trivially bypassable. The weak model
// eyeballs a JSON blob and may miss that one field IS the solution. This tool
// removes the judgment: GET the common CAPTCHA endpoints and confirm only when the
// response is JSON carrying BOTH a challenge and an answer/solution field.
//
// Generic: the path list is a wordlist of conventional CAPTCHA endpoints and the
// signal is structural (an answer-like key in the JSON), never a target fact.

var captchaPaths = []string{
	"/rest/captcha", "/rest/captcha/", "/api/captcha", "/api/Captcha", "/captcha", "/captcha/",
}

// captchaAnswerKeys are JSON field names that would carry the solution. Presence of
// one (with a non-empty scalar value) alongside a challenge is the leak.
var captchaAnswerKeys = []string{"answer", "solution", "result", "expected", "captchaAnswer"}
var captchaChallengeKeys = []string{"captcha", "question", "challenge", "image", "captchaId"}

func anyKeyPresent(m map[string]any, keys []string) (string, bool) {
	for _, k := range keys {
		for mk, mv := range m {
			if strings.EqualFold(mk, k) {
				if s := fmt.Sprintf("%v", mv); strings.TrimSpace(s) != "" && s != "<nil>" {
					return mk, true
				}
			}
		}
	}
	return "", false
}

func (t *ToolSet) captchaVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Base URL of the target, e.g. http://host:3000. The verifier sweeps common CAPTCHA endpoints and checks whether the response leaks the answer.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE a CAPTCHA whose answer is returned to the client. GETs common CAPTCHA endpoints and confirms only when the JSON response carries BOTH a challenge and an answer/solution field (so the client can read the expected answer and bypass the CAPTCHA). Use this instead of guessing from a JSON blob. Pass the base URL."
	return readTool("captcha_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
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
			return actool.Errorf("captcha_verify needs an absolute URL (scheme://host[:port]), got: " + clipXSS(raw, 120)), nil
		}
		root := base.Scheme + "://" + base.Host
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		for _, p := range captchaPaths {
			if runCtx.Err() != nil {
				break
			}
			status, _, body, ok := fetchBody(runCtx, client, root+p)
			if !ok || status < 200 || status >= 300 {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(body)), &m) != nil || len(m) == 0 {
				continue // not JSON (e.g. the SPA shell): not a captcha API response
			}
			ansKey, hasAns := anyKeyPresent(m, captchaAnswerKeys)
			_, hasChal := anyKeyPresent(m, captchaChallengeKeys)
			if hasAns && hasChal {
				return actool.Text(fmt.Sprintf(
					"CONFIRMED CAPTCHA answer disclosure at %s: the response is JSON that includes the challenge AND the "+
						"answer field %q, so a client can read the expected answer and bypass the CAPTCHA (Insecure Design). "+
						"report_finding (CAPTCHA answer returned to client) with the GET request and response as reproduction. "+
						"Do NOT record this as a negative.", p, ansKey)), nil
			}
		}
		return actool.Text(fmt.Sprintf(
			"No CAPTCHA answer disclosure: swept %d common CAPTCHA endpoints on %s; none returned a JSON response that "+
				"carries the answer alongside the challenge. record_fact the negative; do NOT report_finding.",
			len(captchaPaths), root)), nil
	})
}

// captchaSummaries / captchaIntentSummary: fire on the base URL alone (the path
// list is self-contained). The text contains "CAPTCHA" so intentClass canonicalizes
// to "captcha".
func captchaSummaries(s Surface, _ int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	return []string{captchaIntentSummary(s.Base)}
}

func captchaIntentSummary(base string) string {
	return fmt.Sprintf(
		"CAPTCHA answer-disclosure check: call captcha_verify with the base URL %s to confirm or refute a CAPTCHA whose "+
			"answer is returned to the client. The verifier sweeps common CAPTCHA endpoints and confirms only on a JSON "+
			"response that carries both the challenge and the answer. If CONFIRMED, report_finding (CAPTCHA answer returned "+
			"to client, Insecure Design). If not, record_fact the negative and do NOT report_finding.",
		base)
}
