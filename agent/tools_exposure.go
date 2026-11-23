package agent

import (
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

// Deterministic verifiers for the "reachable-without-auth" breadth classes: a
// sensitive-path exposure sweep (covers Juice Shop V10 /ftp, V11 /encryptionkeys,
// V15 /metrics, and generalizes to /.git, /.env, /actuator, ... on any target) and
// a missing-Content-Security-Policy check (V17). Same rationale as xss_verify /
// redirect_verify: a weak model marks a 200 "confirmed" without noticing the body
// is the SPA shell, or calls a missing header a finding from a hunch. These tools
// remove the judgment with a deterministic signal.
//
// Nothing here is target specific: the path list is a generic wordlist of
// well-known sensitive endpoints, and the SPA-fallback baseline below is what makes
// it safe on a single-page app that answers 200+index.html to every unknown path.

// sensitiveProbes is the generic wordlist of well-known sensitive paths worth a
// GET. kind drives the confirmation marker; marker (when set) is a substring the
// real response must contain. Keep this generic (no per-app paths).
var sensitiveProbes = []struct{ path, kind, marker string }{
	{"/metrics", "metrics", ""},            // Prometheus text exposition (V15)
	{"/encryptionkeys/", "listing", ""},    // exposed key directory (V11)
	{"/encryptionkeys", "listing", ""},     //
	{"/ftp/", "listing", ""},               // exposed file directory (V10)
	{"/ftp", "listing", ""},                //
	{"/.git/HEAD", "git", "ref:"},          // leaked git repo
	{"/.git/config", "git", "[core]"},      //
	{"/.env", "env", "="},                  // leaked environment file
	{"/server-status", "html", "Server"},   // Apache status page
	{"/actuator/health", "json", "status"}, // Spring actuator
	{"/api-docs", "json", ""},              // exposed OpenAPI spec
	{"/swagger.json", "json", ""},          //
}

// promLineRe recognizes a Prometheus exposition line (metric{labels} value) so the
// /metrics check does not rely on comments alone.
var promLineRe = regexp.MustCompile(`(?m)^[a-zA-Z_][a-zA-Z0-9_]*(\{[^}]*\})?\s+[0-9eE.+-]+\s*$`)

// hrefRe counts anchor hrefs, the signal of a directory-listing page.
var hrefRe = regexp.MustCompile(`(?i)href\s*=`)

const exposureBodyCap = 64 * 1024 // read at most this much of each probe body

func fetchBody(ctx context.Context, client *http.Client, u string) (status int, ctype, body string, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, exposureBodyCap))
	return resp.StatusCode, strings.ToLower(resp.Header.Get("Content-Type")), string(b), true
}

// looksExposed decides whether a probe response is a real sensitive resource (not
// the SPA fallback and not a custom 404). fallback is the body a known-nonexistent
// path returns, so an identical body means "SPA shell, not real".
func looksExposed(kind, marker, ctype, body, fallback string) bool {
	if strings.TrimSpace(body) == "" {
		return false
	}
	// Identical to the known-nonexistent baseline => SPA/catch-all shell, not a hit.
	if body == fallback {
		return false
	}
	if marker != "" && !strings.Contains(body, marker) {
		return false
	}
	switch kind {
	case "metrics":
		return strings.Contains(body, "# HELP ") || strings.Contains(body, "# TYPE ") || promLineRe.MatchString(body)
	case "listing":
		// A directory listing: either the classic "Index of", or several hrefs in a
		// page that is NOT the SPA shell (already excluded by the fallback compare).
		return strings.Contains(body, "Index of") ||
			strings.Contains(strings.ToLower(body), "parent directory") ||
			len(hrefRe.FindAllString(body, -1)) >= 2
	case "json":
		return strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "[") || strings.Contains(ctype, "json")
	case "git", "env", "html":
		// marker already matched (or none required) and the body differs from the
		// SPA fallback: a served file, not the app shell.
		return !strings.Contains(ctype, "text/html") || marker != ""
	}
	return false
}

func (t *ToolSet) exposureVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Base URL of the target, e.g. http://host:3000. The verifier sweeps a generic wordlist of well-known sensitive paths (/metrics, /encryptionkeys, /ftp, /.git, /.env, ...); no path or payload needed.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE unauthenticated exposure of well-known sensitive endpoints (monitoring/metrics, key and file directories, leaked .git/.env, actuator, OpenAPI). It GETs a generic path wordlist and, crucially, first baselines the response a nonexistent path returns, so a single-page app that answers 200+index.html to everything does NOT read as a hit: only bodies that differ from that shell AND match a sensitive marker are reported. Use this instead of eyeballing a 200: on an SPA a 200 usually means the catch-all shell, not a real file. Pass the base URL."
	return readTool("exposure_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
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
			return actool.Errorf("exposure_verify needs an absolute URL (scheme://host[:port]), got: " + clipXSS(raw, 120)), nil
		}
		root := base.Scheme + "://" + base.Host

		client := &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		runCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()

		// Baseline: what does a known-nonexistent path return? On an SPA this is the
		// index shell served for every unknown route; we use it to reject false hits.
		_, _, fallback, _ := fetchBody(runCtx, client, root+"/__artemis_nonexistent_"+fmt.Sprint(time.Now().UnixNano()))

		type hit struct{ path, kind string }
		var hits []hit
		for _, p := range sensitiveProbes {
			if runCtx.Err() != nil {
				break
			}
			status, ctype, body, ok := fetchBody(runCtx, client, root+p.path)
			if !ok || status < 200 || status >= 300 {
				continue
			}
			if looksExposed(p.kind, p.marker, ctype, body, fallback) {
				hits = append(hits, hit{path: p.path, kind: p.kind})
			}
		}
		if len(hits) == 0 {
			return actool.Text(fmt.Sprintf(
				"No sensitive-path exposure: swept %d well-known paths on %s; none returned a real sensitive resource "+
					"(every 2xx either matched the SPA/catch-all shell baseline or lacked the expected marker). "+
					"record_fact the negative; do NOT report_finding.",
				len(sensitiveProbes), root)), nil
		}
		var parts []string
		for _, h := range hits {
			parts = append(parts, fmt.Sprintf("%s (%s)", h.path, h.kind))
		}
		return actool.Text(fmt.Sprintf(
			"CONFIRMED sensitive path exposure on %s: %s reachable WITHOUT authentication and serving real content "+
				"(not the app shell). This is a Security Misconfiguration / Information Disclosure: report_finding for EACH "+
				"exposed path with the GET request and response as reproduction. Do NOT record these as negatives.",
			root, strings.Join(parts, ", "))), nil
	})
}

func (t *ToolSet) cspVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "URL of a page to check, e.g. http://host:3000/. The verifier inspects the response for a Content-Security-Policy (header or meta).",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE a missing Content-Security-Policy on a page. GETs the URL and checks both the CSP response header and a <meta http-equiv=\"Content-Security-Policy\"> in the HTML: if neither is present on a served HTML page, the page has no CSP (a Security Misconfiguration that worsens XSS impact). Use this instead of guessing from the body. Pass a page URL (default the site root)."
	return readTool("csp_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(in, &a)
		raw := strings.TrimSpace(a.URL)
		if raw == "" {
			return actool.Errorf("url is required: pass a page URL, e.g. http://host:3000/"), nil
		}
		base, err := url.Parse(raw)
		if err != nil || base.Host == "" {
			return actool.Errorf("csp_verify needs an absolute URL (scheme://host[:port]/path), got: " + clipXSS(raw, 120)), nil
		}
		client := &http.Client{Timeout: 8 * time.Second}
		runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(runCtx, http.MethodGet, base.String(), nil)
		resp, err := client.Do(req)
		if err != nil {
			return actool.Errorf("csp_verify could not reach " + clipXSS(base.String(), 120) + ": " + err.Error()), nil
		}
		hdr := strings.TrimSpace(resp.Header.Get("Content-Security-Policy"))
		b, _ := io.ReadAll(io.LimitReader(resp.Body, exposureBodyCap))
		resp.Body.Close()
		body := strings.ToLower(string(b))
		metaCSP := strings.Contains(body, `http-equiv="content-security-policy"`) ||
			strings.Contains(body, `http-equiv='content-security-policy'`)
		if hdr != "" || metaCSP {
			where := "header"
			if hdr == "" {
				where = "meta tag"
			}
			return actool.Text(fmt.Sprintf(
				"Content-Security-Policy IS present on %s (via %s). No CSP-absent finding here: record_fact the negative, "+
					"do NOT report_finding.", base.Path, where)), nil
		}
		return actool.Text(fmt.Sprintf(
			"CONFIRMED missing Content-Security-Policy on %s: the response carries no CSP header and the HTML has no "+
				"CSP meta tag, so the browser applies no script-source restriction (a Security Misconfiguration that removes "+
				"defense-in-depth against XSS). report_finding (missing CSP) with the response headers as reproduction.",
			base.Path)), nil
	})
}

// --- recognizers (Surface -> intent texts) -----------------------------------

// Exposure and CSP fire on the base URL alone (no route/param mining needed): the
// path wordlist and the page check are self-contained in the verifier, so the
// expander emits ONE intent per class as soon as the base is known. maxN is
// irrelevant here (a single sweep intent) and kept only for signature uniformity.

func exposureSummaries(s Surface, _ int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	return []string{exposureIntentSummary(s.Base)}
}

// exposureIntentSummary: the endpoint path must be the FIRST slash-word (dedup key
// is class + first /path), and the text must contain "sensitive path exposure" so
// intentClass canonicalizes it to "exposure". Prose before the path stays slash-free.
func exposureIntentSummary(base string) string {
	return fmt.Sprintf(
		"Sensitive path exposure check: call exposure_verify with the base URL %s to confirm or refute "+
			"unauthenticated exposure of well-known sensitive endpoints such as /metrics, /encryptionkeys, /ftp, "+
			".git and .env. The verifier sweeps a generic wordlist and baselines the SPA catch-all so a 200+index "+
			"shell is not mistaken for a hit. If it returns CONFIRMED, report_finding (Security Misconfiguration / "+
			"Information Disclosure) for each exposed path with the GET request and response. If it reports none "+
			"exposed, record_fact the negative and do NOT report_finding. Do NOT conclude exposure from a bare 200.",
		base)
}

func cspSummaries(s Surface, _ int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	return []string{cspIntentSummary(s.Base)}
}

// cspIntentSummary: contains "Content-Security-Policy" so intentClass canonicalizes
// to "csp". The page path (root) is the first slash-word for the dedup key.
func cspIntentSummary(base string) string {
	return fmt.Sprintf(
		"Content-Security-Policy check on the page / : call csp_verify with the URL %s/ to confirm or refute a "+
			"missing CSP. The verifier inspects both the response header and a CSP meta tag. If it returns CONFIRMED "+
			"missing, report_finding (Security Misconfiguration, missing Content-Security-Policy) with the response "+
			"headers as reproduction. If a CSP is present, record_fact the negative and do NOT report_finding.",
		base)
}
