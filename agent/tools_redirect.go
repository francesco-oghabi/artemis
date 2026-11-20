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

// Open-redirect verifier: a deterministic judge for open redirects, the companion
// of the XSS rendering oracle for the intent expander's second class. The weak
// model eyeballs a 200/302 body and cannot tell a safe redirect from an
// attacker-controlled one. This tool removes that judgment: it drives the target
// endpoint with a battery of redirect payloads, FOLLOWS NO REDIRECT, and reports
// whether the Location header points at an attacker-controlled host. No browser,
// just HTTP, so it is cheap enough to sweep a wordlist of candidate parameters.

// redirectSentinel is the attacker-controlled host the payloads try to send the
// user to. .example is a reserved TLD that never resolves, which is fine: the
// verifier never follows the redirect, it only inspects the Location header, so a
// Location pointing here is proof the endpoint would send a real victim off-site.
const redirectSentinel = "attacker.example"

// redirectBypassPayloads returns the battery for one parameter. The generic
// payloads catch an unprotected or loosely validated redirect (plain off-site and
// a handful of parser-quirk encodings). The decoy payloads defeat the common
// "the target must CONTAIN an allowlisted URL" filter: each sends the victim to
// the attacker sentinel while carrying an allowlisted URL as a query token, so the
// contains-check passes yet the browser still lands off-site. The decoys are mined
// from the target's OWN response bodies (traffic.DiscoverExternalURLs), so the
// bypass is derived from what the target advertises, never hardcoded per app.
//
// There is deliberately NO probe/skip: a parameter that returns a non-3xx to the
// plain off-site payload is NOT proof it is not a redirect parameter (a
// contains-whitelist answers 406 to the plain payload and only 3xx to a decoy
// one), so every payload is always tried. The task-55 field run proved the old
// probe-skip false-negatived on exactly this filter shape.
func redirectBypassPayloads(decoys []string) []string {
	s := redirectSentinel
	out := []string{
		"https://" + s + "/", // plain off-site (unprotected redirect)
		"//" + s + "/",        // scheme-relative
		"https:/" + s + "/",   // missing-slash parser quirk
		"/\\" + s + "/",       // backslash confusion
	}
	for _, d := range decoys {
		// attacker URL carrying an allowlisted token: Location still resolves to the
		// sentinel, but the "contains an allowlisted URL" check passes. Kept raw;
		// the single url.Values.Encode on the request escapes it exactly once.
		out = append(out, "https://"+s+"/?x="+d)
	}
	return out
}

// isURLish reports whether a string looks like an absolute or scheme-relative URL
// worth using as an allowlist decoy token (has a scheme-ish prefix and a dot host).
func isURLish(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if !strings.Contains(v, "://") && !strings.HasPrefix(v, "//") {
		return false
	}
	return strings.Contains(v, ".")
}

// locationHitsSentinel reports whether a Location header value resolves to a host
// under the attacker-controlled sentinel.
func locationHitsSentinel(loc string) bool {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return false
	}
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == redirectSentinel || strings.HasSuffix(h, "."+redirectSentinel)
}

func (t *ToolSet) redirectVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "URL of the endpoint to test, e.g. http://host:3000/redirect. If it already carries a URL-valued query parameter (to/redirect/url/next/...), that parameter is tested; otherwise the verifier sweeps a wordlist of common redirect parameters. No payload needed: the verifier supplies the bypass payloads itself.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE an open redirect on an endpoint. Sends a battery of off-site and whitelist-bypass payloads through candidate redirect parameters, FOLLOWS NO REDIRECT, and inspects the Location header: a 3xx whose Location points at an attacker-controlled host is a confirmed open redirect (and a report_finding). Use this instead of eyeballing an HTTP response: a 200 or a same-site 302 is not a vulnerability, and a raw body cannot tell you where the browser would actually go. Pass the endpoint URL (with or without the parameter)."
	return readTool("redirect_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(in, &a)
		raw := strings.TrimSpace(a.URL)
		if raw == "" {
			return actool.Errorf("url is required: pass the endpoint to test, e.g. http://host:3000/redirect"), nil
		}
		base, err := url.Parse(raw)
		if err != nil || base.Host == "" {
			return actool.Errorf("redirect_verify needs an absolute URL (scheme://host[:port]/path), got: " + clipXSS(raw, 120)), nil
		}
		origin := base.Host // host[:port]

		// Which parameters to test: any URL-valued ones already on the URL, else the wordlist.
		var params []string
		for name := range base.Query() {
			if isRedirectParam(name) {
				params = append(params, name)
			}
		}
		if len(params) == 0 {
			params = append(params, redirectParamNames...)
		}

		// Allowlisted decoy tokens: any URL-ish value already on the incoming URL,
		// plus URLs mined from the target's own response bodies (engine callback).
		// Deduplicated and capped so the battery stays bounded.
		var decoys []string
		seenDecoy := map[string]struct{}{}
		addDecoy := func(v string) {
			if !isURLish(v) {
				return
			}
			if _, ok := seenDecoy[v]; ok {
				return
			}
			seenDecoy[v] = struct{}{}
			decoys = append(decoys, v)
		}
		for _, vals := range base.Query() {
			for _, v := range vals {
				addDecoy(v)
			}
		}
		if t.redirectDecoys != nil {
			for _, d := range t.redirectDecoys(origin) {
				addDecoy(d)
			}
		}
		// Try ALL mined decoys, not a tiny top-slice: frequency is a weak signal for
		// "allowlist member" (asset CDNs dominate it), so the allowlist URL can sit
		// mid-list. The sampler already host-dedups and caps the set; the sweep is
		// cheap, so breadth here is what turns a contains-whitelist into a CONFIRM.
		if len(decoys) > 24 {
			decoys = decoys[:24]
		}

		client := &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // never follow: we inspect Location ourselves
			},
		}
		runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		payloads := redirectBypassPayloads(decoys)
		const maxRequests = 280 // safety valve for a chatty wordlist on a slow target; the 60s ctx also bounds us. The high-value params (to/url/redirect/...) are swept first, so the allowlist decoy is tried on them well within budget.
		tested := map[string]struct{}{}
		requests := 0
	sweep:
		for _, p := range params {
			for _, payload := range payloads {
				if runCtx.Err() != nil || requests >= maxRequests {
					break sweep
				}
				u := *base
				q := u.Query()
				q.Set(p, payload)
				u.RawQuery = q.Encode()
				req, e := http.NewRequestWithContext(runCtx, http.MethodGet, u.String(), nil)
				if e != nil {
					continue
				}
				resp, e := client.Do(req)
				requests++
				tested[p] = struct{}{}
				if e != nil {
					continue
				}
				status := resp.StatusCode
				loc := resp.Header.Get("Location")
				resp.Body.Close()
				if status >= 300 && status < 400 && locationHitsSentinel(loc) {
					return actool.Text(fmt.Sprintf(
						"CONFIRMED open redirect. Parameter %q on %s redirects off-site to an attacker-controlled host "+
							"(HTTP %d, Location: %s) using payload %q. This is a verified exploit: report_finding (open redirect) "+
							"with this request and the Location response as reproduction. Do NOT record it as a negative.",
						p, base.Path, status, clipXSS(loc, 200), payload)), nil
				}
			}
		}
		return actool.Text(fmt.Sprintf(
			"No open redirect: swept %d candidate parameter(s) on %s with %d payload(s) each (%d decoy token(s) mined from the "+
				"target's own pages), none produced a 3xx redirect to an attacker-controlled host (the endpoint either does not "+
				"redirect on these parameters or its validation holds). record_fact the negative; do NOT report_finding.",
			len(tested), base.Path, len(payloads), len(decoys))), nil
	})
}
