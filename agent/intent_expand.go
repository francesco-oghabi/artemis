package agent

import (
	"fmt"
	"sort"
	"strings"

	"artemis/db"
)

// maxXSSExpandIntents is the DEFAULT cap on how many XSS verification intents the
// expander writes in one shot, used when the caller passes cap<=0. The live value is
// configurable per deployment (Manager.XSSExpandCap, DB setting xss_expand_cap): a
// surface with many client routes should not flood a small worker pool, but more
// workers / faster hardware can drain a wider frontier, so the cap is a knob, not a
// constant. The oracle refutes a non-reflecting route cheaply, so the default is generous.
const maxXSSExpandIntents = 40

// spaRouteCandidates filters mined endpoint paths down to the client-side SPA
// routes worth RENDERING for a reflected/DOM XSS check: it drops the JSON API
// surface (/rest, /api) and anything that looks like a static asset, keeping the
// client route names. Deduplicated, then ORDERED so the shallow top-level routes
// (which are the main rendered pages that read query params, e.g. /search) come
// first and survive the cap, rather than an arbitrary alphabetical cut that could
// drop them. Order: fewer path segments, then shorter, then lexical. Nothing here
// is target specific. cap<=0 falls back to maxXSSExpandIntents.
func spaRouteCandidates(eps []string, maxN int) []string {
	if maxN <= 0 {
		maxN = maxXSSExpandIntents
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(eps))
	for _, p := range eps {
		lp := strings.ToLower(p)
		if strings.HasPrefix(lp, "/rest") || strings.HasPrefix(lp, "/api") {
			continue // JSON API, not a rendered page
		}
		if strings.Contains(p, ".") {
			continue // looks like a static asset, not a route
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := strings.Count(out[i], "/"), strings.Count(out[j], "/")
		if si != sj {
			return si < sj
		}
		if len(out[i]) != len(out[j]) {
			return len(out[i]) < len(out[j])
		}
		return out[i] < out[j]
	})
	if len(out) > maxN {
		out = out[:maxN]
	}
	return out
}

// Surface is everything the deterministic expander knows about the target at the
// moment it runs: the base URL, the renderable SPA routes mined from the JS bundle
// (the input for XSS), and the (path, param) pairs observed in the captured
// traffic (the input for parameter-driven classes like open redirect). The engine
// fills it incrementally and only sets a field once that data is actually
// available, so an empty field means "not ready yet, retry next round".
type Surface struct {
	Base   string
	Routes []string  // SPA routes from the JS bundle (XSS)
	Params []ParamHit // observed (path, query-param) pairs from traffic (open redirect, ...)
}

// ParamHit mirrors traffic.ParamHit at the agent layer (kept decoupled from the
// traffic package): one observed URL path + query-parameter name.
type ParamHit struct {
	Path  string
	Param string
}

// ExpandReadyClasses deterministically populates the frontier with verification
// intents for every registered class whose data is ready and that has not fired
// yet. The engine calls it each planner round, passing which classes already
// fired, so each class fires exactly ONCE per task, as soon as its slice of the
// surface is captured, independent of whether the planner ever generates the
// right intent (the variance seen in tasks 51/53 vs 52). It returns how many
// intents each class created and the classes that fired this call (so the engine
// can mark them done and never retry). Dedup is delegated to addOneIntent
// (canonical class + endpoint), so a planner-authored intent on the same
// route/endpoint collapses into the expander's.
// caps holds the per-class intent cap keyed by class name (from Manager.XSSExpandCap
// / RedirectExpandCap). A missing or <=0 entry means "use the class default".
func ExpandReadyClasses(ts *db.ExplorationStore, s Surface, fired map[string]bool, caps map[string]int) (perClass map[string]int, nowFired []string) {
	perClass = map[string]int{}
	if ts == nil {
		return perClass, nil
	}
	s.Base = strings.TrimRight(strings.TrimSpace(s.Base), "/")
	if s.Base == "" {
		return perClass, nil
	}
	t := &ToolSet{ts: ts, worker: "intent-expander"}
	for _, c := range vulnClasses {
		name := c.Name()
		if fired[name] {
			continue
		}
		mn := caps[name]
		if mn <= 0 {
			mn = c.DefaultCap()
		}
		sums := c.Expand(s, mn)
		if len(sums) == 0 {
			continue // not ready / nothing discovered for this class: retry next round
		}
		n := 0
		for _, sm := range sums {
			id, e := t.addOneIntent(intentItem{Summary: sm, Priority: 6})
			if e == nil && id > 0 {
				n++
			}
		}
		perClass[name] = n
		nowFired = append(nowFired, name)
	}
	return perClass, nowFired
}

// xssSummaries builds one XSS verification intent per renderable SPA route. This
// is the exact behavior validated on task 54 (40 distinct intents), kept bit for
// bit so that validation still holds.
func xssSummaries(s Surface, maxN int) []string {
	var out []string
	for _, r := range spaRouteCandidates(s.Routes, maxN) {
		url := s.Base + "/#/" + strings.TrimPrefix(r, "/")
		out = append(out, xssIntentSummary(r, url))
	}
	return out
}

// xssIntentSummary builds the self-contained intent text for one route.
//
// The route path MUST be the FIRST slash-word in the summary: the intent dedup
// key (addOneIntent) is canonical class + extractEndpoint(summary), and
// extractEndpoint grabs the first /path it sees. Any earlier slash in the prose
// (e.g. "reflected/DOM" -> "/DOM") would be identical across routes and collapse
// every intent into one (the task-54 bug). Keep the wording slash-free before the
// route. The companion test locks this in.
func xssIntentSummary(route, url string) string {
	return fmt.Sprintf(
		"XSS check on the SPA route %s: call xss_verify with the URL %s to confirm or refute a "+
			"reflected or DOM-based XSS. No FUZZ needed: the oracle sweeps candidate query "+
			"parameters and renders the page in a real headless browser. If xss_verify returns "+
			"CONFIRMED, report_finding for the XSS with that URL and the payload as reproduction. "+
			"If it reports no execution, record_fact the negative and do NOT report_finding. Do "+
			"NOT conclude anything about XSS from an unrendered HTTP or JSON response.",
		route, url)
}

// maxRedirectExpandIntents is the DEFAULT cap on open-redirect verification intents
// the expander writes in one shot, used when the caller passes cap<=0. The live value
// is configurable (Manager.RedirectExpandCap, DB setting redirect_expand_cap).
// redirect_verify refutes a non-redirecting endpoint with a single cheap request, so
// the default is generous.
const maxRedirectExpandIntents = 25

// redirectParamNames is the wordlist of query-parameter names whose semantics are
// "a URL to send the user to": the candidate parameters for an open redirect. It
// is the single source of truth for this class, used BOTH to pick candidates out
// of the observed traffic (openRedirectCandidates) and to sweep when the verifier
// is handed a bare endpoint (redirect_verify). Lowercased for case-insensitive
// matching. Nothing here is target specific.
var redirectParamNames = []string{
	"to", "redirect", "redirecturl", "redirect_uri", "redirecturi", "redir",
	"returnurl", "return_url", "returnto", "return", "next", "url",
	"dest", "destination", "continue", "goto", "callback", "forward",
}

func isRedirectParam(name string) bool {
	ln := strings.ToLower(strings.TrimSpace(name))
	for _, w := range redirectParamNames {
		if ln == w {
			return true
		}
	}
	return false
}

// openRedirectCandidates filters the observed (path, param) pairs down to the ones
// whose parameter name carries URL semantics (redirectParamNames), then keeps ONE
// candidate per endpoint path (the verifier sweeps the wordlist itself, so the
// intent granularity is per endpoint, not per param: same rationale as one XSS
// intent per route). Ordered shallow-first so the main top-level endpoints survive
// the cap, then capped. Nothing here is target specific.
func openRedirectCandidates(params []ParamHit, maxN int) []ParamHit {
	if maxN <= 0 {
		maxN = maxRedirectExpandIntents
	}
	byPath := map[string]string{} // path -> first URL-valued param seen
	var order []string
	for _, h := range params {
		if h.Path == "" || !isRedirectParam(h.Param) {
			continue
		}
		if _, ok := byPath[h.Path]; ok {
			continue
		}
		byPath[h.Path] = h.Param
		order = append(order, h.Path)
	}
	sort.Slice(order, func(i, j int) bool {
		si, sj := strings.Count(order[i], "/"), strings.Count(order[j], "/")
		if si != sj {
			return si < sj
		}
		if len(order[i]) != len(order[j]) {
			return len(order[i]) < len(order[j])
		}
		return order[i] < order[j]
	})
	out := make([]ParamHit, 0, len(order))
	for _, p := range order {
		out = append(out, ParamHit{Path: p, Param: byPath[p]})
	}
	if len(out) > maxN {
		out = out[:maxN]
	}
	return out
}

// openRedirectSummaries builds one open-redirect verification intent per candidate
// endpoint observed in the traffic.
func openRedirectSummaries(s Surface, maxN int) []string {
	var out []string
	for _, c := range openRedirectCandidates(s.Params, maxN) {
		url := s.Base + "/" + strings.TrimPrefix(c.Path, "/")
		out = append(out, openRedirectIntentSummary(c.Path, c.Param, url))
	}
	return out
}

// openRedirectIntentSummary builds the self-contained intent text for one endpoint.
//
// Same dedup invariant as xssIntentSummary: the endpoint path MUST be the FIRST
// slash-word in the text (the dedup key is class + extractEndpoint, which grabs the
// first /path), and the text MUST contain the class phrase "open redirect" so
// intentClass canonicalizes it to "openredirect". The companion test locks both.
func openRedirectIntentSummary(endpoint, param, url string) string {
	return fmt.Sprintf(
		"Open redirect check on the endpoint %s: call redirect_verify with the URL %s (observed "+
			"URL-valued parameter: %s) to confirm or refute an open redirect. No payload needed: the "+
			"verifier sweeps common redirect parameters, follows no redirect, fires whitelist-bypass "+
			"payloads and inspects the Location header. If redirect_verify returns CONFIRMED, "+
			"report_finding for the open redirect with that URL and payload as reproduction. If it "+
			"reports no redirect, record_fact the negative and do NOT report_finding. Do NOT conclude "+
			"anything about open redirect from an HTTP response body alone.",
		endpoint, url, param)
}
