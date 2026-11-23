package agent

import (
	"strings"
	"testing"
)

// TestXSSIntentSummaryDedupKeysDistinct locks the task-54 regression: each route
// must yield a DISTINCT dedup key, otherwise addOneIntent collapses every
// expanded intent into one. The key is canonical class + extractEndpoint(summary);
// the route must be the first slash-word so extractEndpoint picks it (not a slash
// buried in the prose like "reflected/DOM").
func TestXSSIntentSummaryDedupKeysDistinct(t *testing.T) {
	base := "http://juice-shop:3000"
	routes := []string{"/search", "/2fa/enter", "/track-result", "/contact", "/complain"}
	seen := map[string]string{}
	for _, r := range routes {
		url := base + "/#/" + strings.TrimPrefix(r, "/")
		summary := xssIntentSummary(r, url)
		if cls := intentClass(summary); cls != "xss" {
			t.Fatalf("route %s: class = %q, want xss", r, cls)
		}
		key := intentDedupKey(summary)
		if key == "" {
			t.Fatalf("route %s: empty dedup key (would fall back to exact-text)", r)
		}
		if prev, ok := seen[key]; ok {
			t.Fatalf("route %s collides on dedup key %q with route %s", r, key, prev)
		}
		seen[key] = r
	}
}

// TestExpandCapsConfigurable locks the 4c behavior: a positive maxN truncates the
// candidate list (deployments with few workers keep the frontier small), while maxN<=0
// falls back to the generous package default (so the engine passing 0 == old behavior).
func TestExpandCapsConfigurable(t *testing.T) {
	routes := []string{"/a", "/b", "/c", "/d", "/e"}
	if got := spaRouteCandidates(routes, 2); len(got) != 2 {
		t.Fatalf("spaRouteCandidates cap=2: got %d, want 2 (%v)", len(got), got)
	}
	if got := spaRouteCandidates(routes, 0); len(got) != len(routes) {
		t.Fatalf("spaRouteCandidates cap=0: got %d, want %d (default, no truncation under %d)", len(got), len(routes), maxXSSExpandIntents)
	}
	params := []ParamHit{{"/p1", "to"}, {"/p2", "url"}, {"/p3", "next"}}
	if got := openRedirectCandidates(params, 1); len(got) != 1 {
		t.Fatalf("openRedirectCandidates cap=1: got %d, want 1", len(got))
	}
	if got := openRedirectCandidates(params, 0); len(got) != len(params) {
		t.Fatalf("openRedirectCandidates cap=0: got %d, want %d (default)", len(got), len(params))
	}
}

// TestSpaRouteCandidatesOrderAndFilter: API/asset paths dropped, shallow routes
// first (so /search survives the cap), capped.
func TestSpaRouteCandidatesOrderAndFilter(t *testing.T) {
	in := []string{
		"/rest/products/search", "/api/Feedbacks", "/main.js", "/assets/x.png",
		"/track-result/new", "/search", "/contact", "/administration",
	}
	out := spaRouteCandidates(in, 0) // 0 → default cap (maxXSSExpandIntents)
	for _, p := range out {
		if strings.HasPrefix(p, "/rest") || strings.HasPrefix(p, "/api") || strings.Contains(p, ".") {
			t.Fatalf("candidate %q should have been filtered out", p)
		}
	}
	// /search is a single-segment route: it must come before the two-segment
	// /track-result/new in the ordering.
	posSearch, posDeep := -1, -1
	for i, p := range out {
		if p == "/search" {
			posSearch = i
		}
		if p == "/track-result/new" {
			posDeep = i
		}
	}
	if posSearch < 0 {
		t.Fatal("/search missing from candidates")
	}
	if posDeep >= 0 && posSearch > posDeep {
		t.Fatalf("/search (pos %d) should precede /track-result/new (pos %d)", posSearch, posDeep)
	}
}

// TestOpenRedirectIntentSummaryDedupKeysDistinct: same invariant as the XSS test,
// for the open-redirect class. Each endpoint must yield a DISTINCT dedup key and
// canonicalize to class "openredirect", or addOneIntent collapses the intents.
func TestOpenRedirectIntentSummaryDedupKeysDistinct(t *testing.T) {
	base := "http://juice-shop:3000"
	endpoints := []struct{ path, param string }{
		{"/redirect", "to"},
		{"/goto", "url"},
		{"/track-order", "next"},
	}
	seen := map[string]string{}
	for _, ep := range endpoints {
		url := base + "/" + strings.TrimPrefix(ep.path, "/")
		summary := openRedirectIntentSummary(ep.path, ep.param, url)
		if cls := intentClass(summary); cls != "openredirect" {
			t.Fatalf("endpoint %s: class = %q, want openredirect", ep.path, cls)
		}
		key := intentDedupKey(summary)
		if key == "" {
			t.Fatalf("endpoint %s: empty dedup key (would fall back to exact-text)", ep.path)
		}
		if prev, ok := seen[key]; ok {
			t.Fatalf("endpoint %s collides on dedup key %q with %s", ep.path, key, prev)
		}
		seen[key] = ep.path
	}
}

// TestOpenRedirectCandidatesFilterAndOrder: only URL-valued parameters are kept,
// one candidate per endpoint path, shallow endpoints first.
func TestOpenRedirectCandidatesFilterAndOrder(t *testing.T) {
	in := []ParamHit{
		{Path: "/products/search", Param: "q"},     // not a redirect param: dropped
		{Path: "/redirect", Param: "to"},           // kept
		{Path: "/redirect", Param: "to"},           // duplicate endpoint: collapsed
		{Path: "/a/b/c/goto", Param: "url"},        // kept, deep
		{Path: "/profile", Param: "username"},       // not a redirect param: dropped
		{Path: "/logout", Param: "returnUrl"},       // kept (case-insensitive param)
	}
	out := openRedirectCandidates(in, 0) // 0 → default cap (maxRedirectExpandIntents)
	paths := map[string]bool{}
	for _, c := range out {
		paths[c.Path] = true
	}
	if paths["/products/search"] || paths["/profile"] {
		t.Fatalf("non-redirect params should have been filtered: %+v", out)
	}
	if !paths["/redirect"] || !paths["/logout"] || !paths["/a/b/c/goto"] {
		t.Fatalf("redirect endpoints missing from candidates: %+v", out)
	}
	// one per endpoint
	count := 0
	for _, c := range out {
		if c.Path == "/redirect" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("/redirect should appear once, got %d", count)
	}
	// shallow (/redirect) before deep (/a/b/c/goto)
	posShallow, posDeep := -1, -1
	for i, c := range out {
		if c.Path == "/redirect" {
			posShallow = i
		}
		if c.Path == "/a/b/c/goto" {
			posDeep = i
		}
	}
	if posShallow > posDeep {
		t.Fatalf("/redirect (pos %d) should precede deep /a/b/c/goto (pos %d)", posShallow, posDeep)
	}
}

// TestRedirectBypassPayloadsDecoys locks Fix 2: the battery always carries the
// four generic payloads, AND one contains-whitelist-bypass payload per decoy that
// embeds the allowlisted token while still pointing the victim at the sentinel.
func TestRedirectBypassPayloadsDecoys(t *testing.T) {
	// No decoys: only the generic battery, and NO own-origin decoy (old Bug B).
	generic := redirectBypassPayloads(nil)
	if len(generic) != 4 {
		t.Fatalf("generic battery should be 4 payloads, got %d: %v", len(generic), generic)
	}
	for _, p := range generic {
		if strings.Contains(p, "?d=") || strings.Contains(p, "?x=") {
			t.Fatalf("generic payload %q must not embed a decoy", p)
		}
	}
	// With a mined allowlisted decoy, a bypass payload embeds it and still resolves
	// off-site to the sentinel (so locationHitsSentinel would fire on reflection).
	decoy := "https://github.com/juice-shop/juice-shop"
	withDecoy := redirectBypassPayloads([]string{decoy})
	if len(withDecoy) != len(generic)+1 {
		t.Fatalf("one decoy should add exactly one payload: got %d", len(withDecoy))
	}
	last := withDecoy[len(withDecoy)-1]
	if !strings.Contains(last, decoy) {
		t.Fatalf("decoy payload %q must embed the allowlisted token", last)
	}
	if !locationHitsSentinel(last) {
		t.Fatalf("decoy payload %q must still resolve to the attacker sentinel", last)
	}
}

// TestIsURLish: only scheme-ish, dotted hosts qualify as decoy tokens.
func TestIsURLish(t *testing.T) {
	for _, ok := range []string{"https://github.com/x", "http://a.b/c", "//cdn.example.com/x"} {
		if !isURLish(ok) {
			t.Fatalf("%q should be URL-ish", ok)
		}
	}
	for _, no := range []string{"", "/rest", "juice-shop:3000", "1", "to", "https://localhost"} {
		if isURLish(no) {
			t.Fatalf("%q should NOT be URL-ish", no)
		}
	}
}

// TestRedirectSentinelDetection locks the Location-header judge.
func TestRedirectSentinelDetection(t *testing.T) {
	hits := []string{
		"https://attacker.example/",
		"//attacker.example/path",
		"http://sub.attacker.example/",
	}
	misses := []string{
		"", "/local/path", "https://juice-shop:3000/account",
		"https://attacker.example.evil.com/", // sentinel is not the host here
	}
	for _, h := range hits {
		if !locationHitsSentinel(h) {
			t.Fatalf("Location %q should be detected as off-site to the sentinel", h)
		}
	}
	for _, m := range misses {
		if locationHitsSentinel(m) {
			t.Fatalf("Location %q should NOT be detected as the sentinel", m)
		}
	}
}

// TestNewBreadthClassesCanonicalize locks that the exposure/csp intent texts
// canonicalize to their class (so dedup and recognition work) and that each
// VulnClass fires exactly one intent on a bare base.
func TestNewBreadthClassesCanonicalize(t *testing.T) {
	s := Surface{Base: "http://juice-shop:3000"}
	exp := exposureSummaries(s, 0)
	if len(exp) != 1 {
		t.Fatalf("exposureSummaries: got %d intents, want 1", len(exp))
	}
	if cls := intentClass(exp[0]); cls != "exposure" {
		t.Fatalf("exposure intent class = %q, want exposure", cls)
	}
	csp := cspSummaries(s, 0)
	if len(csp) != 1 {
		t.Fatalf("cspSummaries: got %d intents, want 1", len(csp))
	}
	if cls := intentClass(csp[0]); cls != "csp" {
		t.Fatalf("csp intent class = %q, want csp", cls)
	}
	// empty base => nothing (not ready)
	if exposureSummaries(Surface{}, 0) != nil || cspSummaries(Surface{}, 0) != nil {
		t.Fatal("empty base should yield no intents")
	}
}

// TestLooksExposedRejectsSPAFallback locks the key anti-false-positive: a body
// identical to the known-nonexistent baseline (the SPA 200+index shell) is NOT a
// hit, while a real sensitive body is.
func TestLooksExposedRejectsSPAFallback(t *testing.T) {
	spaShell := "<!DOCTYPE html><html><app-root></app-root></html>"
	// metrics served as the SPA shell: must be rejected.
	if looksExposed("metrics", "", "text/html", spaShell, spaShell) {
		t.Fatal("SPA-shell body must not count as metrics exposure")
	}
	// real Prometheus body, different from the shell: must confirm.
	prom := "# HELP http_requests_total Total\n# TYPE http_requests_total counter\nhttp_requests_total 5\n"
	if !looksExposed("metrics", "", "text/plain", prom, spaShell) {
		t.Fatal("real Prometheus body must count as metrics exposure")
	}
	// directory listing different from the shell: confirm.
	listing := `<html><title>listing</title><a href="a.md">a.md</a><a href="b.md">b.md</a></html>`
	if !looksExposed("listing", "", "text/html", listing, spaShell) {
		t.Fatal("directory listing must count as exposure")
	}
	// git HEAD with marker: confirm; without marker: reject.
	if !looksExposed("git", "ref:", "text/plain", "ref: refs/heads/main\n", spaShell) {
		t.Fatal("git HEAD with ref: marker must confirm")
	}
	if looksExposed("git", "ref:", "text/plain", "not a git file", spaShell) {
		t.Fatal("body without the required marker must be rejected")
	}
}

// TestInjectionClassSummaries locks that the injection recognizer emits an
// auth-bypass intent (canon authbypass) plus one SQLi intent per GET-param
// endpoint (canon sqli, distinct dedup keys), and that detection regexes fire.
func TestInjectionClassSummaries(t *testing.T) {
	s := Surface{
		Base:   "http://juice-shop:3000",
		Params: []ParamHit{{Path: "/rest/products/search", Param: "q"}, {Path: "/rest/track", Param: "id"}},
	}
	out := injectionSummaries(s, 0)
	if len(out) != 3 {
		t.Fatalf("injectionSummaries: got %d intents, want 3 (1 authbypass + 2 sqli)", len(out))
	}
	if cls := intentClass(out[0]); cls != "authbypass" {
		t.Fatalf("first intent class = %q, want authbypass", cls)
	}
	keys := map[string]bool{}
	for _, sm := range out[1:] {
		if cls := intentClass(sm); cls != "sqli" {
			t.Fatalf("sqli intent class = %q, want sqli", cls)
		}
		k := intentDedupKey(sm)
		if k == "" || keys[k] {
			t.Fatalf("sqli dedup key empty or collides: %q", k)
		}
		keys[k] = true
	}
	// empty base => nothing
	if injectionSummaries(Surface{}, 0) != nil {
		t.Fatal("empty base should yield no injection intents")
	}
}

// TestInjectionDetectors locks the evidence regexes used by the prober.
func TestInjectionDetectors(t *testing.T) {
	for _, e := range []string{
		"SQLITE_ERROR: near \"'\": syntax error",
		"You have an error in your SQL syntax",
		"ORA-00933: SQL command not properly ended",
	} {
		if !sqlErrorRe.MatchString(e) {
			t.Fatalf("sqlErrorRe should match %q", e)
		}
	}
	if sqlErrorRe.MatchString("totally normal product listing") {
		t.Fatal("sqlErrorRe false positive on benign body")
	}
	if !looksAuthenticated(`{"authentication":{"token":"eyJhbGciOiJИ.abcdefgh.sig"}}`) {
		t.Fatal("looksAuthenticated should detect a token field")
	}
	if !looksAuthenticated("prefix eyJabcdefgh.ijklmnop.qrstuvwx suffix") {
		t.Fatal("looksAuthenticated should detect a JWT")
	}
	if looksAuthenticated(`{"error":"Invalid email or password"}`) {
		t.Fatal("looksAuthenticated false positive on an auth failure")
	}
}

// TestNoteFactProgress locks the no-progress terminator (Lever 1+2): consecutive
// no-new-fact record_fact calls end the run after noProgressFactStop; a new fact
// resets the counter.
func TestNoteFactProgress(t *testing.T) {
	ts := &ToolSet{}
	// first (noProgressFactStop-1) redundant calls must NOT stop
	for i := 1; i < noProgressFactStop; i++ {
		if ts.noteFactProgress(false) {
			t.Fatalf("stop fired too early at redundant call %d (threshold %d)", i, noProgressFactStop)
		}
	}
	// the noProgressFactStop-th consecutive redundant call stops
	if !ts.noteFactProgress(false) {
		t.Fatalf("stop should fire at redundant call %d", noProgressFactStop)
	}
	// a new fact resets, so the next redundant call does not immediately stop
	ts = &ToolSet{}
	ts.noteFactProgress(false)
	ts.noteFactProgress(false)
	if ts.noteFactProgress(true) { // new fact: never stops, resets
		t.Fatal("a new fact must not stop and must reset the counter")
	}
	if ts.redundantFacts != 0 {
		t.Fatalf("new fact must reset counter, got %d", ts.redundantFacts)
	}
	for i := 1; i < noProgressFactStop; i++ {
		if ts.noteFactProgress(false) {
			t.Fatalf("after reset, stop fired too early at %d", i)
		}
	}
	if !ts.noteFactProgress(false) {
		t.Fatal("after reset, stop should fire at the threshold again")
	}
}

// TestV18V09V04Classes locks canonicalization/firing of the captcha, traversal and
// jwt classes plus the JWT forge helper.
func TestV18V09V04Classes(t *testing.T) {
	s := Surface{Base: "http://juice-shop:3000"}
	for _, tc := range []struct {
		name string
		sums func(Surface, int) []string
		want string
	}{
		{"captcha", captchaSummaries, "captcha"},
		{"traversal", traversalSummaries, "traversal"},
		{"jwt", jwtSummaries, "jwt"},
	} {
		out := tc.sums(s, 0)
		if len(out) != 1 {
			t.Fatalf("%s: got %d intents, want 1", tc.name, len(out))
		}
		if cls := intentClass(out[0]); cls != tc.want {
			t.Fatalf("%s intent class = %q, want %q", tc.name, cls, tc.want)
		}
		if tc.sums(Surface{}, 0) != nil {
			t.Fatalf("%s: empty base should yield no intents", tc.name)
		}
	}
}

// TestForgeJWTs locks the forgery helper: alg:none variants + one HS256 per weak key.
func TestForgeJWTs(t *testing.T) {
	// a minimal well-formed-looking token: header.payload.sig
	tok := "eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoxfQ.originalsig"
	out := forgeJWTs(tok)
	// 2 alg:none + len(jwtWeakKeys) HS256
	want := 2 + len(jwtWeakKeys)
	if len(out) != want {
		t.Fatalf("forgeJWTs: got %d variants, want %d", len(out), want)
	}
	// every forged token must keep the ORIGINAL payload segment
	for _, f := range out {
		if !strings.Contains(f[1], "eyJ1c2VyIjoxfQ") {
			t.Fatalf("forged %q dropped the original payload", f[0])
		}
	}
	// a malformed token yields nothing
	if forgeJWTs("notajwt") != nil {
		t.Fatal("forgeJWTs should reject a non-JWT")
	}
}

// TestLooksServedFile: a served file body (not the SPA shell, not a listing) is a hit.
func TestLooksServedFile(t *testing.T) {
	shell := "<!DOCTYPE html><app-root></app-root>"
	if looksServedFile("text/html", shell, shell) {
		t.Fatal("SPA shell must not count as a served file")
	}
	if !looksServedFile("application/json", `{"dependencies":{}}`, shell) {
		t.Fatal("a JSON file body must count as served")
	}
	if looksServedFile("text/html", `<html>Index of /ftp <a href=x>x</a></html>`, shell) {
		t.Fatal("a directory listing must not count (exposure handles it)")
	}
}
