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
