package agent

import "testing"

// TestExtractEndpointURLvsPath pins the task-31 root cause: the same endpoint
// written as a full URL vs a bare path must yield the same target token (before
// the fix, the full URL produced "/juice-shop" because the regex stopped at ":").
func TestExtractEndpointURLvsPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"The login endpoint at /rest/user/login is vulnerable", "/rest/user/login"},
		{"The login endpoint at http://juice-shop:3000/rest/user/login is vulnerable", "/rest/user/login"},
		{"see https://host:8443/rest/user/login?x=1", "/rest/user/login"},
	}
	for _, c := range cases {
		if got := extractEndpoint(c.in); got != c.want {
			t.Errorf("extractEndpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestExtractEndpointNounFallback pins the generic-resource fallback for text
// that names a resource but carries no URL path (the four NoSQL "product review
// update endpoint" findings of task 31 all collapse to the same token).
func TestExtractEndpointNounFallback(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Cannot test NoSQL injection in product review update endpoint", "review"},
		{"Testing blocked in product review update endpoint due to SPA", "review"},
		{"a user bypasses login via injection", "login"},
		{"JWT token forged with none algorithm", "token"},
		{"no resource mentioned here at all", ""},
	}
	for _, c := range cases {
		if got := extractEndpoint(c.in); got != c.want {
			t.Errorf("extractEndpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFindingDedupKeyTask31 proves the two task-31 SQLi login findings and the
// four NoSQL findings now produce matching keys within their class (so they dedup).
func TestFindingDedupKeyTask31(t *testing.T) {
	k1 := findingDedupKey("SQL Injection", "SQL Injection in Login Email Parameter",
		"The login endpoint at /rest/user/login is vulnerable to SQL injection in the email parameter")
	k2 := findingDedupKey("SQL Injection", "SQL Injection in Login Endpoint Allows Authentication Bypass",
		"The login endpoint at http://juice-shop:3000/rest/user/login is vulnerable to SQL injection in the email parameter")
	if k1 == "" || k1 != k2 {
		t.Errorf("SQLi login keys must match and be non-empty: k1=%q k2=%q", k1, k2)
	}

	n1 := findingDedupKey("NoSQL Injection", "No exploit found - Cannot test NoSQL injection in product review update endpoint", "OWASP Juice Shop uses AngularJS SPA")
	n2 := findingDedupKey("nosql-injection", "No exploitable NoSQL injection vulnerability found in product review update endpoint", "Cannot test due to missing Chromium")
	if n1 == "" || n1 != n2 {
		t.Errorf("NoSQL keys must match and be non-empty: n1=%q n2=%q", n1, n2)
	}

	// A genuinely different class on the same target must NOT collapse into SQLi.
	x := findingDedupKey("XSS", "Reflected XSS in login form", "/rest/user/login reflects input")
	if x == k1 {
		t.Errorf("different class on same target wrongly merged: xss=%q sqli=%q", x, k1)
	}
}

// factDupDecision mirrors the L3d dedup condition in recordOneFact.
func factDupDecision(a, b string) bool {
	if na := normToken(a); na != "" && na == normToken(b) {
		return true
	}
	ta := factTokens(a)
	return len(ta) >= 3 && jaccard(ta, factTokens(b)) >= factDupJaccard
}

// TestFactDedupL3d pins L3d: identical and trivially reworded restatements collapse,
// genuinely distinct facts do not, and the known limit (differently-worded same
// conclusion, which needs embeddings) is documented as NOT merged.
func TestFactDedupL3d(t *testing.T) {
	// identical restatement (the task-34 x48 block) → merged via exact key
	if !factDupDecision(
		"Test for business logic flaws involving negative quantities",
		"Test for business logic flaws involving negative quantities") {
		t.Error("identical fact not merged")
	}
	// reordered / trivially reworded → merged via token-set overlap
	if !factDupDecision(
		"business logic flaw negative quantity not exploitable confirmed",
		"confirmed business logic flaw not exploitable negative quantity") {
		t.Error("reordered fact not merged")
	}
	// genuinely distinct conclusions → must NOT merge
	if factDupDecision(
		"SQL injection confirmed in login email parameter returning admin token",
		"IDOR allows reading another user basket via rest basket id") {
		t.Error("distinct facts wrongly merged")
	}
	// KNOWN LIMIT: same conclusion worded very differently stays separate (overlap
	// ~0.45 < threshold); collapsing it would need semantic embeddings (out of scope).
	if factDupDecision(
		"Confirmed that AngularJS routing completely blocks direct API access",
		"Final conclusion the AngularJS routing prevents direct API access") {
		t.Error("low-overlap pair unexpectedly merged (threshold too low)")
	}
}
