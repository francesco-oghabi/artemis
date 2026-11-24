package agent

import (
	"strings"
	"testing"
)

// TestForgeConfusion locks the RS256->HS256 confusion forger: HS256 header, payload
// kept, signed with the public-key bytes as the HMAC secret (one variant per
// distinct secret representation).
func TestForgeConfusion(t *testing.T) {
	pub := "-----BEGIN RSA PUBLIC KEY-----\nMIGabc\n-----END RSA PUBLIC KEY-----\n"
	out := forgeConfusion("eyJ1IjoxfQ", pub)
	if len(out) != 2 { // pub and its trailing-newline-trimmed form differ => 2
		t.Fatalf("got %d variants, want 2", len(out))
	}
	for _, f := range out {
		parts := strings.Split(f[1], ".")
		if len(parts) != 3 || parts[1] != "eyJ1IjoxfQ" {
			t.Fatalf("malformed forged token: %q", f[1])
		}
	}
	if forgeConfusion("", pub) != nil || forgeConfusion("p", "") != nil {
		t.Fatal("empty inputs must yield nil")
	}
}
