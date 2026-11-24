package agent

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

func md5hex(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }

func TestCrackMD5Embedded(t *testing.T) {
	target := md5hex("admin123") // must be in the embedded common list
	got := crackMD5([]string{target}, embeddedWords(), len(embeddedWords()))
	if got[target] != "admin123" {
		t.Fatalf("expected admin123, got %v", got)
	}
	// a random/strong value must NOT crack
	if len(crackMD5([]string{md5hex("Zq9$kX2!pLm7_rare")}, embeddedWords(), len(embeddedWords()))) != 0 {
		t.Fatal("strong password should not crack against the common list")
	}
}

func TestExtractMD5Hashes(t *testing.T) {
	in := "admin@x.op:0192023a7bbd73250516f069df18b500\nfoo@x.op:5f4dcc3b5aa765d61d8327deb882cf99"
	got := extractMD5Hashes(in)
	if len(got) != 2 {
		t.Fatalf("want 2 hashes, got %v", got)
	}
}
