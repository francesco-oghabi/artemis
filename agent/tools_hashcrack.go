package agent

import (
	"context"
	"crypto/md5"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	actool "artemis/engine/tool"
)

// Generic offline hash cracker (currently MD5, unsalted). Turns a recognized weak
// hash (e.g. the MD5s dumped by injection_verify for V12) into the actual password
// via a dictionary attack. Dictionaries come from three sources, unioned: a small
// embedded list of common passwords (zero-config), any *.txt the user drops into the
// wordlists directory (ARTEMIS_WORDLISTS_DIR, default data/wordlists, persisted in
// the data volume and reusable across tasks/contexts), and an optional inline list.
// Only MD5 for now; SHA1/SHA256/salted/bcrypt are on the roadmap.

//go:embed wordlists/common.txt
var embeddedWordlist string

var (
	embWordsOnce sync.Once
	embWords     []string
)

// splitWords splits a wordlist blob into trimmed, non-empty, de-commented lines.
func splitWords(blob string) []string {
	var out []string
	for _, ln := range strings.Split(blob, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func embeddedWords() []string {
	embWordsOnce.Do(func() { embWords = splitWords(embeddedWordlist) })
	return embWords
}

// wordlistDir returns the user wordlists directory (env override, else data/wordlists
// relative to the working directory, which is the data volume in the container).
func wordlistDir() string {
	if d := strings.TrimSpace(os.Getenv("ARTEMIS_WORDLISTS_DIR")); d != "" {
		return d
	}
	return filepath.Join("data", "wordlists")
}

// loadWordlist unions the embedded list, every *.txt in the user wordlists dir, and
// an optional inline list. Order: inline first (most specific), then user files,
// then embedded.
func loadWordlist(inline string) []string {
	var words []string
	if strings.TrimSpace(inline) != "" {
		words = append(words, splitWords(inline)...)
	}
	if entries, err := os.ReadDir(wordlistDir()); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".txt") {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(wordlistDir(), e.Name())); err == nil {
				words = append(words, splitWords(string(b))...)
			}
		}
	}
	return append(words, embeddedWords()...)
}

var md5HashRe = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)

// extractMD5Hashes pulls every 32-hex token out of arbitrary text (handles plain
// hashes, "email:hash" dump lines, JSON, etc.), lowercased and de-duplicated.
func extractMD5Hashes(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range md5HashRe.FindAllString(s, -1) {
		m = strings.ToLower(m)
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

const hashCrackMaxWords = 5_000_000

// crackMD5 computes md5 over words (bounded by cap) and returns the hash->plaintext
// pairs that match one of the target hashes. One pass over the wordlist regardless of
// how many targets.
func crackMD5(targets, words []string, cap int) map[string]string {
	want := map[string]bool{}
	for _, h := range targets {
		if len(h) == 32 {
			want[strings.ToLower(h)] = true
		}
	}
	out := map[string]string{}
	if len(want) == 0 {
		return out
	}
	for i, w := range words {
		if i >= cap {
			break
		}
		sum := md5.Sum([]byte(w))
		h := hex.EncodeToString(sum[:])
		if want[h] {
			if _, done := out[h]; !done {
				out[h] = w
				if len(out) == len(want) {
					break
				}
			}
		}
	}
	return out
}

func (t *ToolSet) hashCrack() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"hashes": map[string]any{
				"type":        "string",
				"description": "One or more MD5 hashes to crack. Accepts plain hashes, 'email:hash' dump lines, or any text: every 32-hex token is extracted. Separate multiple by newlines/spaces/commas.",
			},
			"wordlist": map[string]any{
				"type":        "string",
				"description": "Optional extra dictionary: newline-separated words tried IN ADDITION to the built-in common-passwords list and any *.txt in the wordlists directory.",
			},
			"algorithm": map[string]any{
				"type":        "string",
				"description": "Hash algorithm. Only 'md5' is supported for now (default); others are on the roadmap.",
			},
		},
		"required": []any{"hashes"},
	}
	desc := "Offline dictionary crack of MD5 hashes (unsalted). Give it hashes (plain, or 'email:hash' lines from a SQLi dump) and it tries a built-in common-password list, any user dictionaries in the wordlists directory, and an optional inline wordlist, returning the recovered plaintext for each hash it cracks. A cracked credential hash is a real finding (weak, crackable password storage). Only MD5 for now."
	return readTool("hash_crack", desc, schema, func(_ context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Hashes    string `json:"hashes"`
			Wordlist  string `json:"wordlist"`
			Algorithm string `json:"algorithm"`
		}
		_ = json.Unmarshal(in, &a)
		if alg := strings.ToLower(strings.TrimSpace(a.Algorithm)); alg != "" && alg != "md5" {
			return actool.Errorf("hash_crack currently supports only algorithm=md5 (got " + clipXSS(alg, 40) + "); SHA1/SHA256/salted/bcrypt are on the roadmap."), nil
		}
		targets := extractMD5Hashes(a.Hashes)
		if len(targets) == 0 {
			return actool.Errorf("hash_crack: no 32-hex MD5 hash found in `hashes`."), nil
		}
		cracked := crackMD5(targets, loadWordlist(a.Wordlist), hashCrackMaxWords)
		if len(cracked) == 0 {
			return actool.Text(fmt.Sprintf(
				"No hash cracked: tried the dictionary against %d MD5 hash(es), none matched a known word. Add a larger "+
					"dictionary (.txt) under the wordlists directory and retry. record_fact the negative.", len(targets))), nil
		}
		var lines []string
		for h, w := range cracked {
			lines = append(lines, h+" = "+w)
		}
		return actool.Text(fmt.Sprintf(
			"CRACKED %d/%d MD5 hash(es): %s. These are recovered plaintext passwords, confirming weak (unsalted, "+
				"dictionary-crackable) password storage: report_finding (weak password hashing / cracked credentials) with "+
				"the cracked pairs as evidence.", len(cracked), len(targets), strings.Join(lines, "; "))), nil
	})
}
