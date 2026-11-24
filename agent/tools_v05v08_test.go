package agent

import "testing"

// TestV05V08Classes locks canonicalization/firing of mass-assignment and stored-XSS
// classes and their presence in the registry.
func TestV05V08Classes(t *testing.T) {
	s := Surface{Base: "http://juice-shop:3000"}
	if out := massassignSummaries(s, 0); len(out) != 1 || intentClass(out[0]) != "massassign" {
		t.Fatalf("massassign: got %v", out)
	}
	if massassignSummaries(Surface{}, 0) != nil {
		t.Fatal("massassign: empty base should yield nil")
	}
	if out := storedXSSSummaries(s, 0); len(out) != 1 || intentClass(out[0]) != "xss" {
		t.Fatalf("storedxss: got %v (class %q)", out, intentClass(out[0]))
	}
	if storedXSSSummaries(Surface{}, 0) != nil {
		t.Fatal("storedxss: empty base should yield nil")
	}
	names := map[string]bool{}
	for _, n := range ExpandClassNames() {
		names[n] = true
	}
	if !names["massassign"] || !names["storedxss"] {
		t.Fatalf("registry missing classes: %v", ExpandClassNames())
	}
}

// TestMassassignJSONHelpers locks the field extractors the verdict rests on.
func TestMassassignJSONHelpers(t *testing.T) {
	if v, ok := jsonStrField(`{"role":"admin","x":1}`, "role"); !ok || v != "admin" {
		t.Fatalf("jsonStrField role: %q %v", v, ok)
	}
	if _, ok := jsonStrField(`{"x":1}`, "role"); ok {
		t.Fatal("jsonStrField must miss absent key")
	}
	if !jsonBoolTrue(`{"isAdmin": true}`, "isAdmin") {
		t.Fatal("jsonBoolTrue must match true")
	}
	if jsonBoolTrue(`{"isAdmin": false}`, "isAdmin") {
		t.Fatal("jsonBoolTrue must not match false")
	}
}
