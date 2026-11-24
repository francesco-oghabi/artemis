package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	actool "artemis/engine/tool"
)

// TestV06V16Classes locks canonicalization/firing of the new IDOR and
// business-logic classes and their presence in the registry.
func TestV06V16Classes(t *testing.T) {
	s := Surface{Base: "http://juice-shop:3000"}
	for _, tc := range []struct {
		name string
		sums func(Surface, int) []string
		want string
	}{
		{"idor", idorSummaries, "idor"},
		{"buslogic", buslogicSummaries, "buslogic"},
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
	names := map[string]bool{}
	for _, n := range ExpandClassNames() {
		names[n] = true
	}
	if !names["idor"] || !names["buslogic"] {
		t.Fatalf("registry missing new classes: %v", ExpandClassNames())
	}
}

// TestIDORBuslogicHelpers locks the pure helpers the oracles' verdicts rest on.
func TestIDORBuslogicHelpers(t *testing.T) {
	// extractToken must return a FULL JWT (with signature), not the detector's
	// signature-less prefix.
	full := "eyJhbGciOiJIUzI1NiJ9.eyJ1Ijoxfq.abcDEF123"
	if got := extractToken(`{"authentication":{"token":"` + full + `"}}`); got != full {
		t.Fatalf("extractToken(json) = %q, want %q", got, full)
	}
	if got := extractToken("prefix " + full + " suffix"); got != full {
		t.Fatalf("extractToken(bare) = %q, want %q", got, full)
	}
	if n, ok := mineIntField(`{"bid":"7","x":1}`, basketIDFields); !ok || n != 7 {
		t.Fatalf("mineIntField bid: got %d,%v want 7,true", n, ok)
	}
	if n, ok := mineIntField(`{"BasketId":42}`, basketIDFields); !ok || n != 42 {
		t.Fatalf("mineIntField BasketId: got %d,%v want 42,true", n, ok)
	}
	if _, ok := mineIntField(`{"other":1}`, basketIDFields); ok {
		t.Fatal("mineIntField must miss when no key present")
	}
	if !negEchoed(`{"quantity":-1,"id":5}`, "quantity", -1) {
		t.Fatal("negEchoed must match a persisted negative")
	}
	if negEchoed(`{"quantity":1}`, "quantity", -1) {
		t.Fatal("negEchoed must not match a positive")
	}
}

// fakeAuthServer is a minimal target that registers accounts and logs them in,
// handing out a per-account bearer token (with a signature). Object routes are
// delegated to obj with the authenticated owner resolved from the token.
func fakeAuthServer(obj func(w http.ResponseWriter, r *http.Request, owner string)) *httptest.Server {
	var seq int64
	var mu sync.Mutex
	tokens := map[string]string{} // token -> owner email
	mux := http.NewServeMux()
	mux.HandleFunc("/api/Users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})
	mux.HandleFunc("/rest/user/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		email, _ := body["email"].(string)
		if !strings.HasPrefix(email, "artemis_") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n := atomic.AddInt64(&seq, 1)
		tok := fmt.Sprintf("eyJhbGciOiJIUzI1NiJ9.eyJ1Ijo%dfq.sig%d", n, n)
		mu.Lock()
		tokens[tok] = email
		mu.Unlock()
		_, _ = w.Write([]byte(fmt.Sprintf(`{"authentication":{"token":"%s","bid":%d}}`, tok, n)))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		owner := ""
		if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
			mu.Lock()
			owner = tokens[strings.TrimPrefix(ah, "Bearer ")]
			mu.Unlock()
		}
		obj(w, r, owner)
	})
	return httptest.NewServer(mux)
}

func flattenCall(t *testing.T, tool actool.CoreTool, url string) string {
	t.Helper()
	res, err := tool.Call(context.Background(), json.RawMessage(`{"url":"`+url+`"}`), nil)
	if err != nil {
		t.Fatalf("tool call error: %v", err)
	}
	return res.Flatten()
}

// TestIDORVerifyConfirmAndRefute drives idor_verify against a fake that serves a
// per-user object by id without ownership checks (vulnerable), then with checks.
func TestIDORVerifyConfirmAndRefute(t *testing.T) {
	var mu sync.Mutex
	owners := map[string]string{} // "/rest/basket/N" -> bound owner email
	vulnerable := true

	srv := fakeAuthServer(func(w http.ResponseWriter, r *http.Request, owner string) {
		if !strings.HasPrefix(r.URL.Path, "/rest/basket/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mu.Lock()
		if owner != "" {
			if _, ok := owners[r.URL.Path]; !ok {
				owners[r.URL.Path] = owner // first authenticated reader binds the object
			}
		}
		bindOwner := owners[r.URL.Path]
		mu.Unlock()
		if bindOwner == "" || owner == "" { // unknown object, or unauthenticated
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !vulnerable && owner != bindOwner {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"basket":"of ` + bindOwner + `","owner":"` + bindOwner + `"}`))
	})
	defer srv.Close()

	ts := &ToolSet{worker: "test"}
	if out := flattenCall(t, ts.idorVerify(), srv.URL); !strings.Contains(out, "CONFIRMED IDOR") {
		t.Fatalf("vulnerable target: expected CONFIRMED, got: %s", out)
	}

	mu.Lock()
	owners = map[string]string{}
	mu.Unlock()
	vulnerable = false
	if out := flattenCall(t, ts.idorVerify(), srv.URL); strings.Contains(out, "CONFIRMED") {
		t.Fatalf("fixed target: expected no confirm, got: %s", out)
	}
}

// TestBuslogicVerifyConfirmAndRefute drives buslogic_verify against a fake basket
// that accepts (then rejects) a negative quantity.
func TestBuslogicVerifyConfirmAndRefute(t *testing.T) {
	acceptNegative := true
	srv := fakeAuthServer(func(w http.ResponseWriter, r *http.Request, owner string) {
		if r.URL.Path != "/api/BasketItems" || r.Method != http.MethodPost || owner == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		q, _ := body["quantity"].(float64)
		if q < 0 && !acceptNegative {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"quantity must be positive"}`))
			return
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"success","data":{"quantity":%d}}`, int(q))))
	})
	defer srv.Close()

	ts := &ToolSet{worker: "test"}
	if out := flattenCall(t, ts.buslogicVerify(), srv.URL); !strings.Contains(out, "CONFIRMED negative-quantity") {
		t.Fatalf("vulnerable target: expected CONFIRMED, got: %s", out)
	}

	acceptNegative = false
	if out := flattenCall(t, ts.buslogicVerify(), srv.URL); strings.Contains(out, "CONFIRMED") {
		t.Fatalf("fixed target: expected no confirm, got: %s", out)
	}
}
