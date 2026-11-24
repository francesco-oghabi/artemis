package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	actool "artemis/engine/tool"
)

// Deterministic verifier for the negative-quantity business-logic flaw (Juice Shop
// V16, OWASP A04 Insecure Design). The invariant of the class: a server-side
// quantity/amount field must reject values outside its valid domain (a basket item
// cannot hold a negative quantity). A weak model cannot sustain the sequence
// (provision a session, submit a baseline, then an out-of-domain value, compare);
// it guesses from a single 200. This oracle does it in code:
//
//   - self-provision one throwaway session (generic register + login).
//   - sweep a generic wordlist of item-creation endpoints and quantity field names;
//     send a POSITIVE baseline (quantity 1) to prove the request shape works (2xx),
//     then the same request with a NEGATIVE quantity.
//   - confirm only when the negative value is ACCEPTED (2xx) and PERSISTED (echoed
//     back in the response), proving the invariant is not enforced.
//
// Everything is generic technique (endpoint / field-name wordlists), never a target
// fact. The baseline-must-work discipline means an endpoint whose shape we cannot
// satisfy is skipped (honest false-negative), never mislabeled; a confirm requires
// the server to echo the negative, so it does not false-positive on an error 200.

var basketItemPaths = []string{
	"/api/BasketItems", "/api/basketitems", "/rest/basket/items", "/api/Basket",
	"/api/cart", "/api/CartItems", "/cart/items", "/api/OrderItems",
}

var quantityFields = []string{"quantity", "qty", "amount", "count"}
var productIDFields = []string{"ProductId", "productId", "product", "productid", "itemId"}
var basketIDFields = []string{"BasketId", "basketId", "bid", "cartId"}

const buslogicMaxRequests = 200

// mineIntField returns the first integer value of any of the given JSON keys found
// in body (login responses carry the session's basket id under one of these names).
func mineIntField(body string, keys []string) (int, bool) {
	for _, k := range keys {
		re := regexp.MustCompile(`"` + regexp.QuoteMeta(k) + `"\s*:\s*"?(-?\d{1,9})`)
		if m := re.FindStringSubmatch(body); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// negEchoed reports whether the response body echoes the quantity field carrying a
// negative value (proof the negative was persisted, not silently dropped).
func negEchoed(body, qf string, neg int) bool {
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(qf) + `"\s*:\s*"?` + strconv.Itoa(neg))
	return re.MatchString(body)
}

// buildItemBody populates all candidate id field names (whichever the server reads
// gets a valid value) plus the chosen quantity field.
func buildItemBody(qf string, qty, productID, basketID int) []byte {
	b := map[string]any{qf: qty}
	for _, f := range productIDFields {
		b[f] = productID
	}
	for _, f := range basketIDFields {
		b[f] = basketID
	}
	raw, _ := json.Marshal(b)
	return raw
}

func (t *ToolSet) buslogicVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Base URL of the target, e.g. http://host:3000. The verifier self-registers a throwaway account and checks whether a basket/cart item accepts a negative quantity; no path or credentials needed.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE the negative-quantity business-logic flaw (a basket/cart accepting a quantity below its valid domain). It self-provisions a session, sends a positive baseline to prove the request shape works, then the same request with a negative quantity, and confirms only when the negative is accepted (2xx) and echoed back (persisted). Use this instead of guessing from a 200: a 200 that rejects or ignores the value is not a flaw. Pass the base URL."
	return readTool("buslogic_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(in, &a)
		raw := strings.TrimSpace(a.URL)
		if raw == "" {
			return actool.Errorf("url is required: pass the target base URL, e.g. http://host:3000"), nil
		}
		base, err := url.Parse(raw)
		if err != nil || base.Host == "" {
			return actool.Errorf("buslogic_verify needs an absolute URL (scheme://host[:port]), got: " + clipXSS(raw, 120)), nil
		}
		root := base.Scheme + "://" + base.Host
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		budget := buslogicMaxRequests

		sess, ok := provisionSession(runCtx, client, root, "q", &budget)
		if !ok {
			return actool.Text(
				"No negative-quantity flaw confirmed: could not self-provision an authenticated session (register+login " +
					"sweep did not yield a token), so the oracle could not run. record_fact the negative (inferred); do NOT " +
					"report_finding."), nil
		}
		// Basket id candidates: mined from the login body, plus a couple of defaults.
		bidCandidates := []int{1}
		if bid, found := mineIntField(sess.loginBody, basketIDFields); found && bid > 0 {
			bidCandidates = append([]int{bid}, bidCandidates...)
		}

		baselineSeen := false
		// Baseline and negative MUST target DISTINCT products: a cart with a unique
		// (basket, product) constraint (e.g. Juice Shop) rejects re-adding the same
		// product with a 500, which would mask the flaw. Each pair is {baselineProduct,
		// negativeProduct}; low ids that exist on a typical catalog.
		for _, path := range basketItemPaths {
			for _, qf := range quantityFields {
				for _, pair := range [][2]int{{1, 2}, {3, 4}} {
					for _, bid := range bidCandidates {
						if runCtx.Err() != nil || budget <= 0 {
							goto done
						}
						budget--
						st1, _, okb := bearerReq(runCtx, client, http.MethodPost, root+path, sess.token, buildItemBody(qf, 1, pair[0], bid))
						if !okb || st1 < 200 || st1 >= 300 {
							continue // request shape not accepted here; skip (honest)
						}
						baselineSeen = true
						// Baseline works: now submit a negative quantity for a DIFFERENT product.
						budget--
						stN, bodyN, okn := bearerReq(runCtx, client, http.MethodPost, root+path, sess.token, buildItemBody(qf, -1, pair[1], bid))
						if okn && stN >= 200 && stN < 300 && negEchoed(bodyN, qf, -1) {
							return actool.Text(fmt.Sprintf(
								"CONFIRMED negative-quantity business-logic flaw at %s (field %q): a positive baseline was "+
									"accepted, and a quantity of -1 was then accepted (HTTP %d) and persisted (echoed in the "+
									"response), so the server does not enforce the quantity's valid domain. report_finding "+
									"(business logic flaw / insecure design) with the baseline and the negative-quantity request "+
									"as reproduction. Do NOT record it as a negative.",
								path, qf, stN)), nil
						}
					}
				}
			}
		}
	done:
		tail := "none accepted a negative quantity that was persisted"
		if !baselineSeen {
			tail = "no endpoint accepted even a positive baseline, so the item-creation shape could not be satisfied generically"
		}
		return actool.Text(fmt.Sprintf(
			"No negative-quantity flaw confirmed: swept generic item-creation endpoints and quantity field names; %s. Note "+
				"this is not proof of absence if the real endpoint/shape differs from the generic wordlist. record_fact the "+
				"negative (inferred); do NOT report_finding.", tail)), nil
	})
}

// buslogicSummaries / intent: fire on the base URL alone. Text contains "business
// logic" and "negative quantity" so intentClass canonicalizes to "buslogic".
func buslogicSummaries(s Surface, _ int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	return []string{buslogicIntentSummary(s.Base)}
}

func buslogicIntentSummary(base string) string {
	return fmt.Sprintf(
		"Business logic check (negative quantity): call buslogic_verify with the base URL %s. It self-registers an account "+
			"and tests whether a basket/cart accepts a negative quantity (a positive baseline then a negative value). If "+
			"CONFIRMED, report_finding (business logic flaw) with the requests as reproduction. If not, record_fact the "+
			"negative (inferred) and do NOT report_finding.",
		base)
}
