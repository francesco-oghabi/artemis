package traffic

import "testing"

// TestExtractEndpoints checks the R2b endpoint extraction against the exact
// shapes seen in the Juice Shop bundle that the field run (task 47) missed:
// a template-literal with interpolation (`${host}/rest/products/search?q=`),
// a relative href URL with a query (`./redirect?to=...`), an Angular route
// declaration (path:"redirect"-style) and plain quoted paths. It also asserts
// that static assets and numeric noise are filtered out.
func TestExtractEndpoints(t *testing.T) {
	js := "" +
		"this.http.get(`${this.hostServer}/rest/products/search?q=${t}`).pipe();" +
		"[`href`,`./redirect?to=https://blockchain.info/address/1A`];" +
		"this.router.navigate([`/login`],{queryParams:{redirectUrl:`/basket`}});" +
		"{path:\"administration\",component:X},{path:'score-board',component:Y};" +
		"const a='/rest/user/whoami';const b=\"/api/Feedbacks\";" +
		"import(`./assets/i18n/en.json`);src=`/main.js`;u=`./2`;"

	set := make(map[string]struct{})
	extractEndpoints(js, set)

	mustHave := []string{
		"/rest/products/search", // template-literal interpolation
		"/redirect",             // relative href with query
		"/login",                // quoted absolute path
		"/basket",               // quoted absolute path
		"/administration",       // angular route (double-quoted)
		"/score-board",          // angular route (single-quoted)
		"/rest/user/whoami",     // quoted rest path
		"/api/Feedbacks",        // quoted api path
	}
	for _, e := range mustHave {
		if _, ok := set[e]; !ok {
			t.Errorf("missing expected endpoint %q (got %v)", e, keys(set))
		}
	}

	mustNot := []string{
		"/assets/i18n/en.json", // .json asset filtered
		"/main.js",             // .js asset filtered
		"/2",                   // numeric-only first segment filtered
	}
	for _, e := range mustNot {
		if _, ok := set[e]; ok {
			t.Errorf("unexpected noise endpoint %q should have been filtered", e)
		}
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
