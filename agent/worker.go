package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"artemis/db"
	"artemis/engine/agentcore"
	"artemis/engine/harness"
	"artemis/engine/llm"
	"artemis/engine/memory"
	"artemis/engine/permission"
	actool "artemis/engine/tool"
	"artemis/engine/transcript"
)

// Worker is an LLM work agent (docs §4.4): it claims ONE intent, completes it
// with real tools (Bash: kali tooling through the recording proxy), writes the
// FACTS it found back into the graph, and stops. It does NOT generate new
// directions (that is the planner's job) and does NOT keep exploring toward the
// goal on its own. Multiple workers run concurrently as goroutines.
// WebSearchOpts is the web-search backend selection the server pushes into each
// agent (planner/worker/main). Enabled=false leaves the web_search tool off.
// Backend is "ddgs" (no key), "brave-free" (BraveKey required), or "tavily"
// (TavilyKey required). It maps directly onto agentcore.Options.
// Proxy is a dedicated egress proxy for the search request (http/https/socks5),
// independent of the traffic-recording MITM proxy — set it when the search endpoint
// is only reachable via a VPN/SOCKS proxy. Empty = direct.
type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string
}

type Worker struct {
	prov        llm.Provider
	model       string
	workDir     string
	proxyAddr   string
	proxyCACert string            // recording proxy's CA cert path (for WebFetch HTTPS verify)
	webSearch   WebSearchOpts     // web_search tool backend selection (off by default)
	mem         *memory.Store     // cross-engagement tradecraft memory (G4)
	tx          *transcript.Store // raw LLM conversation persistence (nil = off)
	window      int               // context window in tokens (for compaction)
	maxTurns    int               // max agent turns per run (0 = unlimited)
	// runTimeout is the wall-clock budget for the main exploration of one intent
	// (0 = unlimited). When it fires, the run is cut and a settlement round is
	// forced so already-identified facts get written back instead of being lost.
	runTimeout time.Duration
	// extraTools are host-provided tools (e.g. traffic query, oast) appended to
	// the worker's graph write-back tools.
	extraTools []actool.CoreTool
	// trafficResolver, if set, resolves a finding's reproduction steps to real
	// recorded traffic exchange ids at record time (host callback). nil = no linkage.
	trafficResolver func(taskID int64, repro json.RawMessage) json.RawMessage
	// redirectDecoys, if set, supplies allowlisted decoy URLs mined from the
	// target's own captured response bodies to the open-redirect verifier (host
	// callback). nil = verifier uses generic payloads only.
	redirectDecoys func(host string) []string
}

// SetRunTimeout configures the per-intent wall-clock budget for the main
// exploration (0 = unlimited). When it fires, the SDK settlement phase still runs
// so facts are never lost to a timeout. Safe to call before Execute.
func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

// settleHardGrace is how far past the soft wall-clock budget (runTimeout) the hard
// ctx deadline sits — a backstop for a hung turn; the soft budget handles the
// normal case at the turn boundary.
const settleHardGrace = 90 * time.Second

// settleWrapUpPrompt is injected by the SDK settlement phase when a worker hits its
// turn/time budget: stop probing, write back what was found, then end with a
// plain-text one-liner (which becomes this run's displayed result).
const settleWrapUpPrompt = "You are about to be terminated because the budget is exhausted. Do not run any more commands/probes. Proceed in order: (1) write back, one by one, everything you have already identified above but not yet written back: use insert_assets for new assets, record_fact for exploration conclusions/facts, report_finding for confirmed vulnerabilities; (2) **finally, in a single separate plain-text sentence**, summarize what you did and which key conclusions you reached (this sentence will be shown as the result of this run, so you must output it)."

// SetMemory enables cross-engagement tradecraft memory (RecallMemory/RecordMemory
// tools + auto-injection of relevant memories, docs §8 G4).
func (w *Worker) SetMemory(m *memory.Store) { w.mem = m }

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

// SetProxy configures the recording proxy address that workers route target
// traffic through, plus the CA cert path WebFetch trusts to verify HTTPS through
// that MITM proxy. Empty addr disables the hint.
func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for this worker (off by default).
func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

// SetTrafficResolver wires the record-time traffic linkage callback (host-provided).
func (w *Worker) SetTrafficResolver(fn func(taskID int64, repro json.RawMessage) json.RawMessage) {
	w.trafficResolver = fn
}

// SetRedirectDecoys wires the allowlisted-decoy sampler for the open-redirect
// verifier (host-provided, backed by traffic mined from the target's bodies).
func (w *Worker) SetRedirectDecoys(fn func(host string) []string) { w.redirectDecoys = fn }

// proxyEnv builds the Bash-subprocess env that routes child-command HTTP through
// the recording proxy and makes the common toolchain trust its MITM CA — so tools
// need no manual -x/--proxy/-k. Each ecosystem reads a different CA var (verified
// empirically): SSL_CERT_FILE→curl/urllib/Go/openssl, REQUESTS_CA_BUNDLE→python
// requests (it ignores SSL_CERT_FILE), CURL_CA_BUNDLE→curl, GIT_SSL_CAINFO→git,
// NODE_EXTRA_CA_CERTS→node; NODE_USE_ENV_PROXY makes Node 24+ honor the proxy vars.
// Empty proxyAddr → nil (direct, unchanged env).
func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"NODE_USE_ENV_PROXY=1", // Node 24+: honor HTTP(S)_PROXY in built-in fetch/http
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

// workerDefaultTmpl is the built-in EDITABLE body (section [A]) of the worker system
// prompt, seeded into agent_prompts. The trafficTool block and the artifactSpec
// are NOT here: they are code-owned and appended by workerSystem after rendering
// (sections [B]/[C]), so editing the DB body can never drop them.
const workerDefaultTmpl = `You are the EXECUTOR (worker) of an authorized penetration-testing system. You receive ONE intent (a single exploration/exploitation direction). Your ONLY job: carry out that intent by ACTIVELY TESTING the target, write the concrete security facts you discover back into the knowledge graph, then stop.

You are an attacker, NOT a describer. Do NOT summarize the website content or business. For your intent, actually DO the security work with your tools (shell/curl, browser):
- send real requests, using the Basic credentials from the task when required;
- probe parameters and endpoints with test payloads (SQLi, XSS, IDOR, SSRF and so on, according to your intent);
- test authentication/session handling, access control, file upload, and business logic;
- read the responses (status codes, errors, reflected input, timing, returned data) as evidence.

KNOWLEDGE BASE (consult it, do not improvise from memory): before you start testing a vulnerability class, and again before you conclude a vector is not exploitable, call search_knowledge with the class or technique as the query (for example "SQLi", "IDOR", "XSS", "JWT", "SSRF", "mass assignment", "success") to pull the exploitation playbook and the concrete success signature for that class. Use what it returns to choose the right endpoint/method and to judge whether a response is already a win.

ENDPOINT DISCOVERY (find the surface, do not guess or give up): before you conclude a vector is "not testable", "blocked", or that the SPA prevents it, call endpoint_discover with the target host to extract the real routes/endpoints from the JavaScript the app itself ships (it reveals paths you cannot guess, for example /rest/products/search or /redirect). Then TEST the discovered endpoints that match your intent with the correct method and payload. "Cannot be tested on this parameter", "blocked by SPA architecture" or "no endpoint found" is NOT an acceptable conclusion until endpoint_discover has returned and you have tried the relevant paths it lists.

XSS VERIFICATION (use the oracle, do not eyeball): to confirm or refute a reflected/DOM XSS, call xss_verify with the URL of the rendered page/route and the marker FUZZ at the injection point (for example /#/search?q=FUZZ). DOM XSS executes in the browser, so a <script> payload on a JSON API never proves it, and a JSON/HTTP response you read by hand cannot confirm it. xss_verify renders the page in a real headless browser, fires canonical non-<script> payloads, and tells you deterministically whether one executed. A confirmed execution is a report_finding; do not conclude "no XSS" from an unrendered response or from a <script> payload that did not fire.

ESCALATION (do not stop at the first signal): an error, a 401, a 500 "unexpected path", or a reflected input are NOT results by themselves. Push further before concluding: turn a SQL error into a UNION-based data extraction; turn an IDOR signal into actually retrieving another user's data; turn reflected input into confirmed script execution; turn a forged/weak token into an authenticated request that succeeds. Conclude the intent only when you have EITHER achieved exploitation OR genuinely exhausted realistic escalation for this vector.

SUCCESS RECOGNITION (read the response, do not assume failure): a response is a CONFIRMED exploit, so report_finding and not a negative fact, when it carries any of: an authentication/session token or a cookie for a principal you should not have; "status":"success" or a 2xx for an action that should have been denied; data belonging to another user/account/entity (an IDOR/BOLA win); unexpected database rows, a SQL/stack error, or a response that changes with vs without your payload. If you logged in with an injection and got back a token, THAT IS the bypass: confirm it, do not call it "only user info".
Never conclude "not vulnerable", "cannot test" or "blocked" from a 2xx you did not parse: an unexpected success is a SIGNAL, read it.
The target's REST/JSON API is reachable DIRECTLY with curl. A client-side SPA or framework (Angular/React/Vue) and a hash route like /#/login do NOT block direct API calls: if a request "returns the HTML page" you hit a UI route, not the API, so retry the real API path (/rest/..., /api/...) with the correct METHOD and JSON body. Do NOT record "the framework blocks direct API access" as a fact: it is a methodology error, not a property of the target.
A NEGATIVE result must carry the concrete blocking response (status + key body) as evidence. If you probed only once, mis-targeted the endpoint/method, or could not parse the response, mark it inferred and RETRY: do not declare the vector or class dead.

Record results with your tools:
- record_fact: a technical observation that CHANGES the assessment (a vulnerable parameter, an exposed endpoint/file/dir, an auth weakness) OR a clear NEGATIVE result for a vector you actually tested ("X not vulnerable"). Do NOT record routine noise as facts (a plain 404, a generic 500 "unexpected path", a 401 on an endpoint that simply requires auth). A negative/inconclusive result is ALWAYS a record_fact, NEVER a report_finding.
- report_finding: ONLY for a vulnerability you ACTUALLY exploited/confirmed in THIS run, with reproducible evidence (request/response or command output). A confirmed exploit MUST be a report_finding, not left as a fact. Never a finding from fingerprinting, guessing, or a "potential"/"cannot test" result.

Stay strictly within your single intent. Be persistent: if the first attempt is blocked (a payload filtered, a 404), try other encodings/paths/parameters before concluding. When you have genuinely exhausted this direction or confirmed a result, write it back and stop.

OUTPUT LANGUAGE: write all facts, findings and notes in English; keep technical terms, payloads, URLs, parameters and code in their original form.`

// workerTrafficBlock is section [B]: the traffic-tool note, code-injected only when
// traffic capture is on (proxyAddr set). Not stored, not editable.
func workerTrafficBlock(proxyAddr string) string {
	if proxyAddr == "" {
		return ""
	}
	return "\n\n**Traffic tools**:\n- traffic_search / traffic_get: all target traffic has been fully persisted by the recording proxy (local file tree data/traffic/<host>/<access path>/). To review responses and find already-visited resources, **query the traffic first, don't curl the same URL again**. traffic_search **must specify a host**, and by default returns only 3 extremely lightweight index entries (id/method/url/status/resp_len, no response body); raise limit explicitly if you need more; to see the verbatim content of one entry use traffic_get(id)."
}

// artifactSpec is section [C]: the code-owned, non-editable tail appended to every
// pentest agent's prompt — intermediate artifacts must land in the shared work
// dir, never /tmp. Guaranteed present regardless of how the DB body is edited.
func artifactSpec(workDir string) string {
	return "\n\n**Intermediate-artifact output convention**: scripts, payloads, captured response bodies, temporary data, and all other intermediate artifacts **must all be written to the shared working directory " + workDir + "** (this is the CWD shared by all agents; a relative path writes here, and you may also use this absolute path): **do not write to /tmp, do not use any other absolute path**."
}

// workerArtifactSubdir is the worker-only addendum to artifactSpec: put a run's
// artifacts under an i<intentID>/ subdir to avoid concurrent name collisions.
const workerArtifactSubdir = "To avoid name collisions with other works, put this run's artifacts under the subdirectory i<intent id>/ (e.g. i123/exploit.py)."

func workerSystem(proxyAddr, workDir string) string {
	body := renderSystem("worker", workerDefaultTmpl, WorkerVars{ProxyAddr: proxyAddr})
	return body + workerTrafficBlock(proxyAddr) + artifactSpec(workDir) + workerArtifactSubdir
}

// renderIntentTask formats the claimed intent for the worker's SYSTEM prompt: the
// intent is the worker's whole job, so — like the planner's situational block — it
// belongs in system, where compaction can never drop it during a long run.
func renderIntentTask(intent *db.Node) string {
	return fmt.Sprintf("\n\n[The intent you were assigned (your only task this time: do only this one, produce only facts, stop when done)]:\n%s\nIntent id: %d (pass it when writing back via record_fact / report_finding)", string(intent.Payload), intent.ID)
}

// renderWorkerGraphOverview folds the global situational snapshot into the worker's
// SYSTEM prompt for AWARENESS ONLY. The framing is deliberately strong: the overview
// must NOT widen the worker's job — it still does only its assigned intent. Its sole
// purpose is letting the worker read context (existing facts/assets/hints)
// so it avoids redundant work and doesn't re-derive what others already found.
func renderWorkerGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back silently: the worker just won't have the global context
	}
	return "\n\n[Global exploration situation (only to inform you of the big picture, not your task list)]:\n" +
		"Below is the current exploration overview of the entire task. Its **sole purpose** for you is to let you understand the global dynamics, reuse existing conclusions, and avoid duplicating what others have already done.\n" +
		"**It never widens your responsibility boundary**: you still do only the one intent you were assigned above. Even if you see other open intents / uncovered points / other attackable directions here, **never act on them yourself**: those are the business of other workers, scheduled by the planner. If you find a relevant new lead, at most write it into a fact so the planner knows; do not pursue it yourself.\n" +
		string(b)
}

// Execute runs one intent. hooks (the per-task Guard) gates every tool call; may
// be nil. emit, if non-nil, receives one ActivityRecord per execution step.
// Returns the terminal reason (so the engine can distinguish completed vs
// max_turns) and a per-kind breakdown of what was written back (so an intent that
// explored but persisted nothing isn't mistaken for done, and the engine can log
// facts/assets/findings separately instead of lumping them under "facts").
func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	tsx.SetTaskID(taskID)
	tsx.SetTrafficResolver(w.trafficResolver)
	tsx.SetRedirectDecoys(w.redirectDecoys)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID) // assets this worker discovers anchor to its intent → visible to the task
	tsx.SetEnrich(enr)          // async DNS/HTTP auto-completion for assets this worker writes
	// base = built-in worker tools ∪ host tools (traffic) ∪ default tools (incl. Bash);
	// then augment with the agent's visible skills/MCP. During the SDK settlement
	// phase, Bash is hidden via Settlement.DisabledTools (no local gating needed).
	base := append(tsx.WorkerTools(), w.extraTools...)
	base = append(base, actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	// The intent is the worker's whole task, so it goes into the system prompt
	// (compaction-resistant, resident for the whole round), not the user input, matching
	// how the planner puts its key situation in system. It lands after the instructions and
	// before the deferred block. The global situation (graphOverviewData) is carried too, but
	// only for awareness of the big picture; the intent goes last, in the most prominent spot.
	overview := renderWorkerGraphOverview(tsx.graphOverviewData())
	system, boundary := deferredSystem(workerSystem(w.proxyAddr, w.workDir)+overview+renderIntentTask(intent), def)
	// The task-level deadline (injected via ctx) clamps this run's wall-clock budget and decides the wrap-up text (see taskclock.go).
	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		// WebFetch routes through the recording proxy, so its HTTP is traced just like curl's;
		// loading the proxy CA lets the MITM-resigned HTTPS certificate [pass verification
		// normally] (rather than disabling verification). Empty proxy = direct.
		EnableWebFetch: true,
		WebFetchProxy:  w.proxyAddr,
		WebFetchCACert: w.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a separate egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty = direct.
		EnableWebSearch:    w.webSearch.Enabled,
		WebSearchBackend:   w.webSearch.Backend,
		BraveSearchAPIKey:  w.webSearch.BraveKey,
		TavilySearchAPIKey: w.webSearch.TavilyKey,
		WebSearchProxy:     w.webSearch.Proxy,
		// Bash subcommands' HTTP routes through the recording proxy and trusts its CA by default (tools need no -x/-k).
		BashEnv:    proxyEnv(w.proxyAddr, w.proxyCACert),
		WorkingDir: w.workDir,
		MaxTurns:   w.maxTurns, // 0 = unlimited (configurable in agent management)
		// Wall-clock budget, checked at the turn boundary, never interrupting mid-way; 0 = unlimited.
		// With a task-level deadline, clamp it to min(own budget, time remaining until deadline), so
		// this run enters wrap-up naturally when the task hits its deadline (see taskclock.go).
		MaxDuration: maxDur,
		// On hitting the budget (turns OR duration) -> the SDK runs one wrap-up round (hiding Bash),
		// writing back what was identified to avoid a botched ending.
		// When clamped (by the task deadline) it uses PromptByReason: on timeout = task hit its
		// deadline -> task-timeout text; on step count = the steps within the clamped window ran out
		// first -> fall back to the per-run text. When not clamped it stays pure per-run.
		Settlement: settle,
		// large tool output spills to cmd-output/ with a head + pointer (SDK tool.Capture);
		// full output preserved on disk. The truncation cap uses the SDK default (30000 characters).
		ToolOutputDir: filepath.Join(w.workDir, "cmd-output"),
		Compaction:    compactionConfig(w.window), // long tool-heavy runs stay within the window
		Todos:         actool.NewTodoStore(),      // session-scoped temporary to-dos (TodoWrite), purely for planning, discarded on exit
	}
	if hooks != nil { // typed-nil guard: only set when concrete (avoids harness panic)
		opts.Hooks = hooks
	}
	if w.mem != nil {
		opts.Memory = &agentcore.MemoryOptions{Store: w.mem, AutoInject: true, MaxInject: 3}
	}
	if w.tx != nil { // persist raw LLM conversation; one file per worked intent
		opts.Transcript = w.tx
		opts.SessionID = fmt.Sprintf("exp%d-worker-i%d", ts.ID(), intent.ID)
	}
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	// The intent is already in system. The user input carries only the start instruction.
	input := "Begin executing the intent in the system prompt: do only it, produce only facts, stop when done."

	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)

	// Budgets + settlement are owned by the SDK (MaxTurns/MaxDuration + Settlement):
	// on hit it runs a wrap-up turn and finishes with ReasonMaxTurns/ReasonTimeout.
	// We only add a HARD ctx backstop past the soft wall-clock budget, for the rare
	// case a single turn hangs so the turn-boundary check never runs — the soft
	// budget handles the normal case gracefully (no mid-stream abort). pause /
	// planner kill cancel ctx; the engine distinguishes those and re-queues/stops.
	// backstop uses the EFFECTIVE (deadline-clamped) budget, not the raw runTimeout,
	// so a task-timeout run's hard deadline sits just past its clamped soft budget.
	runCtx := ctx
	if maxDur > 0 {
		var runCancel context.CancelFunc
		runCtx, runCancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer runCancel()
	}
	_, reason, err := captureRunSession(runCtx, s, input, emitWrap)
	return reason, tsx.Writes(), err
}
