package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"artemis/engine/agentcore"
	"artemis/engine/llm"
	"artemis/engine/permission"
	actool "artemis/engine/tool"
	"artemis/engine/transcript"
	"artemis/db"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	prov        llm.Provider
	model       string
	tx          *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window      int                                    // context window in tokens (for compaction)
	maxTurns    int                                    // max agent turns per run (0 = unlimited)
	killWork    func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork   func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr   string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch   WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir     string                                 // shared work dir (surfaced in prompt as artifact-output target)

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning to-dos (kept across wake-ups, written by you last round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Advance accordingly: dispatch an intent only for the next step whose [prerequisite steps are completed / the facts it depends on already exist]; use TodoWrite to update the list (mark steps already satisfied by a fact as completed). Do not re-dispatch steps already pending/in_progress in the list.")
	return b.String()
}

// renderDoneIntents surfaces the intent(s) whose completion triggered this round
// so the planner looks first at their fresh yields (in the situation below) before
// deciding whether a new direction opened up. Empty for non-completion wakes.
func renderDoneIntents(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("#%d", id)
	}
	return "\n\n[The just-completed intents that triggered this round]:" + strings.Join(parts, ", ")
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[This round's situation (graph_overview prefetched, equivalent to the return of calling that tool yourself; call node_detail/list_facts etc. as needed for details)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (section [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the artifact-output
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the PLANNER of an authorized penetration-testing system. You are woken on every change of the exploration graph. Each round: read the situation and DRIVE THE ENGAGEMENT FORWARD by dispatching work to the worker agents via add_intent, and by marking goals met via prove_goal only when proven.

Tools: graph_overview, list_goals, list_facts, list_findings (read state); add_intent (dispatch a worker on a concrete reconnaissance/exploitation direction); prove_goal (mark a goal met WITH evidence). You do NOT fetch or probe targets yourself: the workers do that.

Overall goal: {{.Goal}}

RULES (these override any other consideration):
1) STARTUP: if there are no worker facts yet (only the origin fact) and goals are open, you MUST immediately dispatch a few initial RECONNAISSANCE intents via add_intent (technology/version fingerprinting, endpoint and attack-surface enumeration, authentication analysis, input/parameter discovery). Reconnaissance is HOW the first facts are obtained: you do NOT need any prior fact to dispatch it.
2) ADVANCEMENT: once facts exist but goals are not yet proven, you MUST dispatch concrete testing intents on the DISCOVERED SURFACE, covering DISTINCT vulnerability classes (not just one). Where the surface allows, consider: injection (SQLi/NoSQL), XSS (reflected/DOM/stored), access control/IDOR, authentication & session (JWT weaknesses, weak password hashing), open redirect, mass-assignment, business-logic abuse (e.g. negative quantity/price), sensitive-data & configuration exposure (exposed admin/metrics/backup/key endpoints, directory listings, verbose error/stack traces), security misconfiguration (missing/weak security headers such as CSP), anti-automation (CAPTCHA bypass). Map each discovered endpoint/parameter to the classes that fit it.
3) CLOSURE: mark a goal met (prove_goal) ONLY with concrete evidence (a report_finding, or a verified fact that directly satisfies it).
4) You may emit 0 new intents ONLY IF (a) there are intents still running, OR (b) every open goal already has concrete evidence. In EVERY other case you MUST emit at least one add_intent. "Not enough information yet" is NEVER a reason to emit 0 intents: dispatch reconnaissance to obtain it.
5) BREADTH: keep SEVERAL mutually independent directions alive at once (different classes / different entry surfaces) so the engagement covers the whole attack surface, not one lead. Still avoid DUPLICATES: before add_intent, read graph_overview/list_facts/list_findings and do NOT dispatch a vector/endpoint/class already tested or already covered by a running/open intent. Pursue promising leads with follow-up / escalation intents too, but never leave whole classes of the surface untested.

OUTPUT LANGUAGE: write all content you produce (intents, notes, summaries) in English; keep technical terms and identifiers (payload, exploit, SQLi, URLs, parameters, code) in their original form.`

func plannerSystem(goal, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, Now: time.Now().Format("2006-01-02 15:04:05 MST")})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// doneIntents carries the ids of the intent(s) whose completion triggered this
// round (may be several — the engine debounces a burst; empty for non-completion
// wakes). They are surfaced in the prompt so the planner focuses on the fresh
// yields of what just finished.
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, doneIntents []int64, emit func(db.Activity)) (met bool, reason string, err error) {
	tsx := NewToolSet(ts, "planner")
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// Domain tools + the base default toolset (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash)
	base := append(tsx.PlannerTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// The key situation (just-completed intents + the prefetched full graph) goes into the
	// system prompt, not the user input: the system section is never compacted, so this
	// situation stays present through long rounds; it is fixed within the round and can also
	// hit the system cache. It lands after the instructions and before the deferred-tools
	// block (deferredSystem guarantees the block stays last).
	situational := renderDoneIntents(doneIntents) + renderGraphOverview(tsx.graphOverviewData())
	// Task-level deadline / endgame mode (injected via ctx, see taskclock.go). On the endgame
	// round, the task-timeout planner wrap-up text is injected directly into system as [this
	// round's operating instructions], so it only does the final goal judgment and produces no new intents.
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task endgame wrap-up (special instruction for this round, overriding the regular planning process above)]:" + resolveTaskTimeoutWrapup("planner")
	}
	system, boundary := deferredSystem(plannerSystem(goal, p.workDir)+situational, def)
	// The planner has no wall-clock budget of its own; when there is a deadline, clamp
	// MaxDuration to the remaining time so an in-flight planning round enters wrap-up when the
	// task hits its deadline (on timeout -> task-timeout text, on step count -> per-run text).
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // route through the recording proxy to leave a trace; load the proxy CA to verify the MITM-resigned HTTPS certificate
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a separate egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty = direct.
		EnableWebSearch:    p.webSearch.Enabled,
		WebSearchBackend:   p.webSearch.Backend,
		BraveSearchAPIKey:  p.webSearch.BraveKey,
		TavilySearchAPIKey: p.webSearch.TavilyKey,
		WebSearchProxy:     p.webSearch.Proxy,
		BashEnv:           proxyEnv(p.proxyAddr, p.proxyCACert), // Bash subcommands route through the proxy and trust its CA by default
		MaxTurns:          p.maxTurns,                           // 0 = unlimited (configurable in agent management)
		MaxDuration:       maxDur,                               // 0 = unlimited; with a deadline = time remaining until the deadline
		Compaction:        compactionConfig(p.window),
		// Planning to-dos shared across wake-ups: keep a serial chain alive across rounds (the session is new, the store is not).
		Todos: p.todoFor(ts.ID()),
		// On hitting [this round's] step budget -> the SDK runs a wrap-up: land the conclusions
		// already worked out this round (the add_intent calls to dispatch, the provable prove_goal
		// calls, recording a serial chain with TodoWrite), rather than stopping planning: the
		// planner will still be woken repeatedly afterwards.
		// When clamped (by the task deadline) it switches to PromptByReason (see wrapupSettlementForTask).
		Settlement: settle,
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// The situation (just-completed intents + full graph) has already been folded into the
	// system prompt above (compaction-resistant, resident for the whole round). The user input
	// here keeps only the instructions + the cross-wake-up to-dos (the todo is the model's own
	// planning scratchpad, regenerable, so the user input is fine for it).
	input := "The graph has changed, please plan the next step: read the situation in the system prompt above and judge the goals. **If this round has no uncovered new direction, just end directly (generating 0 intents is normal and common, especially right after dispatching intents while waiting for worker output). Never call goal_met just to \"end this round\": goal_met will [immediately end the whole task], so call it only when you have confirmed the goal is [genuinely met] (the target result obtained / the target vulnerability confirmed); if not met, mark them one by one with prove_goal, or end directly without calling anything.**" +
		renderPlannerTodos(opts.Todos.List())
	// When clamped by a deadline, add a hard ctx backstop (soft budget + grace) to stop a single stuck round from bypassing the turn-boundary soft timeout.
	runCtx := ctx
	if maxDur > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer cancel()
	}
	_, _, err = captureRun(runCtx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
