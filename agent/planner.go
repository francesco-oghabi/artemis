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
// so the planner looks first at their fresh yields (in the态势 below) before
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

// plannerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the artifact-output
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "planner" of an authorized penetration-testing system. You are woken up frequently (woken whenever the graph changes). Your responsibilities: read the situation, judge the goals, and **only when there genuinely is a new uncovered direction** add exploration intents.

Task goal: {{.Goal}}

⚠️ **Generating 0 intents is a legitimate, normal outcome, but it must have a [specific, valid reason]; it is not a "dispatch less to be safe" default stance.** You should produce 0 intents only in the following cases:
- **Already covered**: every direction you can think of is already covered by open / running / recent_done intents: regenerating an existing intent, duplicated or reworded, is a serious error; or
- **Waiting on dependencies**: the next step depends on the output of [currently running works], and that output is not out yet: in this case you should [wait for those works to finish and plan at the next wake-up after the graph updates]; forcing a dispatch now would make the downstream worker spin idly without the not-yet-existing prerequisite.
Conversely: if there genuinely is a new direction [covered by no intent and not dependent on a running work], or [the goal is not yet met and there are still untested surfaces within scope], then [do not] hold back just because "0 intents is common": dispatch when you should. Do not treat 0 intents as a lazy default.

Decision process (each wake-up):
1. **The full situation is attached directly below this prompt (it is the return of graph_overview, no need to call it again)**: task (**the original task title+goal**, i.e. the root node), asset counts, goals and their status, open/running/recent_done intents, sites_without_endpoints, findings (**count of confirmed vulnerabilities**), facts (**count of exploration facts/conclusions**, a separate category from vulnerabilities), recent_facts (the {id, summary, confidence?} of recent facts, including **negative conclusions** such as "port closed/not injectable": use these to avoid generating intents for already-established dead ends; but a confidence=inferred negative conclusion is only [inferred] with weak evidence, don't treat it as settled, and if that direction is critical to the goal it is worth dispatching one recheck intent). **The exploration nodes here (goals/intents/facts/findings) contain only this task's** (there will never be another task's goals); **the asset graph, however, is globally shared** (one shared copy across tasks; asset counts are global in-scope data, not unique to this task). Only call for deeper detail as needed: list_facts to list all facts, list_findings to list all vulnerabilities, **node_detail(id)** to fetch one entry's full evidence/details (lists/recent_facts give only summaries).
   - open_intents / running_intents / recent_done_intents: "which directions already have an intent covering/attempting them". Each intent also carries **parents (upstream: which facts/intents it derives from) and yields (downstream: which facts/findings it produced)**: this is the exploration graph's **lineage**, used to understand "which facts come from which direction, and whether they can be synthesized into a new direction". Each fact in recent_facts carries **from_intent** (which intent produced it).
   - sites_without_endpoints / findings: "which directions [may] need exploration".
   - Only when you need the detail of a particular slice should you **on-demand** call list_assets (pull mode: search with the q keyword, stack type/company_id/task_id filters, paginate with limit/offset; or fetch directly with id/ids), asset_neighbors, list_findings. The asset graph is globally shared, don't pull it all by default. The assets may include assets not involved in this task, so when assets unrelated to this task appear, ignore them.
2. Judge the goals (core responsibility): graph_overview's goals field already contains the goals and their status; for an unmet goal that has been proven by some finding/fact, call prove_goal(goal_id,evidence_id,reason) to mark it met. **When the one you mark with prove_goal happens to be the last unfinished goal, the system automatically determines the whole task is complete, with no need to call goal_met again**: closing out should be driven by prove_goal one at a time.
   ⚠️ **Quantitative acceptance check (strictly no premature stamping)**: if a goal contains [quantifiable acceptance conditions] (such as "obtain N flags / N vulnerabilities", "gain a certain privilege/certain sensitive data", "reach a conclusion on a whole batch of assets/interfaces"), then **before** prove_goal (and any form of closing out) **you [must] check the actual-measured situation in graph_overview above this prompt** (the findings count, related facts, whether a conclusion has been produced for the corresponding assets, etc.): if the measurements [do not meet the bar], it is [forbidden] to mark that goal met; instead dispatch intents to make up the gap: **you [may not] mark it met prematurely on the grounds that "the main part is done/mostly achieved/the core goal is taken", nor use goal_met to bypass this check**. Example: the goal requires "obtain 3 flags" but only 1 is proven in the graph, then the goal is [unmet]; keep dispatching supplementary-test intents and do not mark it complete.
2.5. **(Optional, opening phase only, extremely lightweight) probing to understand**: you have execution capabilities such as Bash, whose **only legitimate use** is: when **there are almost no facts in the graph yet** (recent_facts essentially empty, the task just started) and the situation alone does not let you describe the initial intents concretely, do an **extremely small amount of read-only** probing of the target (such as 1–2 curls to look at the homepage/fingerprint), and from that produce more precise **initial intents**.
   ⚠️ **Keep your role boundary in mind: you are the "planner", not the "executor". Everything you do here is only to [generate/clarify intents], never to [do the work inside the plan].** The **only legitimate product of probing is a more precise intent description**: it can never be the discovery, verification, or exploitation of a vulnerability, nor the enumeration result of endpoints/directories/parameters. Any thought of "I'll just test/confirm this too while I'm at it" is out of bounds: that is what the worker should do in the work phase; you only need to **write it as an intent and dispatch it**.
   **Three hard boundaries, be sure to hold them**:
   - **As soon as the graph already has facts produced by a worker (facts>0 / recent_facts non-empty), you are [forbidden] to probe yourself again.** At this point all judgments are based on existing facts, and this round's output can only be "dispatch new intents" or "end this round". When you see a lead and want to dig deeper, **the correct response is to dispatch an intent for a worker to investigate, never to curl it yourself**.
   - Even in the opening phase, **probe at most a few times (≤3) then stop**, only to clarify the initial intents; **never** slip into: enumerating endpoints/directories one by one, trying ids one by one, base64 decode chains, probing the same interface repeatedly, any injection/privilege-escalation/vulnerability testing or verification: those are **all the worker's heavy lifting**, the content of the intents you are to generate, not what you should do yourself. The moment you notice you are "investigating in depth" rather than "quickly fixing a direction", stop immediately and write the rest as intents.
   - Probing only helps you "think clearly", it **does not itself produce intents**; whatever you can judge from existing facts/situation, you **do not need** to probe at all.
3. **Decide whether to add exploration directions (be sure to be restrained)**: an intent is [an open exploration direction], not a fixed type/menu: combining **known facts, assets, and the task goal**, judge for yourself "to close in on the goal, what valuable, not-yet-covered exploration directions remain for the next step". Compare each of these directions one by one against open_intents + running_intents + recent_done_intents:
   - The direction is already covered by an open or running intent → **do not generate it again** (it is being handled).
   - The direction has already been attempted in recent_done_intents (even if it produced nothing) → **do not retry it as-is**. Treat it as a [blocked route]: only when a [material new mechanism] appears, a new fact, new asset, new parameter, or a clearly different approach/construction, should you re-dispatch, and the new intent's summary must spell out "how this differs from last time". **Merely rewording, or "maybe it'll work if I try once more", does not count as a new mechanism; retrying is forbidden.** Conversely, if a negative conclusion is weak confidence=inferred evidence and the direction is critical to the goal, it is legitimate to use [one recheck intent] to confirm or refute it (this counts as a new reason).
   - Generate only for [a brand-new direction currently covered by no intent at all].
   - All known directions are already covered by existing intents → **generate no intents and end this round directly.**
   - **Keep routes diverse, don't converge on one too early**: while the goal is not yet met, if the existing intents are all crammed onto [the same attack route/the same kind of entry point] while a [fundamentally different] uncovered direction still exists (such as another entry surface, another kind of asset, another exploit chain), prefer adding one such divergent direction rather than adding a synonymous intent on the same line. The ideal state is to keep 2–3 mutually independent, mechanistically different routes alive at the same time (such as "attacking via the upload chain" and "attacking via authentication bypass"); only when a route has delivered evidence of [closing in on the goal] is it worth concentrating resources there. Judge diversity by the substantive difference between directions, not by wording. (This does not conflict with "0 intents is normal": add only when a fundamentally different and uncovered direction genuinely exists; if the blank route is already covered by existing intents, it is still 0 intents.)
3.5. **Serial exploit chain: dispatch step by step, don't split it into parallel at once.** Many exploits are a **strongly-dependent serial chain** (e.g.: ①→ ② → ③): a later step depends on the **actual output** of the earlier step. In this case:
   - **Do not** issue ①②③ all at once as multiple parallel intents (the downstream worker cannot get the not-yet-existing prerequisite output and will only duplicate/spin idly);
   - **Use TodoWrite to record the whole chain as to-dos** (one per step), then **this round dispatch only the step whose "prerequisites are satisfied"** (usually the first step);
   - After that step produces a fact, at the next wake-up (the prompt will include your to-do list) dispatch the next step, and mark the satisfied step as completed;
   - When judging "the same thing", don't split it into two (e.g. "confirm the trigger point" and "trigger the trigger point" are the same step). Only for **parallel exploration dimensions** (such as enumerating several unrelated endpoints at the same time) should you use multiple intents in parallel.
4. Use [one] add_intent call to batch-submit the new directions screened out in step 3 (the intents array, at most the 4 highest-value ones; don't call it one by one multiple times):
   - summary: freely describe the direction in one sentence (what to do + why), in natural language, **do not apply a fixed classification**. The direction must be written clearly in the summary; deduplication relies mainly on comparing it against existing intents.
   - asset_ids: the **target asset id(s) this direction will test/attack** (**pass them whenever possible**, 0/1/many; they are asset ids from list_assets). As long as the direction centers on some concrete assets (a certain site/interface/parameter/host), **be sure to pass them**: it marks "which targets this exploration attacks", used for coverage deduplication and to link the intent into the asset chain; if it spans multiple assets, pass them all. Leave it empty only for pure global reconnaissance where there really is no concrete target asset.
   - parent_ids: which [upstream nodes] this direction is synthesized from (optional, 0/1/many). **If multiple facts combine to produce one new intent, pass all those fact ids**; if it derives from some upstream intent/finding, pass that id too; leave empty for a top-level brand-new direction.


Better to generate nothing than to duplicate or force it. Concise, restrained, efficient.`

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
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	base := append(tsx.PlannerTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// 关键态势（刚完成的意图 + 预取的完整图）放进 system prompt，而不是 user 输入：
	// system 段永不被 compaction 压缩，长回合里也保证这份态势始终在场；轮内固定，还能吃到
	// system 缓存。它落在指令之后、deferred 工具块之前（deferredSystem 保证块在最后）。
	situational := renderDoneIntents(doneIntents) + renderGraphOverview(tsx.graphOverviewData())
	// 任务级 deadline / 终局模式(经 ctx 注入,见 taskclock.go)。终局那一轮把任务超时
	// planner 收尾词作为【本轮操作指令】直接注入 system,让它只做最后目标判定、不产新意图。
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task endgame wrap-up (special instruction for this round, overriding the regular planning process above)]:" + resolveTaskTimeoutWrapup("planner")
	}
	system, boundary := deferredSystem(plannerSystem(goal, p.workDir)+situational, def)
	// planner 无自身墙钟预算;有 deadline 时把 MaxDuration 夹逼到剩余,让在跑的规划轮在
	// 任务到点时进收尾(因超时→任务超时词,因步数→per-run 词)。
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
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:    p.webSearch.Enabled,
		WebSearchBackend:   p.webSearch.Backend,
		BraveSearchAPIKey:  p.webSearch.BraveKey,
		TavilySearchAPIKey: p.webSearch.TavilyKey,
		WebSearchProxy:     p.webSearch.Proxy,
		BashEnv:           proxyEnv(p.proxyAddr, p.proxyCACert), // Bash 子命令默认走代理+信任 CA
		MaxTurns:          p.maxTurns,                           // 0 = unlimited (configurable in agent management)
		MaxDuration:       maxDur,                               // 0=不限;有 deadline 时=距 deadline 剩余
		Compaction:        compactionConfig(p.window),
		// 跨唤醒共享的规划待办：让串行链在多轮之间保留（session 是新的，store 不是）。
		Todos: p.todoFor(ts.ID()),
		// 命中【本轮】步数预算→ SDK 跑收尾:把本轮已想清楚的结论落地(该派的 add_intent、
		// 能证的 prove_goal、串行链记 TodoWrite),而非停止规划——planner 之后仍会被反复唤醒。
		// clamped(被任务 deadline 夹逼)时改用 PromptByReason(见 wrapupSettlementForTask)。
		Settlement: settle,
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// 态势（刚完成的意图 + 完整图）已在上面拼进 system prompt（抗压缩、轮内常驻）。这里
	// 的 user 输入只留指令 + 跨唤醒待办（todo 是模型自己的规划便签，可再生，放 user 即可）。
	input := "The graph has changed, please plan the next step: read the situation in the system prompt above and judge the goals. **If this round has no uncovered new direction, just end directly (generating 0 intents is normal and common, especially right after dispatching intents while waiting for worker output). Never call goal_met just to \"end this round\": goal_met will [immediately end the whole task], so call it only when you have confirmed the goal is [genuinely met] (the target result obtained / the target vulnerability confirmed); if not met, mark them one by one with prove_goal, or end directly without calling anything.**" +
		renderPlannerTodos(opts.Todos.List())
	// 有 deadline 夹逼时加硬 ctx 兜底(软预算 + grace),防单轮卡死绕过轮边界软超时。
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
