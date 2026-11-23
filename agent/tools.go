package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	acperm "artemis/engine/permission"
	actool "artemis/engine/tool"
	"artemis/db"
	"artemis/knowledge"
)

// compactIntents distills intents to {id, summary, state, asset_ids, parents,
// yields} so the planner sees both the direction and its LINEAGE — parents (the
// upstream nodes it derived from: facts/intents/findings) and yields (the facts/
// findings it produced) — without pulling full payloads. parentsOf/yieldsOf are
// built from the exploration edges in graph_overview.
func compactIntents(ns []*db.Node, parentsOf, yieldsOf map[int64][]int64) []map[string]any {
	out := make([]map[string]any, 0, len(ns))
	for _, n := range ns {
		var p map[string]any
		_ = json.Unmarshal(n.Payload, &p)
		m := map[string]any{"id": n.ID, "summary": p["summary"], "state": n.State}
		// asset_ids is the structured "which assets this direction covers" signal for
		// dedup; fall back to legacy payload keys (target_ids plural, then target_id
		// single) so intents stored before the rename still surface their anchors.
		if tg, ok := p["asset_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_id"]; ok && tg != nil && tg != "" {
			m["asset_ids"] = []any{tg}
		}
		if ps := parentsOf[n.ID]; len(ps) > 0 {
			m["parents"] = ps // 上游：本意图派生自哪些节点（多个事实可共同产生一个意图）
		}
		if ys := yieldsOf[n.ID]; len(ys) > 0 {
			m["yields"] = ys // 下游：本意图产生了哪些事实/发现
		}
		out = append(out, m)
	}
	return out
}

// ToolSet exposes the PG-backed dual graph (asset + exploration) to an LLM agent.
// One ToolSet is created per planner/worker run; per-run signals live here.
type ToolSet struct {
	as     *db.AssetStore   // asset store (optional; nil = asset tools not available)
	cs     *db.CompanyStore // company store (optional)
	ts     *db.ExplorationStore
	worker string
	taskID int64 // PG tasks.id; 0 when unknown (tests / orchestrator cross-task reads)
	// ownerNode is the exploration node that writes attach to: assets this run
	// touches get anchored to it as lineage/provenance (NOT visibility — the asset
	// graph is global and shared). Worker = its claimed intent; planner = begin root.
	ownerNode int64
	GoalMet   bool
	Reason    string
	writes    WriteCounts
	// redundantFacts counts CONSECUTIVE record_fact calls on this intent that added
	// nothing new (every item deduped to an existing fact). A ToolSet is built fresh
	// per intent (Worker.Execute → NewToolSet), so this is naturally per-intent and
	// resets with each intent. A weak worker re-records the same conclusion instead
	// of finishing; a few no-progress calls in a row mean it is spinning, so
	// record_fact ends the run cleanly (see noProgressFactStop).
	redundantFacts int
	// killWork, if set, terminates a running work by intent id (engine callback,
	// wired by the planner). nil = the kill_work tool reports unavailable.
	killWork func(intentID int64) error
	// steerWork, if set, queues a mid-run course-correction for the work running an
	// intent id (engine callback, wired by the planner): the worker injects it before
	// its next tool call and re-plans, without being killed. nil = tool unavailable.
	steerWork func(intentID int64, msg string) error
	// enrich, if set, receives async auto-completion triggers (DNS resolve for a
	// domain, HTTP probe for a site). nil = no engine enrichment.
	enrich EnrichTrigger
	// notify, if set, wakes the task's planner after a graph change that should be
	// re-planned promptly (currently: a new hint). nil = no wake (the hint is still
	// stored and read on the next round triggered by other events). debounced.
	notify func()
	// kb, if set, enables search_knowledge / list_knowledge_categories over the
	// two-layer knowledge base (global + this task). nil = tools report "not enabled".
	kb *knowledge.Service
	// resolveTraffic, if set, resolves a finding's reproduction steps to real recorded
	// traffic exchange ids AT RECORD TIME (so the finding's steps carry jump-to-traffic
	// links without view-time guessing). Input = the raw reproduction JSON; returns the
	// same shape with each step's exchange_id filled where it matched. nil = skip.
	resolveTraffic func(taskID int64, repro json.RawMessage) json.RawMessage
	// redirectDecoys, if set, returns candidate allowlisted decoy URLs mined from
	// the target host's own captured response bodies (host-provided, backed by
	// traffic.DiscoverExternalURLs). The open-redirect verifier embeds them to
	// defeat "the target must contain an allowlisted URL" filters. nil = the
	// verifier falls back to its generic payloads only (unprotected redirects).
	redirectDecoys func(host string) []string
}

// SetNotify wires the planner-wake callback (see ToolSet.notify). Set by callers
// that hold the task handle (main-agent chat, cross-task orchestration).
func (t *ToolSet) SetNotify(fn func()) { t.notify = fn }

// EnrichTrigger is the enrichment engine seen from the tool layer (see package
// enrich). Kept as an interface here to avoid coupling agent → enrich.
type EnrichTrigger interface {
	ResolveDomain(id int64, host string)
	ProbeSite(id int64, url string)
}

// WriteCounts breaks down what a worker persisted this run, by node kind, so the
// engine can log an accurate "wrote back" summary instead of lumping assets and
// findings under "facts" (record_fact → Facts, insert_assets → Assets,
// report_finding → Findings; each element of a batch counts once).
type WriteCounts struct {
	Facts    int
	Assets   int
	Findings int
}

// Total is every node persisted this run, regardless of kind — the
// "explored but persisted nothing" signal (Total == 0).
func (w WriteCounts) Total() int { return w.Facts + w.Assets + w.Findings }

// String renders the per-kind breakdown for logs, e.g. "事实1 资产25 漏洞0".
func (w WriteCounts) String() string {
	return fmt.Sprintf("facts %d assets %d vulns %d", w.Facts, w.Assets, w.Findings)
}

// Writes reports what this run wrote back, split by node kind (so the engine can
// tell "explored but persisted nothing" apart from a completed intent, and log an
// honest breakdown instead of calling assets/findings "facts").
func (t *ToolSet) Writes() WriteCounts { return t.writes }

func NewToolSet(ts *db.ExplorationStore, worker string) *ToolSet {
	t := &ToolSet{ts: ts, worker: worker}
	if ts != nil { // auto-wire the knowledge base off the store's DB handle
		t.kb = knowledge.NewService(ts.DB())
	}
	return t
}

// SetTaskID sets the PG task id on this ToolSet so that report_finding can
// dual-write to the standalone findings table (which survives task deletion).
func (t *ToolSet) SetTaskID(id int64) { t.taskID = id }

// SetTrafficResolver wires the record-time traffic linkage callback (host-provided;
// nil = no linkage — reproduction steps are stored verbatim without exchange ids).
func (t *ToolSet) SetTrafficResolver(fn func(taskID int64, repro json.RawMessage) json.RawMessage) {
	t.resolveTraffic = fn
}

// Cross-task reuse: exported accessors returning the per-task tool logic bound to
// THIS ToolSet's store. Host-side orchestration tools build a ToolSet for an
// arbitrary task, then Call these — so cross-task reads/hint reuse the exact
// same logic as the in-task tools. (readTool ignores ToolContext, so Call(…,nil)
// is safe; add_hint is a writeTool but also doesn't deref the context here.)
func (t *ToolSet) GraphOverviewTool() actool.CoreTool      { return t.graphOverview() }
func (t *ToolSet) ListFindingsTool() actool.CoreTool       { return t.listFindings() }
func (t *ToolSet) GetWorkerTraceTool() actool.CoreTool     { return t.getWorkerTrace() }
func (t *ToolSet) ListWorkerTracesTool() actool.CoreTool   { return t.listWorkerTraces() }
func (t *ToolSet) SearchWorkerTracesTool() actool.CoreTool { return t.searchAllWorkerTraces() }
func (t *ToolSet) AddHintTool() actool.CoreTool            { return t.addHint() }

// SetEnrich wires the async enrichment engine (DNS/HTTP auto-completion).
func (t *ToolSet) SetEnrich(e EnrichTrigger) { t.enrich = e }

// SetRedirectDecoys wires the allowlisted-decoy sampler for the open-redirect
// verifier (host-provided, backed by traffic mined from the target's own
// response bodies). nil = the verifier uses only its generic bypass payloads.
func (t *ToolSet) SetRedirectDecoys(fn func(host string) []string) { t.redirectDecoys = fn }

// SetOwnerNode sets the exploration node that writes anchor to (worker: its
// intent node; planner/main: the begin root). Assets created/referenced while
// ownerNode is set are anchored to it as lineage (not visibility).
func (t *ToolSet) SetOwnerNode(id int64) { t.ownerNode = id }

// anchorOwner records a lineage edge from this run's owner node to an asset
// (no-op if unset). Provenance only — the asset graph is global and shared, so
// this no longer affects which assets a task can read.
func (t *ToolSet) anchorOwner(assetID int64) {
	if t.ownerNode > 0 && assetID > 0 {
		_ = t.ts.Anchor(t.ownerNode, assetID)
	}
}

// pid parses an id that may arrive as a JSON number or string ("" / 0 → 0).
func pid(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}
	return 0
}

// pidList parses a list of ids (number|string), dropping zeros/invalids.
func pidList(raw []json.RawMessage) []int64 {
	var out []int64
	for _, r := range raw {
		if v := pid(r); v > 0 {
			out = append(out, v)
		}
	}
	return out
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}
func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func intp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func idp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func readTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func writeTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// --- read tools (planner + worker) ---

func (t *ToolSet) graphOverview() actool.CoreTool {
	return readTool("graph_overview",
		"(exploration lineage graph) Distilled summary of the exploration situation: asset counts, sites with no endpoints, frontier, findings, hints (strategic hints from humans / the main agent, which must be incorporated when generating intents). Call this first when planning.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			return jsonResult(t.graphOverviewData())
		})
}

// graphOverviewData computes the distilled situational snapshot shared by the
// graph_overview tool and the planner's wake-up prompt (which pre-injects it so
// the model needn't spend a turn calling the tool — every plan round starts with
// an empty context and always needs this first).
func (t *ToolSet) graphOverviewData() map[string]any {
	{
		out := map[string]any{}
		// goals summary folded in so the planner needn't call list_goals each round.
		goals, _ := t.ts.ListByKind(db.KindGoal, 100)
		gsum := make([]map[string]any, 0, len(goals))
		for _, g := range goals {
			var p map[string]any
			_ = json.Unmarshal(g.Payload, &p)
			gsum = append(gsum, map[string]any{"id": g.ID, "state": g.State, "text": p["text"]})
		}
		out["goals"] = gsum
		// hints: 人类/主 agent 通过 add_hint 挂上图的战略提示；folded in so the
		// planner reads them every round when generating intents (否则只写不读).
		hints, _ := t.ts.ListByKind(db.KindHint, 50)
		hsum := make([]map[string]any, 0, len(hints))
		for _, h := range hints {
			var p map[string]any
			_ = json.Unmarshal(h.Payload, &p)
			hsum = append(hsum, map[string]any{"id": h.ID, "state": h.State, "text": p["text"]})
		}
		out["hints"] = hsum
		// lineage from the exploration edges: an intent's parents (what it
		// derived_from — possibly several facts combined) and its yields (the
		// facts/findings it produced). factFrom maps a fact → the intent that
		// produced it. This is the relationship layer the flat lists lacked.
		edges, _ := t.ts.Edges(5000)
		parentsOf := map[int64][]int64{}
		yieldsOf := map[int64][]int64{}
		factFrom := map[int64]int64{}
		for _, e := range edges {
			switch e.Rel {
			case db.RelDerivedFrom, db.RelSpawns: // upstream: derived_from (fact/finding/intent→intent) or spawns (origin fact→goal, legacy begin→intent)
				parentsOf[e.To] = append(parentsOf[e.To], e.From)
			case db.RelYields: // intent --yields--> fact/finding
				yieldsOf[e.From] = append(yieldsOf[e.From], e.To)
				factFrom[e.To] = e.From
			}
		}
		fr, _ := t.ts.Frontier(100)
		out["open_intents"] = compactIntents(fr, parentsOf, yieldsOf)
		all, _ := t.ts.ListByKind(db.KindIntent, 300)
		var running, recentDone []*db.Node
		for _, n := range all {
			switch n.State {
			case "running":
				running = append(running, n)
			case "done", "blocked", "exhausted":
				if len(recentDone) < 15 {
					recentDone = append(recentDone, n)
				}
			}
		}
		out["running_intents"] = compactIntents(running, parentsOf, yieldsOf)
		out["recent_done_intents"] = compactIntents(recentDone, parentsOf, yieldsOf)
		out["frontier_open"] = len(fr)
		// findings (confirmed vulns) and facts (worker exploration results) are
		// now distinct node kinds. recent_facts surfaces fact summaries (esp.
		// negative results) so the planner sees them in one call; full content
		// via node_detail(id).
		vulnNodes, _ := t.ts.ListByKind(db.KindFinding, 1000)
		factNodes, _ := t.ts.ListByKind(db.KindFact, 1000) // newest first
		out["findings"] = len(vulnNodes)                   // 确认漏洞数（目标判定看它）
		out["facts"] = len(factNodes)                      // 探索事实/结论数（含否定结论）
		recentFacts := make([]map[string]any, 0, 20)
		for _, n := range factNodes {
			if len(recentFacts) >= 20 {
				break
			}
			m := compactNode(n)
			if from := factFrom[n.ID]; from > 0 {
				m["from_intent"] = from // 本事实由哪个意图产生
			}
			// confidence 带进概览：让规划者一眼看出哪条结论只是 inferred（尤其否定结论
			// 别当铁案）；evidence 较长，留给 node_detail(id)。
			var fp map[string]any
			if json.Unmarshal(n.Payload, &fp) == nil {
				if c, ok := fp["confidence"].(string); ok && c != "" {
					m["confidence"] = c
				}
			}
			recentFacts = append(recentFacts, m)
		}
		out["recent_facts"] = recentFacts // 最近事实的 {id, summary, from_intent, confidence?}，详情/证据用 node_detail(id)
		// the original task (root) so the planner always has it, not just the
		// decomposed goals.
		if description, goal, err := t.ts.Root(); err == nil {
			out["task"] = map[string]any{"description": description, "goal": goal}
		}
		return out
	}
}

// compactNode distills any exploration node to id + summary + state, dropping the
// big detail/evidence (fetch that on demand via node_detail).
func compactNode(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	return map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
}

// compactFinding is compactNode plus the vuln-specific vulnclass/severity.
func compactFinding(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
	if vc, ok := p["vulnclass"]; ok && vc != nil && vc != "" {
		m["vulnclass"] = vc
	}
	if sv, ok := p["severity"]; ok && sv != nil && sv != "" {
		m["severity"] = sv
	}
	return m
}

func (t *ToolSet) listFindings() actool.CoreTool {
	return readTool("list_findings", "List [confirmed vulnerabilities] (compact: id+task_id+intent_id+vulnclass+severity+summary+state). task_id=the task this vuln belongs to, intent_id=the intent that produced it. This lists only vulnerabilities, not ordinary exploration facts (those are in list_facts). Use node_detail(id) for details.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			f, _ := t.ts.ListByKind(db.KindFinding, 500)
			intentOf, _ := t.ts.FindingIntents() // finding id -> 产生它的 intent id
			taskID := t.ts.ID()                  // exploration id = 任务 id（本 store 内所有 finding 同属）
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				m := compactFinding(n)
				m["task_id"] = taskID
				if iid, ok := intentOf[n.ID]; ok {
					m["intent_id"] = iid
				}
				out = append(out, m)
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) listFacts() actool.CoreTool {
	return readTool("list_facts", "List [exploration facts/conclusions] (compact: id+summary+state), i.e. the conclusions a worker reached while pursuing an intent (including negative conclusions such as 'port closed/not injectable'). Use node_detail(id) for details. For vulnerabilities see list_findings.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			f, _ := t.ts.ListByKind(db.KindFact, 500)
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				out = append(out, compactNode(n))
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) nodeDetail() actool.CoreTool {
	return readTool("node_detail", "Fetch the full content of an [exploration graph node] by id (fact/finding/intent/goal: summary + detail/evidence/PoC). Only exploration graph node ids are accepted (ids returned by list_facts / list_findings / graph_overview's recent_facts). To query [assets] use list_assets / asset_neighbors: an asset id is not an exploration node id, do not pass it here.",
		obj(map[string]any{"id": idp("exploration graph node id (not an asset id)")}, "id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.ID)
			if id <= 0 {
				return actool.Errorf("id is required"), nil
			}
			n, err := t.ts.GetNode(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == nil {
				return actool.Errorf(fmt.Sprintf("exploration node %d not found. If you meant to query an asset, use list_assets / asset_neighbors (assets and exploration nodes are different id spaces; an asset id cannot be passed to node_detail).", id)), nil
			}
			return jsonResult(n) // full payload incl. detail / evidence
		})
}

// --- planner write tools ---

// intentItem 是 add_intent 批量/单条的一条探索方向。
type intentItem struct {
	Summary   string            `json:"summary"`
	AssetIDs  []json.RawMessage `json:"asset_ids"`
	ParentIDs []json.RawMessage `json:"parent_ids"`
	Priority  int               `json:"priority"`
}

// addOneIntent 创建一条意图节点并连上游血缘，返回 id。
// 约束：意图只能锚在已确认知识上——每个 parent_id 必须是已存在的 fact/finding
// 节点（不能挂在别的意图/目标/提示上）。顶层全新方向留空 parent_ids，兜底连 origin fact。
// 这样"每个意图都连到 fact 节点、且是发现驱动而非凭空规划"从创建路径上被强制。
// intentClassKeywords maps vuln-class phrasings to a canonical token (checked in
// order) so differently-worded intents about the same class collapse.
var intentClassKeywords = []struct{ pat, canon string }{
	{"sql injection", "sqli"}, {"sqli", "sqli"},
	{"cross-site scripting", "xss"}, {"xss", "xss"},
	{"insecure direct object", "idor"}, {"idor", "idor"},
	{"server-side request forgery", "ssrf"}, {"ssrf", "ssrf"},
	{"cross-site request forgery", "csrf"}, {"csrf", "csrf"},
	{"xxe", "xxe"},
	{"path traversal", "traversal"}, {"directory traversal", "traversal"}, {"lfi", "traversal"},
	{"command injection", "rce"}, {"remote code execution", "rce"}, {"rce", "rce"},
	{"nosql", "nosqli"},
	{"mass assignment", "massassign"},
	{"authentication bypass", "authbypass"}, {"auth bypass", "authbypass"}, {"login bypass", "authbypass"},
	{"privilege escalation", "privesc"}, {"broken access", "accesscontrol"},
	{"open redirect", "openredirect"}, {"jwt", "jwt"},
	{"content security policy", "csp"}, {"content-security-policy", "csp"},
	{"sensitive path exposure", "exposure"}, {"security misconfiguration", "exposure"},
	{"captcha", "captcha"},
	{"reconnaissance", "recon"}, {"enumerate", "recon"}, {"enumeration", "recon"}, {"fingerprint", "recon"},
}

// intentClass returns the canonical vuln-class token mentioned in s, or "".
func intentClass(s string) string {
	ls := strings.ToLower(s)
	for _, k := range intentClassKeywords {
		if strings.Contains(ls, k.pat) {
			return k.canon
		}
	}
	return ""
}

// intentDedupKey builds a SEMANTIC key for an intent: canonical vuln class + the
// first endpoint path. Returns "" unless BOTH are present, so an intent without a
// clear class/endpoint falls back to exact-text dedup (never wrongly merged).
func intentDedupKey(summary string) string {
	cls := intentClass(summary)
	ep := extractEndpoint(summary)
	if cls == "" || ep == "" {
		return ""
	}
	return cls + "|" + ep
}

func (t *ToolSet) addOneIntent(it intentItem) (int64, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return 0, fmt.Errorf("summary cannot be empty")
	}
	// dedup: reuse an equivalent intent already open/running/done instead of
	// creating a duplicate - weak planners re-dispatch the same direction (often
	// re-worded), bloating the frontier so the single worker redoes the same
	// ground. Two signals: a SEMANTIC key (vuln class + endpoint) that collapses
	// re-worded duplicates, and the exact normalized text as a fallback. Stopped/
	// blocked intents are NOT matched, so a failed direction can still be retried.
	if t.ts != nil {
		newSem := intentDedupKey(it.Summary)
		newExact := normToken(it.Summary)
		if newSem != "" || newExact != "" {
			if existing, _ := t.ts.ListByKind(db.KindIntent, 1000); existing != nil {
				for _, n := range existing {
					if n.State != "open" && n.State != "running" && n.State != "done" {
						continue
					}
					var p struct {
						Summary string `json:"summary"`
					}
					_ = json.Unmarshal(n.Payload, &p)
					if newSem != "" && intentDedupKey(p.Summary) == newSem {
						return n.ID, nil // same class + endpoint (semantic duplicate)
					}
					if newExact != "" && normToken(p.Summary) == newExact {
						return n.ID, nil // identical text
					}
				}
			}
		}
	}
	// 先校验锚点（建节点前，避免坏锚点留下孤儿意图）。
	parents := pidList(it.ParentIDs)
	for _, pidv := range parents {
		n, err := t.ts.GetNode(pidv)
		if err != nil || n == nil {
			return 0, fmt.Errorf("parent_id %d does not exist: parent_ids must be ids of existing [fact/finding] nodes; for a brand-new top-level direction leave parent_ids empty", pidv)
		}
		if n.Kind != db.KindFact && n.Kind != db.KindFinding {
			return 0, fmt.Errorf("parent_id %d is a %q node and cannot be an intent anchor: an intent can only be anchored on a confirmed [fact/finding], not on an intent/goal/hint; for a brand-new top-level direction leave parent_ids empty", pidv, n.Kind)
		}
	}
	priority := it.Priority
	if priority == 0 {
		priority = 5
	}
	anchors := pidList(it.AssetIDs)
	payload := map[string]any{"summary": it.Summary}
	if len(anchors) > 0 {
		payload["asset_ids"] = anchors
	}
	id, err := t.ts.AddIntent(payload, priority, anchors, "planner")
	if err != nil {
		return 0, err
	}
	// upstream lineage: link each (validated) fact/finding parent → this intent, so
	// "multiple facts combine into one new intent" is expressible.
	for _, parent := range parents {
		_ = t.ts.Link(parent, db.RelDerivedFrom, id)
	}
	// a top-level intent (no explicit parent) connects to the origin fact, so every
	// intent still traces back to a fact node — at task start the only fact is the
	// origin, and the first intents derive from it.
	if len(parents) == 0 {
		if origin, _ := t.ts.OriginFactID(); origin > 0 {
			_ = t.ts.Link(origin, db.RelDerivedFrom, id)
		}
	}
	return id, nil
}

func (t *ToolSet) addIntent() actool.CoreTool {
	return writeTool("add_intent", "Generate an [exploration direction], write it into the frontier, and link it into the exploration lineage. An intent is an open exploration direction, not a fixed type: use summary to freely describe in one sentence what to explore/verify/exploit.\n"+
		"★Prefer batching: put the several new directions you picked in one round into the intents array and submit them at once (fewer round-trips than calling one by one). Returns an ids array, same length and order as intents (a failed item has id=0, see errors for details). For a single item, omit intents and just give the top-level summary.",
		obj(map[string]any{
			"intents":    map[string]any{"type": "array", "description": "[Prefer this] Array of exploration directions to add, processed in order. Each element has the same fields as the top-level fields below (summary/asset_ids/parent_ids/priority). The returned ids have the same length and order as this array.", "items": map[string]any{"type": "object"}},
			"summary":    str("[single] One sentence describing this exploration direction: what to do + why. As long as the direction is clearly stated it is fine; it does not depend on asset ids."),
			"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "The [target asset ids] this direction will test/attack (**pass them whenever possible**, 0/1/many; these are asset ids returned by list_assets, not exploration node ids): which assets (site/endpoint/parameter/host etc.) this exploration direction targets. Whenever the direction revolves around some specific assets be sure to pass them: it is the structured marker of 'which targets this exploration hits', used for coverage dedup and for linking the intent into the asset lineage. Leave it empty only for pure global reconnaissance, when there really is no specific target asset."},
			"parent_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Upstream anchor ids (optional, 0/1/many): which [confirmed fact(s)/finding(s)] this direction is synthesized from. **Only ids of existing fact/finding nodes are allowed, not intents/goals/hints**: an intent must be anchored on confirmed knowledge, finding-driven rather than planned out of thin air. If several facts jointly produce one new intent, pass several; for a brand-new top-level reconnaissance direction leave it empty (it will be automatically attached to the task's origin fact)."},
			"priority":   intp("priority 0-10, default 5"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Intents    []intentItem `json:"intents"`
				intentItem              // 单条模式：顶层 summary/asset_ids/parent_ids/priority
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Intents) > 0
			items := a.Intents
			if !batch {
				items = []intentItem{a.intentItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.addOneIntent(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("intent created: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) listGoals() actool.CoreTool {
	return readTool("list_goals", "List this task's goal nodes and their state (open/met), to judge whether they are met.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			g, _ := t.ts.ListByKind(db.KindGoal, 100)
			return jsonResult(g)
		})
}

func (t *ToolSet) proveGoal() actool.CoreTool {
	return writeTool("prove_goal", "Call this when you judge that a finding/fact proves a goal is met: it links the evidence node to the goal node and marks the goal met.",
		obj(map[string]any{
			"goal_id":     idp("goal node id"),
			"evidence_id": idp("id of the finding/fact node that proves it"),
			"reason":      str("why this evidence satisfies the goal"),
		}, "goal_id", "evidence_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				GoalID     json.RawMessage `json:"goal_id"`
				EvidenceID json.RawMessage `json:"evidence_id"`
				Reason     string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			goal, ev := pid(a.GoalID), pid(a.EvidenceID)
			if goal == 0 || ev == 0 {
				return actool.Errorf("goal_id and evidence_id are required"), nil
			}
			_ = t.ts.Link(ev, db.RelProves, goal)
			_ = t.ts.SetNodeState(goal, "met")
			// 每标记一个目标 met，就检查本任务是否【所有目标】都已 met；若是，自动判定
			// 任务完成（置 GoalMet），无需再依赖模型显式调 goal_met。
			if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil && len(goals) > 0 {
				allMet := true
				for _, g := range goals {
					if g.State != "met" {
						allMet = false
						break
					}
				}
				if allMet {
					t.GoalMet = true
					t.Reason = fmt.Sprintf("all %d goals are now met (the last one triggered by goal %d)", len(goals), goal)
					// Last goal closed → whole task complete: end the run now rather
					// than hand control back to the model (same loop-prevention as
					// goal_met; prove_goal is the preferred completion path).
					r := actool.Text(fmt.Sprintf("goal %d marked met; all goals of this task are met, the task is complete and this run is ending", goal))
					r.StopContinuation = true
					return r, nil
				}
			}
			return actool.Text(fmt.Sprintf("goal %d marked met", goal)), nil
		})
}

func (t *ToolSet) goalMet() actool.CoreTool {
	return writeTool("goal_met", "[Immediately end the entire task]: call this only when you confirm that [all of the task's goals are truly met and the whole thing is wrapped up] (note this is the task as a WHOLE being complete; merely reaching one of the goals/one flag/one vulnerability does NOT count: in that case just mark that goal with prove_goal). WARNING: it is not for \"ending the current planning round\": if there is no new intent to dispatch this round, or you are waiting for worker output, just [end the current round directly, do not call this tool] (0 intents is perfectly normal). For normal judgement prefer prove_goal to prove goals one by one; goal_met is only a means to bypass proving them one by one and wrap up globally.",
		obj(map[string]any{"reason": str("reason for completion (must be evidence that the goals are truly met, not a round-ending reason like \"no new direction this round\")")}, "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Reason string }
			_ = json.Unmarshal(in, &a)
			// structural guardrail: goal_met may end the task ONLY when EVERY goal is
			// already proven (state "met" via prove_goal). A weak planner otherwise
			// calls it with goals still open, closing the task prematurely and cutting
			// in-flight workers. Refuse until all goals are met.
			if t.ts != nil {
				if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil && len(goals) > 0 {
					var unmet []int64
					for _, g := range goals {
						if g.State != "met" {
							unmet = append(unmet, g.ID)
						}
					}
					if len(unmet) > 0 {
						return actool.Errorf(fmt.Sprintf("goal_met refused: %d goal(s) not yet proven (ids %v). Close goals one by one with prove_goal(goal_id, evidence_id) once a finding/fact satisfies each, and dispatch add_intent for the rest. Do NOT call goal_met until EVERY goal is in state met.", len(unmet), unmet)), nil
					}
				}
			}
			t.GoalMet = true
			t.Reason = a.Reason
			// End the planner round right now: all goals are proven, so there is
			// nothing left to plan. Without this the (weak) model keeps re-calling
			// goal_met every turn until the task deadline cap, burning the whole
			// budget on a task that is already complete.
			r := actool.Text("acknowledged: goal marked met; all goals proven, the task is complete and this run is ending")
			r.StopContinuation = true
			return r, nil
		})
}

// --- worker write tools ---

// normToken lowercases a string and drops every non-alphanumeric rune, so
// "SQL Injection" -> "sqlinjection" and "IDOR"/"idor" -> "idor". Used to build a
// stable dedup key insensitive to casing/spacing of the vuln class.
func normToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		}
	}
	return b.String()
}

var endpointRe = regexp.MustCompile(`/[A-Za-z0-9_][A-Za-z0-9_./-]*`)

// urlAuthorityRe matches a scheme + authority ("http://juice-shop:3000") so it can
// be stripped before path extraction: without this, endpointRe would stop at the
// ':' of ":3000" and grab the HOST ("/juice-shop") instead of the real path, so the
// same endpoint written as a full URL vs a bare path produced different dedup keys
// and the duplicate slipped through.
var urlAuthorityRe = regexp.MustCompile(`(?i)https?://[^/\s]+`)

// resourceTokens maps generic web-resource nouns (and common synonyms) to a
// canonical target token. Fallback for finding/intent text that names a resource
// but carries no explicit URL path, so dedup still gets a stable key. Order is
// PRIORITY (first match wins), most specific/actionable first and the generic
// "user" last, so e.g. "a user bypasses login" keys on "login", not "user".
// Known compromise (matches the existing exact/semantic dedup): substring match,
// so two findings on the same canonical target but different parameters may merge.
var resourceTokens = []struct{ pat, canon string }{
	{"login", "login"}, {"signin", "login"}, {"authenticate", "login"},
	{"logout", "logout"},
	{"register", "register"}, {"signup", "register"},
	{"password", "password"}, {"forgot", "password"},
	{"token", "token"}, {"jwt", "token"},
	{"basket", "basket"}, {"cart", "basket"},
	{"feedback", "feedback"},
	{"review", "review"},
	{"comment", "comment"},
	{"search", "search"},
	{"upload", "upload"},
	{"coupon", "coupon"},
	{"captcha", "captcha"},
	{"order", "order"},
	{"admin", "admin"},
	{"profile", "profile"},
	{"product", "product"},
	{"user", "user"},
}

// resourceNoun returns the canonical token of the first (by priority) known
// resource noun contained in s, or "".
func resourceNoun(s string) string {
	ls := strings.ToLower(s)
	for _, t := range resourceTokens {
		if strings.Contains(ls, t.pat) {
			return t.canon
		}
	}
	return ""
}

// extractEndpoint returns a stable TARGET token for dedup: the first real URL path
// in the text (e.g. "/rest/products/search"), lowercased with trailing punctuation
// trimmed; scheme+host are stripped first so a full URL and a bare path normalize
// to the same path. When no path is present it falls back to a generic resource
// noun (login/basket/feedback/...), and returns "" only when neither is found (in
// which case the callers skip dedup rather than merge on nothing).
func extractEndpoint(s string) string {
	clean := urlAuthorityRe.ReplaceAllString(s, "")
	if ep := strings.ToLower(strings.TrimRight(endpointRe.FindString(clean), "./-")); ep != "" {
		return ep
	}
	return resourceNoun(s)
}

// findingDedupKey keys a finding by normalized vuln class + the first endpoint
// path in its summary/evidence. Returns "" when no endpoint can be extracted, in
// which case dedup is skipped so distinct findings are never wrongly merged.
func findingDedupKey(vulnclass, summary, evidence string) string {
	ep := extractEndpoint(summary + " " + evidence)
	if ep == "" {
		return ""
	}
	return normToken(vulnclass) + "|" + ep
}

func (t *ToolSet) addFinding() actool.CoreTool {
	return writeTool("report_finding", "You must call this tool when you discover a vulnerability or confirm an exposure-type risk! Record a confirmed vulnerability, or a confirmed exposure/information-disclosure risk (unauthenticated-reachable sensitive/admin/debug endpoints, publicly exposed Swagger/config/backup, sensitive data leakage, etc.: it counts as confirmed once actually accessed with response evidence). In a task context intent_id is required (the id of the intent currently being executed); in a conversation context intent_id can be omitted.",
		obj(map[string]any{
			"vulnclass": str("vulnerability class"),
			"severity":  str("critical|high|medium|low"),
			"summary":   str("finding summary"),
			"intent_id": idp("id of the intent that produced this finding (required in a task context; optional in a conversation context)"),
			"asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "affected asset ids (optional, 0/1/many): parameter/endpoint/site etc. If one vulnerability affects several places you can fill them all; for a pure observation you can leave it empty."},
			"evidence":  str("evidence/PoC text"),
			"reproduction": map[string]any{
				"type":        "object",
				"description": "[Strongly recommended] Structured reproduction process, for a human to reproduce from scratch and for the delivered report. Write each step's request as a [standard HTTP request message] (not curl/a command) and its response as [status line + key body] (do not use ... to omit the key content); everything taken verbatim from the requests/responses you actually executed this time, never rewritten or fabricated; you just finished the attack and know every step best.",
				"properties": map[string]any{
					"entry_point":   str("the key endpoint that triggers the vulnerability (method+URL), e.g. POST /user/validate/otp/forgetPasswordVerify"),
					"prerequisites": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "reproduction prerequisites: the accounts/roles/sessions/prior steps needed. If a test account is required, state clearly [how to register] (endpoint + key request points): reproducible from scratch."},
					"steps": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{
						"request":  str("this step's real request, written as a [standard HTTP request message]: request line (METHOD /path?query HTTP/1.1) + key headers (Host/Content-Type/Cookie etc.) + blank line + body, taken verbatim from the request you actually sent. [Do not write it as a curl/python/shell command]: even if you executed it with curl, reconstruct the equivalent HTTP message. Only when the step really does not go over HTTP (e.g. a direct database connection, generating a token locally) should you write the tool call as-is and prefix it with 'non-HTTP: '."),
						"response": str("this step's real response, written as an [HTTP response]: status line (HTTP/1.1 200 OK) + key headers + key body fragments, taken verbatim from the actual response. [Do not use ... to omit the key content that proves the problem]; if the response is long, keep only the key fragments that locate this exchange and prove the vulnerability (echoes/token/error messages etc.)."),
						"expected": str("this step's expectation/conclusion (status code + key fields, one sentence)"),
						"proves":   str("what this step proves"),
					}}, "description": "ordered reproduction steps (from entry point to confirmation); write each step as a [standard HTTP request message + key response] (not curl/a command, and do not omit the response with ...), so it can be automatically linked to the recorded real traffic capture and support one-click jump and screenshot"},
					"provenance": str("which exploration/intent discovered this vulnerability and which prior results it depends on (the attack-chain origin)"),
				},
			},
		}, "vulnclass", "severity", "summary"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnClass, Severity, Summary, Evidence string
				IntentID                               json.RawMessage   `json:"intent_id"`
				AssetIDs                               []json.RawMessage `json:"asset_ids"`
				Reproduction                           json.RawMessage   `json:"reproduction"`
			}
			_ = json.Unmarshal(in, &a)
			payload := map[string]any{"vulnclass": a.VulnClass, "severity": a.Severity, "summary": a.Summary,
				"evidence": map[string]any{"by": t.worker, "poc": a.Evidence}}
			repro := a.Reproduction
			if len(repro) > 2 { // "{}" is 2 bytes; only carry a real recipe
				// Resolve steps → real traffic exchange ids at record time (host callback),
				// so the stored finding's steps carry jump-to-traffic links up front.
				if t.resolveTraffic != nil && t.taskID > 0 {
					if r := t.resolveTraffic(t.taskID, repro); len(r) > 2 {
						repro = r
					}
				}
				payload["reproduction"] = repro
			}
			var anchors []int64
			for _, raw := range a.AssetIDs {
				if p := pid(raw); p > 0 {
					anchors = append(anchors, p)
				}
			}
			var id int64
			if t.ts != nil {
				// dedup: skip if an equivalent finding (same vuln class + endpoint)
				// already exists in this task's graph — weak models and concurrent
				// workers often re-confirm the same vuln and call report_finding again.
				if key := findingDedupKey(a.VulnClass, a.Summary, a.Evidence); key != "" {
					if dups, _ := t.ts.ListByKind(db.KindFinding, 500); dups != nil {
						for _, n := range dups {
							var p struct {
								VulnClass string `json:"vulnclass"`
								Summary   string `json:"summary"`
								Evidence  struct {
									Poc string `json:"poc"`
								} `json:"evidence"`
							}
							_ = json.Unmarshal(n.Payload, &p)
							if findingDedupKey(p.VulnClass, p.Summary, p.Evidence.Poc) == key {
								return actool.Text(fmt.Sprintf("finding duplicate of #%d (same class+endpoint), skipped", n.ID)), nil
							}
						}
					}
				}
				var err error
				id, err = t.ts.AddNode(db.KindFinding, payload, 9, "confirmed", t.worker, anchors)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if intent := pid(a.IntentID); intent > 0 {
					_ = t.ts.Link(intent, db.RelYields, id) // chain: intent -> finding
				}
				_, _ = t.ts.AddStandaloneFinding(t.taskID, id, a.VulnClass, a.Severity, a.Summary, a.Evidence, t.worker, anchors)
				if len(repro) > 2 { // 就地记录的结构化复现过程(agent 测完即填,请求逐字真实)
					_ = t.ts.SetFindingReproduction(id, repro)
				}
			} else {
				// conversation context: no exploration store available, cannot record finding
				return actool.Errorf("report_finding requires a task context (exploration store not initialized)"), nil
			}
			t.writes.Findings++
			return actool.Text(fmt.Sprintf("finding recorded: %d", id)), nil
		})
}

// recordFact writes a general exploration RESULT/conclusion (not a vuln, not a
// new asset) into the EXPLORATION graph, chained to the intent that produced it.
// This is the home for observations and — importantly — negative results
// ("port closed", "param not injectable", "no login found"). Such conclusions
// must NOT be stuffed into the asset graph via upsert_asset.
// factItem 是 record_fact 批量/单条的一条事实。
type factItem struct {
	Summary    string            `json:"summary"`
	Detail     string            `json:"detail"`
	Evidence   string            `json:"evidence"`   // 一行关键证据（命令+关键输出行），支撑结论、便于事后核对
	Confidence string            `json:"confidence"` // observed（直接看到）| inferred（据现象推断）
	IntentID   json.RawMessage   `json:"intent_id"`
	AssetIDs   []json.RawMessage `json:"asset_ids"`
}

// --- fact dedup (L3d) ---

// factStopwords are boilerplate/common tokens dropped before token-set similarity,
// so two facts are not judged similar merely because they share scaffolding words
// (every summary tends to repeat "OWASP Juice Shop ...", "the", "API", etc.).
var factStopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "that": true, "this": true,
	"are": true, "was": true, "were": true, "has": true, "have": true, "from": true,
	"via": true, "due": true, "not": true, "any": true, "all": true, "can": true,
	"owasp": true, "juice": true, "shop": true, "http": true, "https": true,
}

// factTokens returns the set of significant lowercase tokens (len>=3, non-stopword)
// in s, used for token-set (Jaccard) similarity between fact summaries.
func factTokens(s string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		if len(w) >= 3 && !factStopwords[w] {
			out[w] = struct{}{}
		}
	}
	return out
}

// jaccard returns |a∩b| / |a∪b| for two token sets (0 when either is empty).
func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// factDupJaccard is the token-set overlap above which two fact summaries are treated
// as the same conclusion reworded (tuned to collapse restatements, not merge distinct
// facts that only share a topic).
const factDupJaccard = 0.82

// noProgressFactStop is how many CONSECUTIVE no-progress record_fact calls (each
// adding nothing new to the graph) end a worker's intent run. Tuned from the
// observed loop (a weak worker re-recording the same conclusion 5-7x on one
// intent): 4 tolerates a couple of redundant restatements but cuts the spin well
// before the per-intent turn/time budget. A call that records a new fact resets
// the count.
const noProgressFactStop = 4

// recordOneFact 写一条 fact 节点并连到意图（intent→yields→fact）。defaultIntent 为
// 批量时的默认意图（本条未给 intent_id 时用）。
// noteFactProgress updates the per-intent no-progress counter after a record_fact
// call and reports whether the worker should now end its run (it is spinning,
// re-recording with nothing new). anyCreated = the call added at least one NEW
// fact, which resets the counter.
func (t *ToolSet) noteFactProgress(anyCreated bool) (stop bool) {
	if anyCreated {
		t.redundantFacts = 0
		return false
	}
	t.redundantFacts++
	return t.redundantFacts >= noProgressFactStop
}

// recordOneFact returns the fact node id, whether a NEW node was created (false
// when the fact deduped to an existing one), and any error.
func (t *ToolSet) recordOneFact(it factItem, defaultIntent int64) (int64, bool, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return 0, false, fmt.Errorf("summary cannot be empty")
	}
	// dedup (L3d): weak workers re-record the same conclusion many times (task 34:
	// 612 facts but only 302 unique; a single negative restated ~48x), bloating the
	// graph and poisoning the context. Skip a fact equivalent to one already in THIS
	// task — identical normalized summary, or a high token-set overlap that also
	// catches rewordings — returning the existing node id without a new write.
	if t.ts != nil {
		newExact := normToken(it.Summary)
		newTok := factTokens(it.Summary)
		if existing, _ := t.ts.ListByKind(db.KindFact, 1000); existing != nil {
			for _, n := range existing {
				var p struct {
					Summary string `json:"summary"`
				}
				_ = json.Unmarshal(n.Payload, &p)
				if newExact != "" && normToken(p.Summary) == newExact {
					return n.ID, false, nil // identical conclusion already recorded
				}
				if len(newTok) >= 3 && jaccard(newTok, factTokens(p.Summary)) >= factDupJaccard {
					return n.ID, false, nil // reworded restatement of an existing fact
				}
			}
		}
	}
	payload := map[string]any{"summary": it.Summary}
	if it.Detail != "" {
		payload["detail"] = it.Detail
	}
	if e := strings.TrimSpace(it.Evidence); e != "" {
		payload["evidence"] = e
	}
	if c := strings.TrimSpace(it.Confidence); c != "" {
		payload["confidence"] = c
	}
	// a fact is its OWN node kind (distinct from a vuln finding).
	id, err := t.ts.AddNode(db.KindFact, payload, 5, "confirmed", t.worker, pidList(it.AssetIDs))
	if err != nil {
		return 0, false, err
	}
	intent := pid(it.IntentID)
	if intent <= 0 {
		intent = defaultIntent
	}
	if intent > 0 {
		_ = t.ts.Link(intent, db.RelYields, id) // chain: intent -> fact
	}
	t.writes.Facts++
	return id, true, nil
}

func (t *ToolSet) recordFact() actool.CoreTool {
	return writeTool("record_fact", "Write an exploration [fact/conclusion] into the exploration graph, linked to the intent that produced it (intent_id). Used to record exploration results: including [positive conclusions] such as fingerprinting/enumeration, and [negative conclusions] such as 'port closed'/'parameter not injectable'/'no login entry found'.\n"+
		"⚠️Multiple observations from a single exploration should be [aggregated into one fact], do not split them into many; whenever they can be merged into one fact, express them as one fact: summary=a one-sentence summary of this conclusion, detail=the related details (may contain several specific items). Example: a fingerprinting intent -> one fact {summary:'identified the tech stack and response characteristics of site X', detail:'nginx 1.25 / Vue3 / 200 / title=.. / body_len=..'}, rather than recording the status code, fingerprint, and title each separately. One intent usually yields only one fact; splitting too finely makes the graph grow without bound.\n"+
		"★The facts array is for writing several [mutually distinct] conclusions at once (each may omit intent_id, defaulting to the top-level intent_id). Returns an ids array, same length and order as facts.\n"+
		"⚠️Only write conclusions you [actually saw] in the tool output, do not make things up. evidence and confidence are used to prevent inaccurate conclusions from polluting the graph:\n"+
		"  · evidence=the [one-line] key evidence supporting this conclusion (the command + the one or two output lines that best prove it), **be concise**: the details are already in detail, do not paste a large block of output here.\n"+
		"  · confidence=observed (seen directly in the output) | inferred (deduced from the phenomenon).\n"+
		"  · **Negative conclusions** (not injectable/port closed/no entry found etc.) especially need evidence and an honest confidence: they make the planner abandon this direction, and a wrong negative is very costly; if you only probed once or the evidence is weak, mark it inferred, do not treat it as hard fact.",
		obj(map[string]any{
			"facts":      map[string]any{"type": "array", "description": "[Use when there are several distinct conclusions] Array of facts; each element has the same fields as the top-level fields below (summary/detail/evidence/confidence/intent_id/asset_ids); if intent_id is omitted the top-level intent_id is used. The returned ids have the same length and order as this array.", "items": map[string]any{"type": "object"}},
			"summary":    str("a [one-sentence summary] of this exploration's conclusion (a recap of detail)"),
			"intent_id":  idp("id of the intent that produced this fact (the intent you were assigned; used as the per-item default in batch mode)"),
			"detail":     str("the related details of this fact: write all the observations from this exploration here"),
			"evidence":   str("[one-line] key evidence: the command + the one or two output lines that best prove the conclusion. Be concise, do not paste a large block of output (put details in detail)."),
			"confidence": str("observed (seen directly in the output) | inferred (deduced from the phenomenon). Negative conclusions must be labelled honestly."),
			"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "related asset ids (optional, 0/1/many): which assets this fact involves"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Facts    []factItem `json:"facts"`
				factItem            // 单条模式 + 批量默认 intent_id
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Facts) > 0
			items := a.Facts
			if !batch {
				items = []factItem{a.factItem}
			}
			defaultIntent := pid(a.factItem.IntentID) // 顶层 intent_id = 批量默认

			ids := make([]int64, len(items))
			errs := map[string]string{}
			anyCreated := false
			for i, it := range items {
				id, created, err := t.recordOneFact(it, defaultIntent)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				if created {
					anyCreated = true
				}
			}

			// No-progress terminator (Lever 1+2): a call that added nothing new (all
			// items deduped) is a no-progress tick; a NEW fact resets the counter.
			// After noProgressFactStop consecutive no-progress calls the worker is
			// re-recording its one intent's conclusion instead of finishing, so end
			// the run cleanly (StopContinuation -> ReasonHookStopped -> intent done)
			// and let the loop advance. Below the threshold, a redundant call still
			// gets a nudge to stop.
			stop := t.noteFactProgress(anyCreated)

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				if stop {
					r := actool.Text(fmt.Sprintf(
						"This conclusion was already recorded and you have now repeated record_fact %d times on this intent "+
							"without adding anything new. The intent's result is already in the graph, so this run is ending "+
							"and the loop will move to the next intent. Do NOT re-record the same conclusion.", t.redundantFacts))
					r.StopContinuation = true
					return r, nil
				}
				if !anyCreated {
					return actool.Text(fmt.Sprintf(
						"fact already recorded (#%d): nothing new was added. If your assigned check is complete, STOP now "+
							"(end with a brief final note, no more tool calls) instead of re-recording the same conclusion.", ids[0])), nil
				}
				return actool.Text(fmt.Sprintf("fact recorded: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			r, jerr := jsonResult(out)
			if jerr != nil {
				return r, jerr
			}
			if stop {
				r.StopContinuation = true
			}
			return r, nil
		})
}

type hintItem struct {
	Text     string            `json:"text"`
	AssetIDs []json.RawMessage `json:"asset_ids"`
}

// addOneHint 挂一条 hint 节点(active/human)到探索图,可锚定资产,返回 id。
func (t *ToolSet) addOneHint(it hintItem) (int64, error) {
	if strings.TrimSpace(it.Text) == "" {
		return 0, fmt.Errorf("text cannot be empty")
	}
	var anchors []int64
	for _, raw := range it.AssetIDs {
		if tid := pid(raw); tid > 0 {
			anchors = append(anchors, tid)
		}
	}
	id, err := t.ts.AddNode(db.KindHint, map[string]any{"text": it.Text}, 0, "active", "human", anchors)
	if err == nil && t.notify != nil {
		t.notify() // wake the planner so the new hint is read promptly (debounced)
	}
	return id, err
}

func (t *ToolSet) addHint() actool.CoreTool {
	return writeTool("add_hint", "Attach a strategic hint from a human / the main agent onto the exploration graph; the planner will read it the next time it generates intents.\n"+
		"★Prefer batching: put several hints in the hints array and submit them at once (fewer round-trips than calling one by one). Returns an ids array, same length and order as hints (a failed item has id=0, see errors for details). For a single item, omit hints and just give the top-level text.",
		obj(map[string]any{
			"hints":     map[string]any{"type": "array", "description": "[Prefer this] Array of hints to add, processed in order. Each element has the same fields as the top-level fields below (text/asset_ids). The returned ids have the same length and order as this array.", "items": map[string]any{"type": "object"}},
			"text":      str("[single] hint content, e.g. 'focus on digging into post-authentication endpoints'"),
			"asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "anchored asset ids (optional, 0/1/many)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Hints    []hintItem `json:"hints"`
				hintItem            // 单条模式：顶层 text/asset_ids
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Hints) > 0
			items := a.Hints
			if !batch {
				items = []hintItem{a.hintItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.addOneHint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("hint added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// killWorkTool lets the planner terminate a single running work (by intent id).
func (t *ToolSet) killWorkTool() actool.CoreTool {
	return writeTool("kill_work", "Terminate a running intent (work). Used to stop an off-track/pointless exploration; the terminated intent is marked stopped and is no longer auto-reclaimed. First use get_worker_output to see what it is doing before deciding.",
		obj(map[string]any{"intent_id": idp("id of the intent to terminate (= the work handle)")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.killWork == nil {
				return actool.Errorf("kill_work is currently unavailable"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			if err := t.killWork(id); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("sent a termination signal to the work of intent %d", id)), nil
		})
}

// steerWorkTool lets the planner inject a mid-run course-correction into a running
// work WITHOUT killing it: the message reaches the worker before its next tool call,
// which re-plans its next step (already-gathered context is kept). For in-intent
// nudges ("停做 X、聚焦 Y"); if the whole direction is wrong use kill_work + a new intent.
func (t *ToolSet) steerWorkTool() actool.CoreTool {
	return writeTool("steer_work", "Inject a real-time course-correction instruction into a running intent (work) without interrupting it or losing existing progress: the worker will receive your instruction before its next action and adjust accordingly. Used for [in-intent] corrections like 'stop going down X, focus on Y'; if the whole direction is wrong, use kill_work instead and then issue a new intent. It is recommended to first use get_worker_output to see what it is doing.",
		obj(map[string]any{
			"intent_id": idp("id of the intent to correct (= the work handle)"),
			"message":   str("the correction instruction for the worker, clearly stating what to stop and what to switch to"),
		}, "intent_id", "message"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.steerWork == nil {
				return actool.Errorf("steer_work is currently unavailable"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
				Message  string          `json:"message"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			if strings.TrimSpace(a.Message) == "" {
				return actool.Errorf("message is required"), nil
			}
			if err := t.steerWork(id, a.Message); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("injected a correction instruction into the work of intent %d (takes effect on the next step)", id)), nil
		})
}

// getWorkerOutput returns a work's final (or截至中止时的) conclusion text by intent id.
func (t *ToolSet) getWorkerOutput() actool.CoreTool {
	return readTool("get_worker_output", "Fetch the final output conclusion of an intent (work). On normal completion it returns its summary; for a terminated (stopped)/abnormal work it returns its last output as of termination (terminated=true).",
		obj(map[string]any{"intent_id": idp("intent id (= the work handle)")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			acts, _, err := t.ts.ActivityList(&id, 0, 1000)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var chosen, fallback *db.Activity
			for i := range acts {
				switch acts[i].Kind {
				case "result":
					chosen = &acts[i]
					fallback = &acts[i]
				case "text":
					fallback = &acts[i]
				}
			}
			pick, terminated := chosen, false
			if pick == nil {
				pick, terminated = fallback, true
			}
			if pick == nil {
				return actool.Text("(this work has no output yet)"), nil
			}
			detail, _ := t.ts.ActivityDetail(pick.ID)
			if detail == "" {
				detail = pick.Summary
			}
			return jsonResult(map[string]any{
				"intent_id": id, "worker_name": pick.Worker, "final_text": detail,
				"summary": pick.Summary, "is_error": pick.IsError, "terminated": terminated,
			})
		})
}

// traceSteps renders summary-only trace rows, re-truncating each summary to 100
// chars — the stored summary is capped at 200 for the UI transcript; the trace
// tools want it tighter since a whole work's step list is many rows.
func traceSteps(acts []db.Activity) []map[string]any {
	steps := make([]map[string]any, 0, len(acts))
	for i := range acts {
		steps = append(steps, map[string]any{
			"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
			"is_error": acts[i].IsError, "summary": firstLine(acts[i].Summary, 100),
		})
	}
	return steps
}

// getWorkerTrace exposes a work's execution PROCESS (not just its final output):
// list step summaries, keyword-search within one work, or pull full detail of a
// few specific steps. Thinking steps are excluded everywhere.
func (t *ToolSet) getWorkerTrace() actool.CoreTool {
	return readTool("get_worker_trace",
		"View the [execution process] of an intent (work) (as opposed to get_worker_output which gives only the final conclusion). Three usages:\n"+
			"① Pass only intent_id → returns the summary stream of every step of this work (summary ≤100 chars, including step_id; just the outline of actions, not the full output);\n"+
			"② intent_id + q → returns only the summaries of steps matching the keyword (searches both summaries and full output; still gives only summary, use ③ to see the content);\n"+
			"③ intent_id + step_ids (at most 5) → returns the full content (detail) of these steps.\n"+
			"Typical flow: first use ①/② to locate the step_id of a suspicious step, then use ③ to fetch its full output. Thinking steps are excluded.",
		obj(map[string]any{
			"intent_id": idp("intent id (= the work handle)"),
			"q":         str("keyword: returns only steps whose summary/full output matches it (optional; mutually exclusive with step_ids)"),
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "the step_ids whose full content to fetch (from the ①/② results, at most 5 at a time)"},
			"limit":     intp("return limit for the summary stream/search (optional)"),
		}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage   `json:"intent_id"`
				Q        string            `json:"q"`
				StepIDs  []json.RawMessage `json:"step_ids"`
				Limit    int               `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			// ③ detail drill-down by step ids (max 5), thinking excluded by the store.
			if len(a.StepIDs) > 0 {
				var ids []int64
				for _, raw := range a.StepIDs {
					if v := pid(raw); v > 0 {
						ids = append(ids, v)
					}
				}
				if len(ids) > 5 {
					return actool.Errorf("step_ids: at most 5 at a time (first locate with a call without step_ids, then fetch in batches)"), nil
				}
				acts, err := t.ts.ActivityByIDs(ids)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				steps := make([]map[string]any, 0, len(acts))
				for i := range acts {
					steps = append(steps, map[string]any{
						"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
						"is_error": acts[i].IsError, "detail": acts[i].Detail,
					})
				}
				return jsonResult(map[string]any{"intent_id": id, "steps": steps})
			}
			// ①/② summary stream, optionally keyword-filtered; 100-char summaries.
			var acts []db.Activity
			var err error
			if strings.TrimSpace(a.Q) != "" {
				acts, err = t.ts.ActivityTraceSearch(&id, a.Q, a.Limit)
			} else {
				acts, err = t.ts.ActivityTrace(id, a.Limit)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"intent_id": id, "steps": traceSteps(acts)})
		})
}

// searchAllWorkerTraces keyword-searches EVERY work's process in this task — for
// finding what a worker saw but never wrote back as a fact. Returns only matching
// summaries (≤100 chars), each tagged with its intent_id for follow-up drill-down.
func (t *ToolSet) searchAllWorkerTraces() actool.CoreTool {
	return readTool("search_all_worker_traces",
		"Search by keyword (q) across [the execution processes of all works in this task]: used to recover something a worker saw but never wrote into a fact (some path/token/error message etc.). "+
			"Returns only the summaries of matching steps (summary ≤100 chars), each tagged with intent_id; then use get_worker_trace(intent_id, step_ids=[...]) to fetch the full content. Thinking steps are excluded.",
		obj(map[string]any{
			"q":     str("keyword (searches the summaries + full output of all work steps)"),
			"limit": intp("return limit, default 100 (optional)"),
		}, "q"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Q) == "" {
				return actool.Errorf("q is required"), nil
			}
			acts, err := t.ts.ActivityTraceSearch(nil, a.Q, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			hits := make([]map[string]any, 0, len(acts))
			for i := range acts {
				var intent int64
				if acts[i].NodeID != nil {
					intent = *acts[i].NodeID
				}
				hits = append(hits, map[string]any{
					"intent_id": intent, "step_id": acts[i].ID, "worker": acts[i].Worker,
					"kind": acts[i].Kind, "tool": acts[i].Tool, "is_error": acts[i].IsError,
					"summary": firstLine(acts[i].Summary, 100),
				})
			}
			return jsonResult(map[string]any{"query": a.Q, "hits": hits})
		})
}

// listWorkerTraces gives a worker (which has no graph_overview and can't see the
// intent graph) a lightweight index of the works in this task — intent_id +
// one-line summary + state — so it can DISCOVER which works to inspect via
// get_worker_trace. Without this a worker only knows intent_ids that come back
// from search_all_worker_traces hits. Excludes still-open intents (not yet run →
// no process to inspect).
func (t *ToolSet) listWorkerTraces() actool.CoreTool {
	return readTool("list_worker_traces",
		"List an index of [works (intents) that have already run] in this task: intent_id + one-sentence direction (summary) + state. "+
			"You (the worker) cannot see the exploration graph; use this to discover which works are worth looking at, then use get_worker_trace(intent_id) to view its steps and get_worker_trace(intent_id, step_ids=[...]) to fetch details. "+
			"Lists only executed ones (running/done/exhausted/blocked/stopped), not the open ones that have not run yet. Note: your task boundary is still the one intent you were assigned; looking at other works is only to reuse observations / avoid duplicate work.",
		obj(map[string]any{
			"q":     str("filter by summary keyword (optional)"),
			"limit": intp("return limit, default 50 (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 50
			}
			all, err := t.ts.ListByKind(db.KindIntent, 500)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Q))
			out := make([]map[string]any, 0, limit)
			for _, n := range all {
				switch n.State {
				case "running", "done", "exhausted", "blocked", "stopped": // has run → has a process
				default:
					continue
				}
				var p map[string]any
				_ = json.Unmarshal(n.Payload, &p)
				summary, _ := p["summary"].(string)
				if q != "" && !strings.Contains(strings.ToLower(summary), q) {
					continue
				}
				out = append(out, map[string]any{"intent_id": n.ID, "summary": summary, "state": n.State})
				if len(out) >= limit {
					break
				}
			}
			return jsonResult(map[string]any{"works": out})
		})
}

// PlannerTools is the read + intent-generation + goal-judgement tool set.
func (t *ToolSet) PlannerTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.listGoals(), t.addIntent(), t.proveGoal(), t.goalMet(),
		t.killWorkTool(), t.steerWorkTool(),
		// report_finding：规划态势研判时若自身已确证漏洞，可直接登记（与 worker 同工具）。
		t.addFinding(),
		// list_companies：查看企业列表 + scope + 资产数（拿 company_id / 理解归属范围）。
		t.listCompanies(),
		// 知识库：规划时检索评分规则/目标/通用方法论以校准探索意图。
		t.searchKnowledge(), t.listKnowledgeCategories(),
	}
}
