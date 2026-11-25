package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"artemis/engine/permission"
	actool "artemis/engine/tool"
	"artemis/agent"
)

// jsonResult marshals v to a JSON tool result.
func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// This file implements the P2 "cross-task orchestration tool set" (docs: benchmark orchestration §2 P2). These are host tools, which need
// access to the Manager (any task's Store), the Engine (pause), and the task-creation flow, so they live in the server layer.
// Read-type tools redirect the "existing per-task tools" to run against the target task's store (building a temporary ToolSet
// and calling its corresponding tool), reusing exactly the same logic; control-type tools (spawn/pause) call Manager/Engine directly.
// Like the traffic tools, they are seeded into the tools table and bound per agent (visible only when bound to the orchestration agent).

// hostTools is the runtime host-tool provider fed to ToolAugment: traffic tools
// (gated by capture) + cross-task orchestration tools + user-defined custom tools.
// The second return is the names of custom tools flagged `deferred` (schema
// withheld, routed via SearchExtraTools/ExecuteExtraTool). Per-agent binding still
// decides who actually sees any of them.
//
//nolint:unused // used as the hostTools provider in wireAgentAugment
func (s *Server) hostTools() ([]actool.CoreTool, map[string][]string) {
	tools := append(s.m.HostTools(), s.orchestrationTools()...)
	tools = append(tools, s.platformTools()...) // platform operation tools (create/edit skill/tool/MCP, for Auto)
	custom, err := s.customTools()
	if err != nil {
		log.Printf("[custom-tool] loading failed: %v", err)
		return tools, nil
	}
	tools = append(tools, custom...)
	// deferred custom tools → name -> its bound agent keys. ToolAugment turns a
	// name into a deferred entry only for agents it's actually bound to (so we don't
	// advertise a tool the per-agent binding will drop from the callable set).
	deferred := map[string][]string{}
	rows, _ := s.m.pg.ListCustomTools()
	for _, t := range rows {
		if t.Deferred && t.Enabled {
			deferred[t.Key] = t.Agents
		}
	}
	return tools, deferred
}

// orchestrationTools returns the cross-task tool set. Bound per-agent via the
// tools table (default: no binding — opt-in for orchestration agents).
func (s *Server) orchestrationTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListTasks(),
		s.toolListLLMProfiles(),
		s.toolSpawnTask(),
		s.toolPauseTask(),
		s.toolGetTaskGraph(),
		s.toolListTaskFindings(),
		s.toolAddHint(),
		s.toolGetWorkerTrace(),
		s.toolListWorkerTraces(),
		s.toolSearchWorkerTraces(),
	}
}

// --- schema helpers ---

func strParam(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// parseProfileID reads an LLM profile id from a tool arg that may arrive as a JSON
// number (5) or a numeric string ("5"); returns 0 when absent/unparseable.
func parseProfileID(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(str), 10, 64)
		return v
	}
	return 0
}

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		m["required"] = req
	}
	return m
}

func roTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func wrTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// delegateToTask resolves the `task_id` in the input, builds a ToolSet bound to
// that task's store, strips task_id, and calls the chosen per-task tool — so the
// cross-task read reuses the exact in-task logic against another task.
func (s *Server) delegateToTask(ctx context.Context, in json.RawMessage, pick func(*agent.ToolSet) actool.CoreTool) (actool.Result, error) {
	var head struct {
		TaskID string `json:"task_id"`
	}
	_ = json.Unmarshal(in, &head)
	if strings.TrimSpace(head.TaskID) == "" {
		return actool.Errorf("task_id è obbligatorio"), nil
	}
	t, ok := s.m.Task(head.TaskID)
	if !ok {
		return actool.Errorf("task non trovato: " + head.TaskID), nil
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(in, &m)
	delete(m, "task_id")
	inner, _ := json.Marshal(m)
	tsx := agent.NewToolSet(t.Store, "orchestrator")
	if s.m.Assets() != nil {
		tsx.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	}
	tsx.SetNotify(t.Notify) // hint writes wake this task's planner (no-op for read tools)
	return pick(tsx).Call(ctx, inner, nil)
}

// --- tools ---

func (s *Server) toolListTasks() actool.CoreTool {
	return roTool("list_tasks",
		"List all tasks (id/description/goal/status/run_seconds/parent task/LLM profile); the orchestration agent uses it to grasp the whole picture, see which tasks are stuck too long, and which LLM each one uses. run_seconds: running=created->now, terminal=created->last activity (seconds). llm_profile: the profile name used by the task's planner/worker, (active profile)=follows the global active one.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			lastAct, _ := s.m.PG().LastActivityAll()
			// id -> name to resolve each task's pinned LLM profile.
			profName := map[int64]string{}
			if profs, err := s.m.pg.ListProfiles(); err == nil {
				for _, p := range profs {
					profName[p.ID] = p.Name
				}
			}
			out := make([]map[string]any, 0)
			for _, t := range s.m.List() {
				status := s.deriveTaskStatus(t)
				end := lastAct[t.ExpID]
				if live := s.engine.LastActivity(t.ID); live > end {
					end = live
				}
				dur := int64(0)
				if status == "running" {
					dur = time.Now().Unix() - t.CreatedAt
				} else if end > t.CreatedAt {
					dur = end - t.CreatedAt
				}
				row := map[string]any{"id": t.ID, "description": t.Description, "goal": t.Goal, "status": status, "run_seconds": dur}
				if t.ParentRef != "" {
					row["parent_ref"] = t.ParentRef
				}
				if t.LLMProfileID == nil {
					row["llm_profile"] = "(active profile)"
				} else if n, ok := profName[*t.LLMProfileID]; ok {
					row["llm_profile"] = n
				} else {
					row["llm_profile"] = fmt.Sprintf("#%d(deleted)", *t.LLMProfileID)
				}
				out = append(out, row)
			}
			return jsonResult(out)
		})
}

// toolListLLMProfiles lists the available LLM profiles (name/model/active) so an
// orchestration agent can pick one for spawn_task's llm_profile. Never leaks keys.
func (s *Server) toolListLLMProfiles() actool.CoreTool {
	return roTool("list_llm_profiles",
		"List the available LLM profiles: id, name, model, format, and whether each is the currently active profile. Use the id for spawn_task's llm_profile_id parameter to assign a sub-task its own LLM (e.g. a cheap model for recon, a strong model for exploitation). Does not include the API Key.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			profs, err := s.m.pg.ListProfiles()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(profs))
			for _, p := range profs {
				out = append(out, map[string]any{
					"id": p.ID, "name": p.Name, "model": p.Model, "format": p.Format, "is_active": p.IsDefault,
				})
			}
			return jsonResult(map[string]any{"profiles": out})
		})
}

func (s *Server) toolSpawnTask() actool.CoreTool {
	return wrTool("spawn_task",
		"Create a new sub-task and start its exploration engine, returning task_id. Used to dispatch one thing (e.g. a challenge/a goal) as an independent task. parent_ref optional: supply the parent task id associated with the current orchestration to establish a parent-child link.",
		objSchema(map[string]any{
			"description":     strParam("task description (short title)"),
			"goal":            strParam("task goal (what to achieve)"),
			"parent_ref":      strParam("optional: parent task id (for parent-child linking)"),
			"llm_profile_id":  map[string]any{"type": "integer", "description": "optional: the LLM profile id to use for this sub-task's planner/worker (see list_llm_profiles); if left empty, inherits the parent task, then falls back to the global active profile"},
			"timeout_seconds": map[string]any{"type": "integer", "description": "optional: task-level timeout (seconds). When reached, triggers a graceful wind-down and enters the timeout terminal state; empty or 0 = no limit"},
		}, "description", "goal"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Description, Goal, ParentRef string
				LLMProfileID                 json.RawMessage `json:"llm_profile_id"`
				TimeoutSeconds               int             `json:"timeout_seconds"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Description) == "" {
				a.Description = "Task senza nome"
			}
			if strings.TrimSpace(a.Goal) == "" {
				return actool.Errorf("goal è obbligatorio"), nil
			}
			if a.TimeoutSeconds < 0 {
				a.TimeoutSeconds = 0
			}
			// LLM profile resolution: explicit id > inherit parent's pin > active(nil).
			var pin *int64
			if id := parseProfileID(a.LLMProfileID); id > 0 {
				if _, ok := s.loadProfileConfig(id); !ok {
					return actool.Errorf(fmt.Sprintf("configurazione LLM #%d non trovata o API Key non impostata", id)), nil
				}
				pin = &id
			} else if a.ParentRef != "" {
				if pt, ok := s.m.Task(a.ParentRef); ok {
					pin = pt.LLMProfileID
				}
			}
			t, err := s.m.CreateTask("", a.Description, a.Goal, "", pin, a.TimeoutSeconds)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.ParentRef != "" {
				t.ParentRef = a.ParentRef
				if id, e := strconv.ParseInt(t.ID, 10, 64); e == nil {
					_ = s.m.PG().SetParentRef(id, a.ParentRef)
				}
			}
			s.seed(t, a.Description+" "+a.Goal) // seed the initial assets, fed to the event-driven loop
			s.createGoals(s.ctx, t, nil)        // goal decomposition (LLM; rule-based fallback)
			s.engine.Run(s.ctx, t)              // start this task's exploration engine
			return actool.Text(fmt.Sprintf("task created: %s", t.ID)), nil
		})
}

func (s *Server) toolPauseTask() actool.CoreTool {
	return wrTool("pause_task", "Pause the given task (stop its planner/worker loop).",
		objSchema(map[string]any{"task_id": strParam("the id of the task to pause")}, "task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)
			if _, ok := s.m.Task(a.TaskID); !ok {
				return actool.Errorf("task non trovato: " + a.TaskID), nil
			}
			s.engine.Pause(a.TaskID)
			return actool.Text("task paused: " + a.TaskID), nil
		})
}

func (s *Server) toolGetTaskGraph() actool.CoreTool {
	return roTool("get_task_graph", "Read the given task's exploration graph overview (same as graph_overview: asset count/frontier/findings/coverage etc.); use task_id to specify the task.",
		objSchema(map[string]any{"task_id": strParam("task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GraphOverviewTool)
		})
}

func (s *Server) toolListTaskFindings() actool.CoreTool {
	return roTool("list_task_findings", "Read the given task's confirmed vulnerabilities (incl. flag/PoC; each carries id/task_id/intent_id/vulnclass/severity/summary/status); use task_id to specify the task.",
		objSchema(map[string]any{"task_id": strParam("task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListFindingsTool)
		})
}

func (s *Server) toolAddHint() actool.CoreTool {
	return wrTool("add_task_hint", "Inject a strategic hint into the given task (the task's planner reads it on its next round of intent generation).\n"+
		"★Prefer batching: put multiple hints into the hints array and submit in one call (returns an ids array, same length and order as hints, failed items id=0); for a single hint, omit hints and give the top-level text directly.",
		objSchema(map[string]any{
			"task_id":   strParam("task id"),
			"hints":     map[string]any{"type": "array", "description": "[Prefer this] hint array, each element has the same fields as the top level (text/asset_ids).", "items": map[string]any{"type": "object"}},
			"text":      strParam("[single] hint content"),
			"asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "anchored asset id (optional, 0/1/many; asset ids within this task)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).AddHintTool)
		})
}

func (s *Server) toolGetWorkerTrace() actool.CoreTool {
	return roTool("get_task_worker_trace",
		"View the execution process of a given work (intent) in the given task: get_task_worker_trace(task_id, intent_id) shows step summaries; then pass step_ids=[...] to fetch the full content of those steps (<=5 at a time).",
		objSchema(map[string]any{
			"task_id":   strParam("task id"),
			"intent_id": map[string]any{"type": "integer", "description": "intent id (a work within this task)"},
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "optional: step ids to fetch full content for (<=5)"},
		}, "task_id", "intent_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GetWorkerTraceTool)
		})
}

func (s *Server) toolListWorkerTraces() actool.CoreTool {
	return roTool("list_task_worker_traces", "List which works (intents) ran in the given task + each one's step count, to discover which works are worth reviewing (then use get_task_worker_trace).",
		objSchema(map[string]any{"task_id": strParam("task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListWorkerTracesTool)
		})
}

func (s *Server) toolSearchWorkerTraces() actool.CoreTool {
	return roTool("search_task_worker_traces", "Search all works' execution processes in the given task by keyword (returns matching step summaries + intent_id).",
		objSchema(map[string]any{"task_id": strParam("task id"), "q": strParam("search keyword")}, "task_id", "q"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).SearchWorkerTracesTool)
		})
}

// deriveTaskStatus mirrors listTasks' status derivation for the list_tasks tool.
func (s *Server) deriveTaskStatus(t *Task) string {
	switch {
	case isTerminalStatus(t.Status):
		return t.Status
	case t.Paused || s.engine.IsPaused(t.ID):
		return "paused"
	case s.engine.Ready() && s.engine.Started(t.ID):
		return "running"
	}
	return "created"
}

// orchestrationToolSeeds seeds the cross-task tools into the tools table so they
// are bindable per-agent (default: bound to nobody — opt-in for orchestration
// agents). First-insert only, like the traffic seeds.
func (s *Server) seedOrchestrationTools() {
	// task-op + platform tools default-bind to the built-in Auto agent (it is designed to
	// operate the platform). SeedTool takes effect on first insert; rows already seeded in an old DB are back-bound by seedAutoDefaultBindings.
	autoAgents, _ := json.Marshal([]string{"auto"})
	for _, t := range s.orchestrationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, autoAgents)
	}
	for _, t := range s.platformTools() {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, autoAgents)
	}
	s.refreshBuiltinToolSchemas()
	s.refreshReportFindingSchema() // add the reproduction structured-steps parameter -> push to old DBs, otherwise the agent can't see it
	s.seedAutoDefaultBindings()
	s.seedPlannerDefaultBindings()
	s.seedAutoReportFindingBinding()
	s.seedMainagentReportFindingBinding()
	s.reseedAgentPrompt("mainagent", "prompt_exposure_findings_mainagent_v1", "record exposure/info-leak findings + persist confirmed exposures when reviewing")
	s.reseedAgentPrompt("worker", "prompt_exposure_findings_worker_v1", "also record exposure/info-leak cases as findings")
	s.reseedAgentPrompt("pentest", "prompt_exposure_findings_pentest_v1", "also record exposure/info-leak cases as findings")
	// adapted from the autonomy prompt improvements in AntiFox 0.3.4-0.3.6 (fitted to our wording without a coverage subsystem):
	s.reseedAgentPrompt("planner", "prompt_zerointent_acceptance_v1", "rewrite of the zero-intent criteria (two kinds of valid justification) + quantified acceptance check (no early wrap-up before targets are met)")
	s.reseedAgentPrompt("worker", "prompt_negfact_threshold_v1", "evidence threshold for negative conclusions: mark everything inferred until means are exhausted, do not weld a direction shut with a hasty observed")
	// record reproduction steps in place: when confirming a vulnerability, fill the structured reproduction in report_finding (entry/prerequisites/ordered real steps/source).
	s.reseedAgentPrompt("worker", "prompt_reproduction_recipe_v1", "report_finding fills the structured reproduction process (recorded in place, requests verbatim and real)")
	s.reseedAgentPrompt("pentest", "prompt_reproduction_recipe_pentest_v1", "report_finding fills the structured reproduction process")
	s.reseedAgentPrompt("mainagent", "prompt_reproduction_recipe_mainagent_v1", "report_finding fills the structured reproduction process")
	s.bumpWorkerRunSecondsTo1200() // worker per-round wall clock 600->1200s (only the default when not customized; from AntiFox 0.3.3)
	// Note: pentest's default tool bindings need no migration, since BuiltinToolSeeds, on a fresh init, seeds
	// list_assets/insert_assets/report_finding/list_findings/list_companies together with
	// pentest (the project has no old DB yet, so no migration is done).
}

// refreshBuiltinToolSchemas propagates code schema/description changes on the
// orchestration + platform tools into already-seeded rows ONCE per version flag —
// SeedTool is first-insert-only, so a new param (e.g. spawn_task's llm_profile) never
// reaches an old DB otherwise. Preserves each tool's agent binding + enabled flag.
// Bump the flag whenever these tools' schemas/descriptions change in code.
func (s *Server) refreshBuiltinToolSchemas() {
	const flag = "tool_schema_refresh_v4_goal_met_desc"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := append(s.orchestrationTools(), s.platformTools()...)
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
			log.Printf("[tools] refresh %s schema failed: %v", t.Name(), err)
		}
	}
	// Also refresh the planner's goal_met description to the code default: the description seeded in old DBs carried the misleading phrase "end this planning round",
	// which made the planner treat goal_met as a way to "end an empty round" and misjudge the whole task as complete right after starting.
	for _, sd := range agent.BuiltinToolSeeds() {
		if sd.Key != "goal_met" {
			continue
		}
		schema, _ := json.Marshal(sd.Schema)
		if err := s.m.pg.RefreshToolDefaults(sd.Key, sd.Desc, schema); err != nil {
			log.Printf("[tools] refresh %s desc failed: %v", sd.Key, err)
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[tools] refreshed orchestration/platform tool schema to code defaults (one-time)")
}

// seedAutoReportFindingBinding adds "auto" to report_finding's binding ONCE so
// conversation-context agents can call it without requiring an intent_id.
func (s *Server) seedAutoReportFindingBinding() {
	const flag = "auto_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("auto", []string{"report_finding"}); err != nil {
		log.Printf("[auto] report_finding default binding failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerDefaultBindings adds "planner" to report_finding's binding ONCE
// (guarded by a settings flag), so existing DBs — whose report_finding row was
// seeded as worker-only — also let the planner record findings. Fresh DBs already
// get it via PlannerTools(); this only backfills without overriding a user unbind.
func (s *Server) seedPlannerDefaultBindings() {
	const flag = "planner_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"report_finding"}); err != nil {
		log.Printf("[planner] report_finding default binding failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedMainagentReportFindingBinding binds report_finding to the main Agent
// (mainagent) ONCE. Root-cause fix: the main agent synthesizes/confirms vulns in
// its orchestration conversation but, without this tool, could only READ findings
// (list_findings) — never record them — so its conclusions never became finding
// nodes (missing from the findings page / exploration graph / report). Guarded by a flag; won't re-add
// after a deliberate user unbind.
func (s *Server) seedMainagentReportFindingBinding() {
	const flag = "mainagent_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("mainagent", []string{"report_finding"}); err != nil {
		log.Printf("[mainagent] report_finding default binding failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[mainagent] default-bound report_finding (the main Agent can now record vulnerabilities)")
}

// bumpWorkerRunSecondsTo1200 raises the worker single-run wall-clock from the old
// 600s default to 1200s ONCE (guarded), for existing DBs. Only touches the untouched
// 600 default so a user-customized value is preserved. Fresh DBs already seed 1200.
// Runs inside seedOrchestrationTools (before applyLLM builds the worker), so the live
// worker picks up the new SetRunTimeout without a restart-after-migration.
func (s *Server) bumpWorkerRunSecondsTo1200() {
	const flag = "worker_run_seconds_1200_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if a, err := s.m.pg.GetAgentByKey("worker"); err == nil && a != nil && a.RunSecs == 600 {
		if err := s.m.pg.SetAgentRunSeconds("worker", 1200); err != nil {
			log.Printf("[worker] run_seconds 1200 migration failed: %v", err)
			return
		}
		log.Printf("[worker] single-run wall-clock default 600→1200s")
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// reseedAgentPrompt force-updates ONE agent's DB prompt to the current code default
// ONCE (guarded by a settings flag). DB prompt overrides the code default, so a code
// change alone won't reach existing DBs — this bumps it. Use a FRESH flag whenever the
// code default changes again. Runs before any user edit; won't clobber later user edits
// (the flag is set on first apply).
func (s *Server) reseedAgentPrompt(key, flag, note string) {
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	a, err := s.m.pg.GetAgentByKey(key)
	if err != nil || a == nil {
		return
	}
	tmpl, ok := agent.BuiltinPromptSeeds()[key]
	if !ok {
		return
	}
	// Fresh DBs just seeded this exact template as v1; appending an identical v2 is a
	// cosmetic duplicate in the version history. Skip the write when already current.
	if cur, _ := s.m.pg.CurrentPrompt(a.ID); cur == tmpl {
		_ = s.m.pg.SetSetting(flag, "true")
		return
	}
	if _, err := s.m.pg.SavePrompt(a.ID, tmpl, "System update: "+note, "system"); err != nil {
		log.Printf("[%s] prompt replay failed: %v", key, err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[%s] prompt updated (%s)", key, note)
}

// refreshReportFindingSchema pushes report_finding's CODE schema to the DB tools table
// ONCE (guarded). The runtime offers the DB-stored schema to the agent, and SeedTool is
// first-insert-only — so the newly-added structured `reproduction` param wouldn't reach
// existing DBs' agents without this. Won't clobber user param-default edits after the flag.
func (s *Server) refreshReportFindingSchema() {
	const flag = "tool_schema_refresh_report_finding_repro_v3" // v3: require each step to use a standard HTTP message (not curl), responses not abbreviated with ...
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, sd := range agent.BuiltinToolSeeds() {
		if sd.Key != "report_finding" {
			continue
		}
		schema, _ := json.Marshal(sd.Schema)
		if err := s.m.pg.RefreshToolDefaults(sd.Key, sd.Desc, schema); err != nil {
			log.Printf("[tools] refresh report_finding schema failed: %v", err)
			return
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[tools] refreshed report_finding schema (added structured reproduction parameter)")
}

// seedAutoDefaultBindings adds "auto" to the task-op + platform tools' bindings
// ONCE (guarded by a settings flag), so existing DBs whose tool rows were seeded
// before Auto existed still give Auto its default toolset — without re-adding it
// after a user deliberately unbinds.
func (s *Server) seedAutoDefaultBindings() {
	const flag = "auto_default_bindings_v3" // v3: replace old asset tool names, add insert_assets/add_company_scope
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	keys := make([]string, 0, len(platformToolKeys)+12)
	for _, t := range s.orchestrationTools() {
		keys = append(keys, t.Name())
	}
	keys = append(keys, platformToolKeys...)
	// asset tools: operating the Auto platform often needs to view/register assets and manage company scope.
	keys = append(keys, "insert_assets", "add_company_scope", "list_assets")
	if err := s.m.pg.AddAgentToToolBinding("auto", keys); err != nil {
		log.Printf("[auto] default binding failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
