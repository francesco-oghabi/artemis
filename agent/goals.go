package agent

import (
	"context"
	"encoding/json"
	"strings"

	"artemis/engine/agentcore"
	acperm "artemis/engine/permission"
	actool "artemis/engine/tool"
	"artemis/db"
)

// goalsDefaultTmpl is the built-in EDITABLE body (section [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `You are a penetration-testing goal decomposer. Your job is to identify from the user input the **final results to be achieved**, not to plan attack steps.

**Goal = a final deliverable/verifiable result**

**What is NOT a goal (must not be listed as a sub-goal)**:
- information gathering, reconnaissance, endpoint scanning
- vulnerability analysis and verification processes
- attack steps, exploitation techniques
- result-verification steps

**Decomposition principles**:
- the user describes only one final goal → output one
- there are multiple **mutually independent** final deliverables → list them separately
- for a goal that maps to a clear vulnerability class, annotate vulnclass; leave it empty for information-gathering/business-logic goals
- it is strictly forbidden to fabricate goals the user did not mention

Call set_goals to submit the result.`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a pentest task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// desc is the task's free-text description (background: target scope / number of flags / engagement notes, etc.).
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
func DecomposeGoals(ctx context.Context, c Config, goalText, desc string, emit func(db.Activity)) []GoalSpec {
	prov, err := c.NewProvider()
	if err != nil {
		return nil
	}
	var out struct {
		Goals []GoalSpec `json:"goals"`
	}
	captured := false
	seen := map[string]bool{}
	submitTool := actool.Build(actool.Spec{
		Name:        "set_goals",
		Description: "Submit the list of decomposed goals.",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"goals": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "properties": map[string]any{
					"text":      map[string]any{"type": "string", "description": "An independently verifiable goal"},
					"vulnclass": map[string]any{"type": "string", "description": "The corresponding vulnerability class (if clear), e.g. SQLi/IDOR; business-logic goals may be left empty"},
				}, "required": []string{"text"},
			}},
		}, "required": []string{"goals"}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			// Accumulate and dedup across calls instead of overwriting. The model may
			// call set_goals more than once within the decomposition turns, sometimes
			// splitting goals across calls or re-submitting a reduced list. Overwriting
			// let the LAST call win, which silently dropped breadth (e.g. a run that
			// first proposed auth-bypass + JWT, then only UNION + exposure, ended with
			// just 2 goals). Merging by normalized text keeps the full union.
			var call struct {
				Goals []GoalSpec `json:"goals"`
			}
			if json.Unmarshal(in, &call) == nil {
				for _, g := range call.Goals {
					key := strings.ToLower(strings.TrimSpace(g.Text))
					if key == "" || seen[key] {
						continue
					}
					seen[key] = true
					out.Goals = append(out.Goals, g)
				}
			}
			captured = true
			return actool.Text("ok"), nil
		},
	})
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{})
	userMsg := "Task goal:\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\nTask description (background information, may include target scope/number of flags/engagement notes; for reference only, do not fabricate anything not mentioned in it):\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  []actool.CoreTool{submitTool},
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		MaxTurns:               4,
	}, userMsg, captureEmit)
	if !captured {
		return nil
	}
	return out.Goals
}
