package agent

import (
	"strings"

	"artemis/engine/harness"
)

// Wrap-up / settlement prompt: when an agent is terminated due to [step budget
// exhausted (MaxTurns)] or [timeout (run_seconds/MaxDuration)], the SDK's settlement
// phase injects this prompt so the agent first persists what it has identified but not
// yet written back, then outputs a one-sentence summary, avoiding a botched ending.
//
// Each agent's wrap-up prompt can be overridden as needed in the admin UI (stored in
// agents.wrapup_prompt); leave it blank to use the built-in default here. Only [the prompt
// body] is editable; which tools are disabled and how many turns the wrap-up itself gets are code-fixed policy.

// WrapupOverride, if set, returns the stored wrap-up prompt for an agent key and
// whether a non-empty one exists. Wired by the server to the agents table (like
// PromptOverride for system prompts). nil / empty → the built-in default is used.
var WrapupOverride func(agentKey string) (string, bool)

// WrapupMaxTurnsOverride, if set, returns the admin-configured turn budget for the
// wrap-up phase of an agent and whether a positive one exists. Wired to the agents
// table. nil / ≤0 → the built-in per-agent default (wrapupTurnDefaults) is used.
var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

// Built-in default wrap-up prompts, indexed by agent key. worker reuses the historically
// hardcoded settleWrapUpPrompt (defined in worker.go); planner/mainagent each have their own;
// an unmatched key (a custom agent) falls back to the generic default.
var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

// wrapupTurnDefaults: the built-in default turn budget for each agent's [own] wrap-up phase
// (can be overridden by a >0 value in the admin UI). worker's write-back may take a few turns
// (record_fact/insert_assets), so it gets 4; the rest get 5. An unmatched key uses genericWrapupTurns.
var wrapupTurnDefaults = map[string]int{
	"worker":    4,
	"planner":   5,
	"mainagent": 5,
}

const genericWrapupTurns = 5

const plannerWrapUpDefault = "Your planning step budget for this round is about to run out. Note that only [this round] is ending: the system will wake you again as the situation changes to continue planning, this is not the end of the task, and you do not need to wrap up the entire plan here. Land the conclusions you have already thought through this round so it doesn't go to waste, but also [do not force intents just to wrap up] (0 intents this round is still a perfectly normal result): (1) if you have already identified exploration directions that [should be dispatched right now], submit them in one batch with add_intent (don't hold back what you've worked out); (2) for goals already proven met by some finding/fact, call prove_goal to mark them met (don't miss any); (3) if you identify a serial exploitation chain that needs to be split into steps, record it with TodoWrite so the next wake-up can keep dispatching. When done, end this round directly, no need to output a summary text."

const mainAgentWrapUpDefault = "Your step budget is about to run out and this interaction is about to end. Do not start any new exploration/operations. Please **use a single plain-text sentence on its own** to summarize for the user the current progress, the key conclusions, and the suggested next step."

const genericWrapUpDefault = "You are about to be terminated because your budget is exhausted. First write back any completed results that have not yet been persisted, then **use a single plain-text sentence on its own** to summarize what you did and which key conclusions you reached (this sentence will be shown as the result of this run)."

// WrapupDefault returns the built-in default wrap-up prompt for an agent key —
// used by the admin UI as the "restore default" value and empty-field placeholder.
func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

// WrapupTurnsDefault returns the built-in wrap-up turn budget for an agent key —
// used by the admin UI as the "0 = default N" hint.
func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

// resolveWrapup returns the effective wrap-up prompt: the DB override (if set and
// non-empty) over the built-in default.
func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

// resolveWrapupTurns returns the effective wrap-up turn budget: a positive DB
// override over the built-in per-agent default.
func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

// wrapupSettlement builds the settlement config for an agent's run. Prompt and the
// turn budget are admin-editable per agent; disabled tools are code-owned policy so
// a user can't edit away the "stop probing" guardrail. Resolved fresh each run
// (reads DB live), so edits apply on the next run without a restart.
func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        resolveWrapup(agentKey),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

// ---------- Task-level timeout wrap-up text (see docs/task-level-timeout-and-wrapup-design.md) ----------
//
// This is a [separate set] from the per-run wrap-up text: per-run means "the budget for this
// one run of yours is used up"; task timeout means "the whole task has hit its deadline and is
// about to end". The semantics are often opposite (especially for planner: per-run says "don't
// stop, keep planning", task timeout says "the deadline is reached, stop planning and make the
// final judgment"). Configured only for worker/planner.

// WrapupTaskTimeoutOverride / …TurnsOverride: DB overrides for the task-timeout wrap-up text and
// turn count (wired to agents.task_timeout_wrapup_prompt / _max_turns, worker/planner only).
var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "**The entire task has reached its timeout limit and is about to end** (this is not the budget of this run of yours, the whole exploration has hit its deadline). This is the last chance: (1) persist [all] of the content you have identified but not yet written back: new assets with insert_assets, exploration conclusions/facts with record_fact, confirmed vulnerabilities with report_finding; (2) do not start any new commands/probes; (3) **finally, in a single plain-text sentence on its own**, summarize your key conclusions on this intent."

const plannerTaskTimeoutDefault = "**The entire task has reached its timeout limit and is about to end** (this is not just this round, the entire task is terminating). Based on [all] of the current facts and findings, make a final goal assessment: for goals already proven met by evidence, call prove_goal to mark them met (don't miss any). **Do not generate any new intents** (intents dispatched now would no longer be executed). Once the assessment is done, wrap up; no need to output a summary text."

// TaskTimeoutWrapupDefault returns an agent's built-in default task-timeout wrap-up text (for the admin UI placeholder / restore-default).
func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey] // not configured (mainagent/chat) returns an empty string
}

// resolveTaskTimeoutWrapup: DB override (non-empty) > built-in default. An empty string means
// this agent has no task-timeout text (not worker/planner); the caller should then fall back to the per-run text.
func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey) // defaults to reusing the per-run turn count
}

// wrapupSettlementForTask builds settlement for a worker/planner run that is aware
// of the task deadline. See §5 of the design doc:
//   - clamped=true  -> this run is clamped by the task deadline: wrap-up due to Timeout = task hit
//     its deadline -> task-timeout text; wrap-up due to MaxTurns = steps within the clamped window
//     ran out first while the task still has a few minutes left -> fall back to the per-run text.
//   - clamped=false -> the task is still far off: both reasons use the per-run text (i.e. it degrades to wrapupSettlement).
//
// The PromptByReason handed to the harness picks on the spot by the [actual] reason at wrap-up time, so there is no mismatch at build time.
func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := resolveWrapup(agentKey)
	st := &harness.Settlement{
		Prompt:        perRun, // fallback (also the value both reasons take when not clamped)
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  tt,     // task hit its deadline
				harness.ReasonMaxTurns: perRun, // steps ran out first while the task still has time left
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}
