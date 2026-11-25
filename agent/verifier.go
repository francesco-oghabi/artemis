package agent

import (
	"context"
	"encoding/json"
	"strings"

	"artemis/db"
	"artemis/engine/agentcore"
	acperm "artemis/engine/permission"
	actool "artemis/engine/tool"
)

// VerifierVars are the template vars for the verifier prompt (none today).
type VerifierVars struct{}

// verifierDefaultTmpl is the built-in EDITABLE body of the independent-verifier
// prompt, seeded into agent_prompts. This Phase-1 verifier adjudicates a finding
// from its RECORDED evidence only: it does not re-test the target live (that is a
// later phase). Its job is to catch findings whose evidence does not actually meet
// the bar for their class, while preserving anything plausible.
const verifierDefaultTmpl = `You are an INDEPENDENT, skeptical verifier in an authorized penetration-testing system. A worker has reported a finding. Your job is to judge, from the recorded evidence alone, whether that evidence actually proves the vulnerability for its class. You cannot create findings and you cannot re-test the target; you only adjudicate what is already recorded.

You are adversarial toward the claim, not toward the target: assume the finding is NOT real until its own evidence proves it, but never invent a reason to reject.

Per-class evidence bar (what the evidence must actually show):
- SQL injection: a concrete differential or extraction (an auth bypass that returned a session/token, a UNION/stacked result with real rows, or a clearly injection-induced error), not merely "the parameter looks injectable".
- XSS (reflected/DOM/stored): evidence of actual script execution or an unmistakable execution sink, not just reflected input in a response body.
- IDOR / access control: another principal's data actually retrieved, or an action that should have been denied returning success, with the two identities distinguishable.
- JWT / auth: a forged or manipulated token actually accepted on a protected call, not just a decoded token.
- Mass assignment: a privileged field actually accepted and reflected back (e.g. role=admin on the created object).
- Open redirect: an off-site redirect actually issued (3xx Location to an attacker host) from a user-controlled parameter.
- Path traversal / exposure: the sensitive file/endpoint actually reached with a response proving exposure (content or listing), not just a 404/401.
- Business logic: the abusive state actually persisted (e.g. a negative quantity/price accepted), with a baseline for contrast.
- Security misconfiguration (missing CSP, verbose errors, etc.): the response actually shows the missing control or the leak.
Information-only observations (something merely "exists") are not vulnerabilities.

Decision rule (critical):
- Emit "exploit-proven" when the evidence shows a real, reproduced exploitation for the class.
- Emit "verified" when the evidence clearly meets the class bar above, even if not a full exploit chain.
- Emit "rejected" ONLY when the evidence POSITIVELY contradicts the claim or plainly fails the class bar (e.g. a "SQLi" whose only evidence is a generic 500, an "XSS" that is only reflected text, a "finding" that is just an endpoint existing). Rejecting means you are confident it is not demonstrated.
- Emit "needs-manual-verification" when the evidence is thin, ambiguous, or you cannot tell from what is recorded. Never reject on uncertainty: preserve the finding for a human. Irreproducible or inconclusive is always "needs-manual-verification", never "rejected".

Call set_verdict exactly once with the verdict, a one-sentence reason grounded in the recorded evidence, and (optionally) the single most decisive piece of evidence you relied on.`

// Verdict is the independent verifier's adjudication of one finding.
type Verdict struct {
	// Status is one of the VerdictStatus* values below.
	Status string
	// Reason is a one-sentence justification grounded in the recorded evidence.
	Reason string
	// Evidence is the single most decisive piece the verifier relied on (optional).
	Evidence string
}

// Verdict status values written to findings.verdict.
const (
	VerdictUnverified  = "unverified"
	VerdictExploit     = "exploit-proven"
	VerdictVerified    = "verified"
	VerdictNeedsManual = "needs-manual-verification"
	VerdictRejected    = "rejected"
)

// validVerdict maps a model-supplied status to a canonical value, or "" if unknown.
func validVerdict(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case VerdictExploit, "exploit", "exploit_proven", "exploitproven":
		return VerdictExploit
	case VerdictVerified, "verify", "confirmed":
		return VerdictVerified
	case VerdictRejected, "reject", "false-positive", "false_positive":
		return VerdictRejected
	case VerdictNeedsManual, "needs-manual", "needs_manual", "manual", "inconclusive":
		return VerdictNeedsManual
	default:
		return ""
	}
}

// VerifyInput is the recorded finding handed to the verifier.
type VerifyInput struct {
	VulnClass    string
	Severity     string
	Summary      string
	Evidence     string
	Reproduction json.RawMessage // optional structured recipe; may be nil/empty
}

// VerifyFinding runs the independent verifier over one finding's recorded evidence
// and returns its adjudication. The bool is false when no provider is configured or
// the model produced no verdict (the caller should then leave the finding
// "unverified" rather than treat silence as a rejection).
//
// emit, when non-nil, receives every LLM step (Worker="verifier") for UI visibility.
func VerifyFinding(ctx context.Context, c Config, in VerifyInput, emit func(db.Activity)) (Verdict, bool) {
	prov, err := c.NewProvider()
	if err != nil {
		return Verdict{}, false
	}
	var out Verdict
	captured := false
	submitTool := actool.Build(actool.Spec{
		Name:        "set_verdict",
		Description: "Submit your adjudication of the finding.",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"verdict": map[string]any{"type": "string", "description": "one of: exploit-proven | verified | needs-manual-verification | rejected"},
			"reason":  map[string]any{"type": "string", "description": "one-sentence justification grounded in the recorded evidence"},
			"evidence": map[string]any{"type": "string", "description": "the single most decisive piece of recorded evidence you relied on (optional)"},
		}, "required": []string{"verdict", "reason"}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, raw json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var call struct {
				Verdict  string `json:"verdict"`
				Reason   string `json:"reason"`
				Evidence string `json:"evidence"`
			}
			if json.Unmarshal(raw, &call) == nil {
				if v := validVerdict(call.Verdict); v != "" {
					out.Status = v
					out.Reason = strings.TrimSpace(call.Reason)
					out.Evidence = strings.TrimSpace(call.Evidence)
					captured = true
				}
			}
			return actool.Text("ok"), nil
		},
	})

	sys := renderSystem("verifier", verifierDefaultTmpl, VerifierVars{})
	var b strings.Builder
	b.WriteString("Finding to adjudicate:\n")
	b.WriteString("- vulnerability class: " + strings.TrimSpace(in.VulnClass) + "\n")
	b.WriteString("- severity: " + strings.TrimSpace(in.Severity) + "\n")
	b.WriteString("- summary: " + strings.TrimSpace(in.Summary) + "\n")
	if e := strings.TrimSpace(in.Evidence); e != "" {
		b.WriteString("- recorded evidence / PoC:\n" + e + "\n")
	} else {
		b.WriteString("- recorded evidence / PoC: (none recorded)\n")
	}
	if r := strings.TrimSpace(string(in.Reproduction)); r != "" && r != "{}" && r != "null" {
		b.WriteString("- structured reproduction:\n" + r + "\n")
	}
	userMsg := b.String()

	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "verifier"
			emit(r)
		}
	}
	// Greedy (temperature 0): the verdict is a one-shot structured judgment where
	// determinism is what we want, same rationale as goal decomposition.
	greedyTemp := 0.0
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  []actool.CoreTool{submitTool},
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		MaxTurns:               3,
		Temperature:            &greedyTemp,
	}, userMsg, captureEmit)
	if !captured {
		return Verdict{}, false
	}
	return out, true
}
