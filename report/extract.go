package report

// Retroactive finding extraction: pull confirmed vulnerabilities out of a task's
// agent transcript (synthesis + worker conclusions) that were described but never
// recorded via report_finding — so they can be back-filled as finding nodes.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"artemis/db"
)

// ExtractedFinding is one vuln pulled from the transcript.
type ExtractedFinding struct {
	VulnClass string `json:"vulnclass"`
	Severity  string `json:"severity"` // high|medium|low
	Summary   string `json:"summary"`
	Target    string `json:"target"`
	Evidence  string `json:"evidence"`
}

const sysExtract = "You are a senior penetration testing expert. Extract the CONFIRMED vulnerabilities from the penetration test execution/summary records. Output ONLY strict JSON, with no markdown code fences. Evidence must preserve the real, original text from the records and must not be fabricated."

const userExtract = `From the penetration test execution and summary records below, extract every CONFIRMED vulnerability and every PROVEN exposure / information-disclosure risk (excluding unverified guesses and negative conclusions).

Already-recorded vulnerabilities (do NOT output these again):
%s
Execution / summary records:
%s

Requirements:
- One confirmed vulnerability per entry: vulnclass (vulnerability type/name, e.g. "Stored XSS", "Hardcoded Credentials", "Unauthorized Access"), severity (critical|high|medium|low; critical = can directly lead to full compromise of the system/data), summary (one-sentence summary including the affected object), target (affected host or URL), evidence (key PoC/request/command/response verbatim, preserving the real content).
- Only extract vulnerabilities/exposures that are **explicitly verified** in the records; do not repeat items semantically identical to those in the "already-recorded" list above.
- **Exposure / information-disclosure issues must also be extracted**: unauthorized-reachable sensitive/admin/debug endpoints, Swagger/API docs, exposed configuration or backup/source code, sensitive-data leaks, etc. that were actually accessed with response evidence in the records; set severity by sensitivity (general information disclosure = low, unauthorized-reachable sensitive/admin endpoint = medium, account takeover or obtaining credentials/keys = high). Still exclude pure speculation (version/CVE matching, "looks injectable"); the mere existence of an endpoint with no unauthorized exposure does not count.
- If there are no new vulnerabilities/exposures, output an empty findings array.

Output ONLY JSON: {"findings":[{"vulnclass":"...","severity":"high","summary":"...","target":"...","evidence":"..."}]}`

// ExtractFindings asks the active LLM to extract confirmed vulns from the
// transcript, excluding ones already recorded (passed as short labels).
func ExtractFindings(ctx context.Context, pg *db.DB, transcript string, existing []string) ([]ExtractedFinding, error) {
	if strings.TrimSpace(transcript) == "" {
		return nil, fmt.Errorf("no session records available to analyze")
	}
	var ex strings.Builder
	for _, e := range existing {
		ex.WriteString("- ")
		ex.WriteString(e)
		ex.WriteString("\n")
	}
	if ex.Len() == 0 {
		ex.WriteString("(none)\n")
	}
	raw, err := complete(ctx, pg, sysExtract, fmt.Sprintf(userExtract, ex.String(), transcript), 4000)
	if err != nil {
		return nil, err
	}
	var out struct {
		Findings []ExtractedFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("failed to parse AI output")
	}
	return out.Findings, nil
}
