package report

// AI narrative layer: turns thin findings ({vulnclass, severity, summary, poc})
// into professional, client-ready report prose (description / test process / risk /
// remediation + CVSS) via the platform's active LLM profile. Report-level and
// per-finding calls run concurrently. All AI output is JSON; parse failures fall
// back to the raw finding fields (assembly in build.go), so generation never
// hard-fails on a bad LLM response.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"artemis/agent"
	"artemis/db"
	"artemis/engine/agentcore"
	acperm "artemis/engine/permission"
	actool "artemis/engine/tool"
)

// complete runs one system+user → text completion on the active LLM profile.
// Returns an error when no profile is configured (caller falls back to skeleton).
func complete(ctx context.Context, pg *db.DB, system, user string, maxTokens int) (string, error) {
	// The report/enrichment role can be bound to a specific LLM (role separation); when
	// unbound it uses the globally active one. This lets enrichment run on a stronger
	// model (e.g. Claude) without touching the pentest agent's model.
	p, err := pg.ReportRoleProfile()
	if err != nil || p == nil || strings.TrimSpace(p.APIKey) == "" {
		return "", fmt.Errorf("no active LLM profile")
	}
	cfg := agent.ConfigFrom(p.Format, p.Model, p.BaseURL, p.APIKey, p.Proxy)
	cfg.RatePerSecond, cfg.RatePerMinute = p.RatePerSecond, p.RatePerMinute
	cfg.ReasoningEffort = p.ReasoningEffort
	prov, err := cfg.NewProvider()
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	out, err := agentcore.Run(cctx, agentcore.Options{
		Provider:       prov,
		SystemPrompt:   []string{system},
		Tools:          []actool.CoreTool{}, // non-nil empty → no default tools offered
		PermissionMode: acperm.ModeBypass,
		MaxTurns:       1,
		MaxTokens:      maxTokens,
	}, user)
	if err != nil {
		return "", err
	}
	return cleanJSON(out), nil
}

// ---------------------------------------------------------------------------
// Report-level narrative (background / service result / remediation / checklist)
// ---------------------------------------------------------------------------

type reportLevelOut struct {
	Background            []string `json:"background"`
	ServiceResult         string   `json:"service_result"`
	RemediationConclusion string   `json:"remediation_conclusion"`
	ChecklistHits         []string `json:"checklist_hits"`
}

const sysReportLevel = "You are a senior penetration test report writer at %s, skilled at producing professional, client-readable, technically rigorous penetration test reports. Output ONLY strict JSON, with no markdown code fences."

const userReportLevel = `Write the summary/overview content of the report based on the project and vulnerability list below.

Project name: %s
Client name: %s
Vulnerability list:
%s
Requirements (professional delivery tone; avoid phrasing such as "this test was performed today"):
- background: array of strings, 2 paragraphs. The first states that the client commissioned %s to carry out the penetration test and the testing objectives; the second describes the testing scope and the combined manual + tooling approach. 60-130 characters each.
- service_result: 1 paragraph summarizing which systems were tested and the number and severity distribution of the vulnerabilities found.
- remediation_conclusion: 1 paragraph remediation conclusion (for a first-round test, all findings default to pending remediation; recommend remediating promptly and retesting).
- checklist_hits: array of strings; infer the names of the standard test items hit from the vulnerability types (e.g. standard names such as "SQL Injection", "Unauthorized Access", "Authentication Bypass", "Sensitive Information Disclosure", "Command Injection", "Cross-Site Scripting (XSS)", "Vertical Privilege Escalation").

Output ONLY JSON: {"background":["...","..."],"service_result":"...","remediation_conclusion":"...","checklist_hits":["...","..."]}`

// reportLevelPromptData feeds the editable report-level prompt template.
type reportLevelPromptData struct {
	Company, Project, Client, FindingsList, LangDirective string
}

// vulnPromptData feeds the editable per-vuln prompt template.
type vulnPromptData struct {
	Company, VulnClass, Severity, Summary, PoC, LangDirective string
}

func aiReportLevel(ctx context.Context, pg *db.DB, in *GenInput, sk *skillContent) reportLevelOut {
	var out reportLevelOut
	loc := normLocale(in.Locale)
	var sb strings.Builder
	// Feed the full testing scope / target systems to the narrative as context (via the
	// FindingsList channel, carried by both the skill and fallback prompt paths), so the
	// overview can name specific systems while the cover project name stays short
	// (ProjectName) and unaffected.
	if sc := strings.TrimSpace(in.Scope); sc != "" {
		fmt.Fprintf(&sb, "[Testing Scope / Target Systems] %s\n\n[Vulnerability List]\n", truncateRune(sc, 1500))
	}
	for _, f := range in.Findings {
		fmt.Fprintf(&sb, "- [%s] %s: %s\n", severityName(loc, f.Severity), nz(f.VulnClass, "-"), truncateRune(f.Summary, 80))
	}
	dir := outputLangDirective(loc)
	data := reportLevelPromptData{Company: in.CompanyName, Project: in.ProjectName, Client: in.ClientName, FindingsList: sb.String(), LangDirective: dir}
	sys := renderPrompt(sk.reportLevelSys, data)
	if sys == "" {
		sys = fmt.Sprintf(sysReportLevel, in.CompanyName)
	}
	user := renderPrompt(sk.reportLevelUser, data)
	if user == "" {
		user = fmt.Sprintf(userReportLevel, in.ProjectName, in.ClientName, sb.String(), in.CompanyName) +
			"\n\nOutput language requirement: " + dir
	}
	raw, err := complete(ctx, pg, sys, user, 4000)
	if err != nil {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// ---------------------------------------------------------------------------
// Per-finding narrative (description / test process / risk / remediation / CVSS)
// ---------------------------------------------------------------------------

type Enrichment struct {
	Title        string            `json:"title"`  // concise professional vuln name
	Target       string            `json:"target"` // affected host / URL, extracted from evidence
	Description  []string          `json:"description"`
	Module       string            `json:"module"`
	TestProcess  []procBlock       `json:"test_process"`
	RiskAnalysis []string          `json:"risk_analysis"`
	Remediation  []string          `json:"remediation"`
	CVSSScore    float64           `json:"cvss_score"`
	CVSSVector   string            `json:"cvss_vector"`
	CVSSMetrics  map[string]string `json:"cvss_metrics"`
}

const sysVuln = "You are a senior penetration test report writer at %s. Rewrite the raw vulnerability records into DELIVERY-GRADE report body text: written as a senior consultant would write directly to the client, concise, professional, and to the point. Output ONLY strict JSON, with no markdown code fences, no pleasantries, disclaimers, or boilerplate. The original HTTP requests/commands/responses and similar must be preserved verbatim and must not be fabricated."

const userVuln = `Rewrite the vulnerability below into report body text. Core requirement: be CONCISE, SPECIFIC, and RESTRAINED. Better to omit than pad: do not inflate the count, do not add filler, do not state correct-but-useless truisms; every sentence must be real information about this specific target and this specific vulnerability.

Vulnerability type / original name: %s
Severity: %s
Original summary:
%s
Original reproduction steps / evidence:
%s

Field requirements:
- title: a standardized, professional vulnerability name (10-26 characters). If the original name is already standardized (including a CVE, etc.), keep it or lightly adjust it; do not copy the summary verbatim.
- target: the affected host or URL, extracted from the summary/evidence; leave an empty string when it cannot be determined.
- description: 1 paragraph of 2-3 sentences stating only what the vulnerability is, where it occurs, and its root cause. Do not pile on OWASP categories, restate the fix, or add vague preamble.
- module: the functional module it belongs to (short, e.g. "External account login / unauthorized endpoint").
- risk_analysis: 2-4 items, one sentence each, each a concrete consequence for this specific target and vulnerability (who, can do what, obtains what data or privileges); no boilerplate.
- remediation: 2-4 items, one sentence each, concrete and actionable (which point to change, how to change it, what to validate); no empty platitudes.
- CVSS 3.1: cvss_score (number), cvss_vector (e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), cvss_metrics (the eight English values).

Do not output test_process: the reproduction steps are generated directly by the platform from real evidence, so just return "test_process":[].

Output ONLY JSON: {"title":"...","target":"...","description":["..."],"module":"...","test_process":[],"risk_analysis":["..."],"remediation":["..."],"cvss_score":0,"cvss_vector":"...","cvss_metrics":{...}}`

func aiVulnNarrative(ctx context.Context, pg *db.DB, locale string, f FindingInput, companyName string, sk *skillContent) Enrichment {
	var out Enrichment
	loc := normLocale(locale)
	dir := outputLangDirective(loc)
	data := vulnPromptData{Company: companyName, VulnClass: nz(f.VulnClass, "-"), Severity: severityName(loc, f.Severity), Summary: nz(f.Summary, "-"), PoC: nz(f.PoC, "-"), LangDirective: dir}
	sys := renderPrompt(sk.vulnSys, data)
	if sys == "" {
		sys = fmt.Sprintf(sysVuln, companyName)
	}
	user := renderPrompt(sk.vulnUser, data)
	if user == "" {
		user = fmt.Sprintf(userVuln,
			nz(f.VulnClass, "-"), severityName(loc, f.Severity), nz(f.Summary, "-"), nz(f.PoC, "-")) +
			"\n\nOutput language requirement: " + dir
	}
	// Ground the PROSE (description / risk / remediation) in the ACTUAL work transcript
	// (real tool calls / requests / responses / analysis recorded when the finding was
	// made) so it reflects what actually happened, not an expansion of the one-liner.
	if tr := strings.TrimSpace(f.Transcript); tr != "" {
		user += "\n\n=== REAL WORK TRANSCRIPT from when this vulnerability was found (tool calls/requests/responses/analysis) ===\n" +
			"Write description/risk_analysis based on the real phenomena in the transcript; do not fabricate or speculate about anything not present in it.\n\n" + tr
	}
	// PROSE-ONLY, ALWAYS. We never ask the model to reconstruct a verbatim test_process:
	// that large generation is slow and unreliable (many models time out / return nothing
	// on it) AND risks fabricating a PoC (the user's key pain). Instead test_process is
	// filled DETERMINISTICALLY below from REAL evidence: the agent's in-situ reproduction
	// steps if present, else the raw PoC. The model only writes prose (title/desc/module/risk/
	// remediation/CVSS), which is small, fast, and reliable on any model.
	if len(f.Reproduction) > 2 { // ""/"{}" carry nothing
		user += "\n\n=== Reproduction steps already recorded in situ by the test engine ===\n" +
			"This vulnerability's entry point/prerequisites/steps/provenance were recorded in situ during testing and will be used directly as the report's 'Testing Process'. You do NOT need to and must NOT reconstruct test_process; just return \"test_process\":[]."
	} else {
		user += "\n\n=== test_process provided directly from real evidence ===\n" +
			"The 'Testing Process' will be generated directly by the platform from the REAL PoC/evidence text; you do NOT need to and must NOT reconstruct or fabricate test_process; just return \"test_process\":[]."
	}
	user += "Focus on writing title / description / module / risk_analysis / remediation and CVSS solidly and professionally, based on the summary above and the real phenomena in the transcript; do not fabricate anything not present in the transcript."
	raw, err := complete(ctx, pg, sys, user, 4000)
	if err != nil {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	// Fill test_process from REAL evidence, never the model's reconstruction: the agent's
	// in-situ reproduction steps win; else the raw PoC (deterministic). This makes every consumer
	// (persisted enrichment → findings page UI, and the report) show real, non-fabricated
	// steps — and keeps the generation prose-only (small, reliable).
	if b := reproToBlocks(f.Reproduction, loc, nil); len(b) > 0 {
		out.TestProcess = b
	} else if len(out.TestProcess) == 0 && strings.TrimSpace(f.PoC) != "" {
		out.TestProcess = proofToBlocks(f.PoC)
	}
	return out
}

// EnrichFinding is the exported per-finding AI enrichment, shared by the report
// pipeline and the findings-management "AI analysis" endpoint. locale controls the
// output language (English in this fork); skillDir enables the editable
// report-generation prompt (falls back to the built-in prompt when unset/missing).
// Returns a zero Enrichment (not an error) when no LLM profile is configured —
// callers keep whatever raw fields the finding already has.
func EnrichFinding(ctx context.Context, pg *db.DB, skillDir, locale string, f FindingInput, companyName string) Enrichment {
	if strings.TrimSpace(companyName) == "" {
		companyName = "Security Services Team"
	}
	sk := loadSkillContent(skillDir, locale)
	return aiVulnNarrative(ctx, pg, locale, f, companyName, sk)
}

// cleanJSON strips markdown fences and surrounding prose from an LLM response.
func cleanJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			s = s[i : j+1] // strip leading AND trailing prose around the JSON object
		}
	}
	return s
}
