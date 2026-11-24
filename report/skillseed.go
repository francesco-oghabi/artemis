package report

// Seeds the editable report-generation skill on startup by materializing the
// built-in Go defaults (defaults.go) into files under <skillDir>/report-generation/.
// Only writes files that are MISSING, so user edits in the Skills page are never
// overwritten. This makes the built-in skeleton + prompts editable without ever
// requiring a hand-maintained copy: the Go defaults remain the single source, and
// this projects them to disk once so they can be tuned and hot-reloaded.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

var seedLocales = []string{"en-US"}

// SeedSkillFiles writes any missing report-generation skill files. Best-effort:
// returns the first write error but always attempts every file.
func SeedSkillFiles(skillDir string) error {
	if strings.TrimSpace(skillDir) == "" {
		return nil
	}
	base := filepath.Join(skillDir, reportSkillName)
	var firstErr error
	put := func(rel, content string) {
		if err := writeIfMissing(filepath.Join(base, rel), content); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	putJSON := func(rel string, v any) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		put(rel, string(b)+"\n")
	}

	put("SKILL.md", skillMD)
	put(filepath.Join("prompts", "report-level.tmpl"), promptReportLevelTmpl)
	put(filepath.Join("prompts", "vuln-narrative.tmpl"), promptVulnTmpl)

	for _, loc := range seedLocales {
		d := filepath.Join("skeleton", loc)
		putJSON(filepath.Join(d, "methodology.json"), map[string]any{
			"intro": methodologyIntro(loc), "phases": methodology(loc),
		})
		putJSON(filepath.Join(d, "tools.json"), tools(loc))
		putJSON(filepath.Join(d, "standards.json"), standards(loc))
		putJSON(filepath.Join(d, "checklist.json"), checklist(loc))
		putJSON(filepath.Join(d, "personnel.json"), defaultPersonnel(loc))
	}
	return firstErr
}

// writeIfMissing creates parent dirs and writes content only when path is absent.
func writeIfMissing(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // exists → keep user edits
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

const skillMD = `---
name: report-generation
description: Editable content for penetration test report generation: the AI-rewrite prompts and the fixed skeleton (methodology / test checklist / tools / reference standards / personnel), split into per-language files. The report engine reads from disk on every generation, so edits take effect immediately.
---

# Report Generation (Editable Content)

This skill holds the **editable content of the penetration test report**, read by the generation pipeline of "Report Management". After an edit, the **next generation takes effect immediately**, with no restart or recompilation needed; any missing or corrupt file automatically falls back to the built-in default.

## Structure

- ` + "`prompts/report-level.tmpl`" + ` : the AI prompt for the report-level narrative (background / service result / remediation conclusion / test items hit).
- ` + "`prompts/vuln-narrative.tmpl`" + ` : the AI prompt for rewriting a single vulnerability (description / reproduction steps / risk / remediation / CVSS).
- ` + "`skeleton/<language>/methodology.json`" + ` : 2.2 Testing Process: ` + "`{intro, phases:[{name,desc}]}`" + `.
- ` + "`skeleton/<language>/checklist.json`" + ` : 2.3 Test Checklist: ` + "`[{category,name,desc}]`" + `. Items the AI determines were hit render as "fail".
- ` + "`skeleton/<language>/tools.json`" + ` : 2.4 Testing Tools: ` + "`[{name,desc}]`" + `.
- ` + "`skeleton/<language>/standards.json`" + ` : 2.5 Reference Standards: ` + "`[\"...\"]`" + `.
- ` + "`skeleton/<language>/personnel.json`" + ` : 2.1 Tester defaults: ` + "`[{name,role,contact}]`" + ` (when the user fills them in under report settings, those take precedence).

Language directories: ` + "`zh-CN`" + ` (Simplified Chinese) / ` + "`zh-TW`" + ` (Traditional Chinese) / ` + "`en-US`" + ` (English).

## Prompt Template Variables

The prompts are Go ` + "`text/template`" + `, using ` + "`===USER===`" + ` to separate the system and user sections:

- Report-level: ` + "`{{.Company}}` `{{.Project}}` `{{.Client}}` `{{.FindingsList}}` `{{.LangDirective}}`" + `
- Vulnerability-level: ` + "`{{.Company}}` `{{.VulnClass}}` `{{.Severity}}` `{{.Summary}}` `{{.PoC}}` `{{.LangDirective}}`" + `

` + "`{{.LangDirective}}`" + ` injects the target-language directive (Simplified / Traditional / English), so the prompt itself is language-independent and a single copy is shared across all three languages.
`

const promptReportLevelTmpl = `You are a senior penetration test report writer at {{.Company}}, skilled at producing professional, client-readable, technically rigorous penetration test reports. Output ONLY strict JSON, with no markdown code fences.
===USER===
Write the summary/overview content of the report based on the project and vulnerability list below.

Project name: {{.Project}}
Client name: {{.Client}}
Vulnerability list:
{{.FindingsList}}
Requirements (professional delivery tone; avoid phrasing such as "this test was performed today"):
- background: array of strings, 2 paragraphs. The first states that the client commissioned {{.Company}} to carry out the penetration test and the testing objectives; the second describes the testing scope and the combined manual + tooling approach. 60-130 characters each.
- service_result: 1 paragraph summarizing which systems were tested and the number and severity distribution of the vulnerabilities found.
- remediation_conclusion: 1 paragraph remediation conclusion (for a first-round test, all findings default to pending remediation; recommend remediating promptly and retesting).
- checklist_hits: array of strings; infer the names of the standard test items hit from the vulnerability types (e.g. standard names such as "SQL Injection", "Unauthorized Access", "Authentication Bypass", "Sensitive Information Disclosure", "Command Injection", "Cross-Site Scripting (XSS)", "Vertical Privilege Escalation").

Output ONLY JSON: {"background":["...","..."],"service_result":"...","remediation_conclusion":"...","checklist_hits":["...","..."]}

Output language requirement: {{.LangDirective}}
`

const promptVulnTmpl = `You are a senior penetration test report writer at {{.Company}}. Rewrite the raw vulnerability records into DELIVERY-GRADE report body text: written as a senior consultant would write directly to the client, concise, professional, and to the point. Output ONLY strict JSON, with no markdown code fences, no pleasantries, disclaimers, or one-size-fits-all boilerplate. The original HTTP requests/commands/responses and similar must be preserved verbatim and must not be fabricated.
===USER===
Rewrite the vulnerability below into report body text. Core requirement: be CONCISE, SPECIFIC, and RESTRAINED. Better to omit than pad: do not inflate the count, do not add filler, do not state correct-but-useless truisms; every sentence must be real information about this specific target and this specific vulnerability.

Vulnerability type / original name: {{.VulnClass}}
Severity: {{.Severity}}
Original summary:
{{.Summary}}
Original reproduction steps / evidence:
{{.PoC}}

Field requirements:
- title: a standardized, professional vulnerability name (10-26 characters, e.g. "External-Account Authentication Bypass Leading to Admin Takeover"). If the original name is already standardized (including a CVE, etc.), keep it or lightly adjust it; do not copy the summary verbatim.
- target: the affected host or URL, extracted from the summary/evidence; leave an empty string when it cannot be determined.
- description: 1 paragraph, 2-3 sentences. State only three things: what the vulnerability is, where it occurs, and its root cause. Do not pile on OWASP categories, restate the fix, or add vague preamble.
- module: the functional module it belongs to (short, e.g. "External account login / unauthorized endpoint").
- risk_analysis: 2-4 items, one sentence each, each a concrete consequence this specific target and vulnerability can cause (who, can do what, obtains what data or privileges). Write less when there is no concrete consequence; avoid boilerplate such as "may affect system security".
- remediation: 2-4 items, one sentence each, concrete and actionable (which point to change, how to change it, what to validate). Avoid empty platitudes such as "raise security awareness" or "conduct regular security audits".
- CVSS 3.1: cvss_score (number), cvss_vector (e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), cvss_metrics (the eight English values, e.g. {"AV":"Network","AC":"Low","PR":"None","UI":"None","S":"Unchanged","C":"High","I":"High","A":"High"}).

Do not output test_process: the reproduction steps are generated directly by the platform from real evidence, so just return "test_process":[].

Output ONLY JSON: {"title":"...","target":"...","description":["..."],"module":"...","test_process":[],"risk_analysis":["..."],"remediation":["..."],"cvss_score":0,"cvss_vector":"...","cvss_metrics":{...}}

Output language requirement: {{.LangDirective}}
`
