package report

// Strings for the Go side of the report pipeline: severity names, status words,
// and the deterministic fallback prose used when the LLM is unavailable. Fixed
// skeleton labels (chapter titles, table headers, etc.) live in
// pybuilder/report_builder.py's LABELS; here we only produce the text that Go
// assembles into the report JSON. This fork renders English-only reports.

import (
	"fmt"
	"strings"
	"time"
)

// normLocale canonicalizes any locale string to the single supported value.
// This fork is English-only, so every locale resolves to en-US.
func normLocale(l string) string { return "en-US" }

// ---- severity ----

var sevNames = map[string]string{
	"critical": "Critical",
	"high":     "High",
	"medium":   "Medium",
	"low":      "Low",
	"info":     "Info",
}

// severityName renders the English severity word for a canonical/raw severity.
func severityName(locale, sev string) string {
	if v, ok := sevNames[canonSeverity(sev)]; ok {
		return v
	}
	return sevNames["info"]
}

// ---- status / small words ----

func statusPending(locale string) string     { return "Pending" }
func statusRemarkFirst(locale string) string { return "First identified in this assessment" }
func defaultTargetName(locale string) string { return "Target System" }
func reportWord(locale string) string        { return "Penetration Test Report" }

// defaultReportTitle builds the fallback cover title "<project> <report word>".
// When project is empty it's just the report word.
func defaultReportTitle(locale, project string) string {
	project = strings.TrimSpace(project)
	if project == "" {
		return reportWord(locale)
	}
	return project + " " + reportWord(locale)
}
func clientDefault(locale string) string  { return "Client" }
func projectDefault(locale string) string { return "Penetration Testing Project" }
func moduleDash() string                  { return "—" }

// ---- composite formatters ----

// sectionSystemHeader renders a 3.x system section title, e.g.
// "3.1 example.com (example.com)".
func sectionSystemHeader(locale string, idx int, name, addr string) string {
	return fmt.Sprintf("3.%d %s (%s)", idx, name, addr)
}

// vulnObject renders a remediation-item object "Title (host)".
func vulnObject(locale, title, target string) string {
	if strings.TrimSpace(target) == "" {
		return title
	}
	return fmt.Sprintf("%s (%s)", title, target)
}

// localizedDate formats today's date in English.
func localizedDate(locale string) string {
	return time.Now().Format("January 2, 2006")
}

// ---- fallback prose (used only when the LLM is unavailable) ----

func fallbackBackground(locale, client, company, project string) string {
	return fmt.Sprintf("%s commissioned %s to perform a penetration test of the information systems related to %s. Security engineers simulated real-world attacker behaviour, combining manual testing with tooling to surface security risks from multiple angles and to provide hardening recommendations.", client, company, project)
}

// infoSeg / infoSegParen append an "info"-severity segment to a breakdown only
// when there are informational findings, so the enumerated counts reconcile with
// the total (which includes info). infoSegParen is the form used inside parentheses.
func infoSeg(locale string, info int) string {
	if info <= 0 {
		return ""
	}
	return fmt.Sprintf(", %d Info", info)
}
func infoSegParen(locale string, info int) string {
	if info <= 0 {
		return ""
	}
	return fmt.Sprintf(", %d Info", info)
}

func fallbackServiceResult(locale string, total, crit, high, med, low, info int) string {
	return fmt.Sprintf("A total of %d security issues were identified: %d Critical, %d High, %d Medium, %d Low%s.", total, crit, high, med, low, infoSeg(locale, info))
}

func fallbackRemediationConclusion(locale string) string {
	return "This was an initial penetration assessment; all identified issues are currently pending remediation. Remediation should follow the recommendations in this report, with retesting performed afterwards to confirm closure."
}

func fallbackFindingsIntro(locale, company string, crit, high, med, low, info int) string {
	return fmt.Sprintf("%s performed penetration testing against the target systems and identified %d Critical, %d High, %d Medium, %d Low%s findings, as detailed in the table below:", company, crit, high, med, low, infoSeg(locale, info))
}

// overallConclusion builds the chapter-5 overall conclusion sentence.
func overallConclusion(locale string, total, crit, high, med, low, info int, worst string) string {
	s := fmt.Sprintf("A total of %d security issues were identified (%d Critical, %d High, %d Medium, %d Low%s). The overall system security rating is \"%s\". ", total, crit, high, med, low, infoSegParen(locale, info), worst)
	if crit > 0 || high > 0 {
		s += fmt.Sprintf("The environment contains %d Critical and %d High findings; immediate remediation followed by retesting is strongly recommended.", crit, high)
	} else if med > 0 {
		s += "No Critical or High findings were identified; Medium findings should be remediated on schedule."
	} else {
		s += "The overall security posture is good; only low-risk or informational issues were found."
	}
	return s
}

// ---- AI output-language directive (injected into prompts) ----

// outputLangDirective tells the LLM which language to write all prose in.
func outputLangDirective(locale string) string {
	return "Write ALL narrative fields (background, description, risk_analysis, remediation, etc.) in professional, client-ready English. Keep the JSON keys in English exactly as specified."
}
