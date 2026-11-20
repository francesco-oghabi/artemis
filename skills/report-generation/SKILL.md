---
name: report-generation
description: Editable content for penetration test report generation: AI rewrite prompts and fixed skeletons (methodology / test checklist / tools / reference standards / testers), split into separate files by language. The report engine reads from disk on every generation, so edits take effect immediately.
---

# Report Generation (Editable Content)

This skill holds the **editable content of penetration test reports**, consumed by the generation pipeline of "Report Management". Changes **take effect on the next generation**, with no restart or recompilation required; if any file is missing or corrupted, it automatically falls back to the built-in default.

## Structure

- `prompts/report-level.tmpl` — AI prompt for report-level narrative (background / service outcomes / remediation conclusion / matched test items).
- `prompts/vuln-narrative.tmpl` — AI prompt for rewriting a single vulnerability (description / reproduction steps / risk / fix / CVSS).
- `skeleton/<language>/methodology.json` — 2.2 Testing process: `{intro, phases:[{name,desc}]}`.
- `skeleton/<language>/checklist.json` — 2.3 Test checklist: `[{category,name,desc}]`. Items the AI judges as matched are rendered as "Failed".
- `skeleton/<language>/tools.json` — 2.4 Testing tools: `[{name,desc}]`.
- `skeleton/<language>/standards.json` — 2.5 Reference standards: `["..."]`.
- `skeleton/<language>/personnel.json` — 2.1 Default testers: `[{name,role,contact}]` (if the user fills this in the report settings, that takes precedence).

Language directories: `zh-CN` (Simplified Chinese) / `zh-TW` (Traditional Chinese) / `en-US` (English).

## Prompt Template Variables

Prompts are Go `text/template`, using `===USER===` to separate the system and user sections:

- Report level: `{{.Company}}` `{{.Project}}` `{{.Client}}` `{{.FindingsList}}` `{{.LangDirective}}`
- Vulnerability level: `{{.Company}}` `{{.VulnClass}}` `{{.Severity}}` `{{.Summary}}` `{{.PoC}}` `{{.LangDirective}}`

`{{.LangDirective}}` injects the target-language directive (Simplified / Traditional / English), so the prompt itself is language-independent and a single copy is shared across all three languages.
