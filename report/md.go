package report

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"artemis/db"
)

// mdLeadNumRe strips the DOCX-style chapter-number prefix (e.g. "3.1 ") from a system title;
// the MD is a standalone deliverable and numbers itself from 1.
var mdLeadNumRe = regexp.MustCompile(`^\d+(\.\d+)*\s+`)

// BuildMarkdown generates the delivery-standard Markdown report body plus the list of
// accompanying evidence images (relative name -> source disk path). The layout mirrors a
// human deliverable: info header -> grouped by target -> each vulnerability (attribute
// table + 7 numbered subsections) -> footer. Evidence images are referenced by the relative
// path assets/<name> and packed into the same zip by GenerateMarkdownFile (no longer
// base64-embedded, keeping the .md clean, small, directly editable in Typora/VSCode, with
// relative image resolution).
func BuildMarkdown(ctx context.Context, pg *db.DB, in *GenInput) (string, map[string]string) {
	doc := BuildDoc(ctx, pg, in)
	assets := map[string]string{}
	var b strings.Builder

	// -- info header --
	b.WriteString("# " + doc.Meta.ReportTitle + "\n\n")
	b.WriteString("> **Prepared by**: " + doc.Meta.CompanyName + "  \n")
	b.WriteString("> **Date**: " + doc.Meta.Date +
		" · **Version**: " + doc.Meta.Version + "  \n")
	var crit, high, med, low int
	for _, s := range doc.Summary.Systems {
		crit += s.Crit
		high += s.High
		med += s.Med
		low += s.Low
	}
	b.WriteString("> **Findings**: " +
		fmt.Sprintf("%s %d · %s %d · %s %d · %s %d (%s %d)\n",
			"Critical", crit, "High", high,
			"Medium", med, "Low", low,
			"total", crit+high+med+low))
	b.WriteString("\n---\n\n")

	s1 := "Description"
	s3 := "Module"
	s4 := "Testing Process"
	s5 := "Risk Analysis"
	s6 := "Remediation"
	s7 := "Remediation Status"
	tTarget := "Target"
	tRisk := "Severity"
	tDate := "Found"

	sysIdx := 0
	for _, sysd := range doc.SystemsDetail {
		sysIdx++
		b.WriteString(fmt.Sprintf("## %d %s\n\n", sysIdx, mdLeadNumRe.ReplaceAllString(sysd.Name, "")))
		vulnIdx := 0
		for _, v := range sysd.Vulns {
			vulnIdx++
			// title: <sys>.<vuln> <name> (<severity>/CVSS <score>); numbered from 1
			paren := v.Severity
			if v.CVSSScore > 0 {
				paren += "/CVSS " + fmt.Sprintf("%.1f", v.CVSSScore)
			}
			b.WriteString(fmt.Sprintf("### %d.%d %s (%s)\n\n", sysIdx, vulnIdx, v.Title, paren))
			// attribute table
			b.WriteString("| | |\n|---|---|\n")
			b.WriteString("| **" + tTarget + "** | " + mdCell(nz(v.Target, v.URL)) + " |\n")
			b.WriteString("| **" + tRisk + "** | **" + v.Severity + "** |\n")
			b.WriteString("| **" + tDate + "** | " + v.FoundDate + " |\n\n")
			// 1. Description
			b.WriteString("**1. " + s1 + "**\n\n")
			for _, p := range v.Description {
				b.WriteString(p + "\n\n")
			}
			// 2. URL
			b.WriteString("**2. URL**\n\n")
			b.WriteString(nz(v.URL, v.Target) + "\n\n")
			// 3. Module
			b.WriteString("**3. " + s3 + "**\n\n")
			b.WriteString(defaultStr(v.Module, "—") + "\n\n")
			// 4. Testing process (step text + verbatim request/response + evidence screenshots)
			b.WriteString("**4. " + s4 + "**\n\n")
			for _, blk := range v.TestProcess {
				switch blk.Type {
				case "code":
					b.WriteString("```\n" + strings.TrimRight(blk.Content, "\n") + "\n```\n\n")
				case "image":
					if blk.Path != "" && fileExists(blk.Path) {
						rel := filepath.Base(blk.Path)
						assets[rel] = blk.Path
						b.WriteString("![" + mdEscapeAlt(blk.Caption) + "](assets/" + rel + ")\n")
						if blk.Caption != "" {
							b.WriteString("*" + blk.Caption + "*\n")
						}
						b.WriteString("\n")
					}
				default:
					b.WriteString(blk.Content + "\n\n")
				}
			}
			// 5. Risk analysis
			b.WriteString("**5. " + s5 + "**\n\n")
			for _, r := range v.RiskAnalysis {
				b.WriteString("- " + r + "\n")
			}
			b.WriteString("\n")
			// 6. Remediation
			b.WriteString("**6. " + s6 + "**\n\n")
			for _, r := range v.Remediation {
				b.WriteString("- " + r + "\n")
			}
			b.WriteString("\n")
			// 7. Remediation status
			b.WriteString("**7. " + s7 + "**\n\n")
			b.WriteString(v.FixStatus + "\n\n")
			b.WriteString("---\n\n")
		}
	}
	b.WriteString("*" + fmt.Sprintf(
		"Report prepared by %s on %s.",
		doc.Meta.CompanyName, doc.Meta.Date) + "*\n")
	return b.String(), assets
}

// GenerateMarkdownFile builds the MD delivery-package zip (report.md + assets/ evidence
// images) and returns the zip path. Pure Go, no python dependency; images are attached as
// real files with relative references, so after extraction they are directly readable and
// editable in Typora/VSCode.
func GenerateMarkdownFile(ctx context.Context, pg *db.DB, in *GenInput, workDir, taskID string) (string, error) {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create report directory: %w", err)
	}
	md, assets := BuildMarkdown(ctx, pg, in)
	zipPath := filepath.Join(workDir, fmt.Sprintf("task-%s-%s.zip", safeName(taskID), nowStamp(ctx)))
	zf, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create report package: %w", err)
	}
	defer zf.Close()
	zw := zip.NewWriter(zf)
	mw, err := zw.Create("report.md")
	if err != nil {
		return "", fmt.Errorf("failed to write report.md: %w", err)
	}
	if _, err := mw.Write([]byte(md)); err != nil {
		return "", fmt.Errorf("failed to write report.md: %w", err)
	}
	for rel, src := range assets {
		data, err := os.ReadFile(src)
		if err != nil {
			continue // skip a missing image without affecting the whole package
		}
		aw, err := zw.Create("assets/" + rel)
		if err != nil {
			continue
		}
		_, _ = aw.Write(data)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("failed to build archive: %w", err)
	}
	return zipPath, nil
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// mdCell escapes characters in a table cell that would break the markdown table.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// mdEscapeAlt cleans image alt text (removes characters that would break ![]() syntax).
func mdEscapeAlt(s string) string {
	s = strings.ReplaceAll(s, "]", "")
	s = strings.ReplaceAll(s, "\n", " ")
	if strings.TrimSpace(s) == "" {
		return "evidence"
	}
	return s
}
