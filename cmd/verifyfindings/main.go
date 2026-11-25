// Command verifyfindings runs the independent verifier (Phase 1, shadow) over the
// findings of one task and records each adjudication in findings.verdict. It is a
// read-mostly, on-demand tool: it never changes the exploration loop, only tags
// existing findings, so it is safe to run against a live database.
//
// Usage:
//
//	verifyfindings -task 73               # adjudicate task 73's unverified findings
//	verifyfindings -task 73 -all          # re-adjudicate all of them
//	verifyfindings -task 73 -dry          # print verdicts without writing
//	verifyfindings -task 73 -profile 6    # use a specific LLM profile id
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"artemis/agent"
	"artemis/db"
	actool "artemis/engine/tool"
)

func main() {
	log.SetFlags(0)
	taskID := flag.Int64("task", 0, "task id whose findings to verify (required)")
	all := flag.Bool("all", false, "re-verify every finding, not just those still 'unverified'")
	dry := flag.Bool("dry", false, "print verdicts without writing them to the database")
	profileID := flag.Int64("profile", 0, "LLM profile id to use (0 = the active profile)")
	limit := flag.Int("limit", 0, "adjudicate at most N findings (0 = no limit)")
	evidenceOnly := flag.Bool("evidence-only", false, "do not re-test live; adjudicate from recorded evidence only")
	flag.Parse()

	if *taskID <= 0 {
		log.Fatalf("missing required -task <id>")
	}

	dsn, _, err := db.DSN()
	if err != nil {
		log.Fatalf("resolve DSN: %v", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer d.Close()

	cfg, err := loadConfig(d, *profileID)
	if err != nil {
		log.Fatalf("load LLM config: %v", err)
	}

	task, err := d.GetTask(*taskID)
	if err != nil || task == nil {
		log.Fatalf("task %d not found: %v", *taskID, err)
	}
	store := d.Exploration(task.ExplorationID)

	rows, err := d.FindingsForVerify(*taskID, !*all)
	if err != nil {
		log.Fatalf("list findings: %v", err)
	}
	if len(rows) == 0 {
		log.Printf("task %d: no findings to verify", *taskID)
		return
	}

	// Build the verifier's read-only re-test tools once (deterministic oracles +
	// context), reused across findings. Nil in evidence-only mode.
	var retest []actool.CoreTool
	mode := "evidence-only"
	if !*evidenceOnly {
		vts := agent.NewToolSet(store, "verifier")
		vts.SetTaskID(*taskID)
		retest = vts.VerifierReadTools()
		mode = "live re-test"
	}
	log.Printf("task %d: adjudicating %d finding(s) [%s]%s\n", *taskID, len(rows), mode, dryNote(*dry))

	if *limit > 0 && len(rows) > *limit {
		rows = rows[:*limit]
	}

	ctx := context.Background()
	counts := map[string]int{}
	for _, r := range rows {
		// In a live run, record the verifier's steps as activity anchored to the
		// finding node, so its reasoning and verdict are an auditable trail in the
		// exploration graph / UI (Worker="verifier" is set inside VerifyFinding).
		// In a dry run we leave the database untouched (no verdict, no activity).
		var emit func(db.Activity)
		if !*dry {
			nid := r.NodeID
			emit = func(a db.Activity) {
				if nid > 0 {
					a.NodeID = &nid
				}
				_, _ = store.AppendActivity(a)
			}
		}
		v, ok := agent.VerifyFinding(ctx, cfg, agent.VerifyInput{
			VulnClass:    r.VulnClass,
			Severity:     r.Severity,
			Summary:      r.Summary,
			Evidence:     r.Evidence,
			Reproduction: r.Reproduction,
		}, retest, emit)
		if !ok {
			counts["no-verdict"]++
			fmt.Printf("  #%-5d %-28s -> (no verdict, left unverified)\n", r.ID, trunc(r.VulnClass, 28))
			continue
		}
		counts[v.Status]++
		fmt.Printf("  #%-5d %-28s -> %-26s %s\n", r.ID, trunc(r.VulnClass, 28), v.Status, trunc(v.Reason, 80))
		if !*dry {
			if err := d.SetFindingVerdict(r.ID, v.Status, v.Reason); err != nil {
				log.Printf("    ! write verdict for #%d failed: %v", r.ID, err)
			}
		}
	}

	fmt.Printf("\nsummary: ")
	for _, k := range []string{agent.VerdictExploit, agent.VerdictVerified, agent.VerdictNeedsManual, agent.VerdictRejected, "no-verdict"} {
		if counts[k] > 0 {
			fmt.Printf("%s=%d  ", k, counts[k])
		}
	}
	fmt.Println()
	if *dry {
		fmt.Println("(dry run: nothing written)")
	}
	os.Exit(0)
}

// loadConfig builds the agent LLM config from a profile row (the given id, or the
// active profile when id<=0), mirroring the server's loadProfileConfig.
func loadConfig(d *db.DB, profileID int64) (agent.Config, error) {
	var p *db.LLMProfile
	var err error
	if profileID > 0 {
		p, err = d.ProfileByID(profileID)
	} else {
		p, err = d.ActiveProfile()
	}
	if err != nil {
		return agent.Config{}, err
	}
	if p == nil {
		return agent.Config{}, fmt.Errorf("no LLM profile found (id=%d)", profileID)
	}
	cfg := agent.ConfigFrom(p.Format, p.Model, p.BaseURL, p.APIKey, p.Proxy)
	cfg.RatePerSecond, cfg.RatePerMinute = p.RatePerSecond, p.RatePerMinute
	cfg.ContextWindowK = p.ContextWindowK
	cfg.ReasoningEffort = p.ReasoningEffort
	cfg.SessionHeaderKey = p.SessionHeaderKey
	return cfg, nil
}

func dryNote(dry bool) string {
	if dry {
		return " (dry run)"
	}
	return ""
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
