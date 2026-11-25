package server

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"artemis/agent"
	pgdb "artemis/db"
)

// verifyOnFinishEnabled reports whether the finish-time shadow verifier is turned on.
// It is opt-in (env ARTEMIS_VERIFY_ON_FINISH=1|true|on) so a plain install does not
// spend LLM budget re-testing every task's findings.
func verifyOnFinishEnabled() bool {
	v := strings.TrimSpace(os.Getenv("ARTEMIS_VERIFY_ON_FINISH"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
}

// verifyOnFinish runs the independent verifier over a just-finished task's still
// -unverified findings, in SHADOW: it only tags findings.verdict and records an audit
// trail (worker=verifier, anchored to each finding node); it never changes the
// confirmed count, the UI, or the exploration loop. Best-effort and non-blocking: it
// runs in its own goroutine, re-tests live with the read-only oracle set, and logs a
// summary. Gated by verifyOnFinishEnabled.
func (e *Engine) verifyOnFinish(t *Task) {
	if t == nil || !verifyOnFinishEnabled() {
		return
	}
	go func() {
		d := e.m.PG()
		if d == nil {
			return
		}
		taskID, err := strconv.ParseInt(t.ID, 10, 64)
		if err != nil {
			return
		}
		// Resolve the provider from the task's pinned profile, else the active one.
		var prof *pgdb.LLMProfile
		if t.LLMProfileID != nil {
			prof, _ = d.ProfileByID(*t.LLMProfileID)
		}
		if prof == nil {
			prof, _ = d.ActiveProfile()
		}
		if prof == nil {
			log.Printf("[verifier] task %s: no LLM profile, skipping shadow verification", t.ID)
			return
		}
		cfg := agent.ConfigFromProfile(prof)

		rows, err := d.FindingsForVerify(taskID, true) // unverified only
		if err != nil {
			log.Printf("[verifier] task %s: listing findings failed: %v", t.ID, err)
			return
		}
		if len(rows) == 0 {
			return
		}

		store := d.Exploration(t.ExpID)
		ts := agent.NewToolSet(store, "verifier")
		ts.SetTaskID(taskID)
		tools := ts.VerifierReadTools()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		log.Printf("[verifier] task %s: shadow verification of %d finding(s) starting", t.ID, len(rows))
		counts := map[string]int{}
		for _, r := range rows {
			if ctx.Err() != nil {
				break
			}
			nid := r.NodeID
			emit := func(a pgdb.Activity) {
				if nid > 0 {
					a.NodeID = &nid
				}
				_, _ = store.AppendActivity(a)
			}
			v, ok := agent.VerifyFinding(ctx, cfg, agent.VerifyInput{
				VulnClass:    r.VulnClass,
				Severity:     r.Severity,
				Summary:      r.Summary,
				Evidence:     r.Evidence,
				Reproduction: r.Reproduction,
			}, tools, emit)
			if ok {
				if err := d.SetFindingVerdict(r.ID, v.Status, v.Reason); err != nil {
					log.Printf("[verifier] task %s: writing verdict for finding %d failed: %v", t.ID, r.ID, err)
				}
				counts[v.Status]++
			}
		}
		log.Printf("[verifier] task %s shadow verification done: exploit-proven=%d verified=%d needs-manual=%d rejected=%d",
			t.ID, counts[agent.VerdictExploit], counts[agent.VerdictVerified], counts[agent.VerdictNeedsManual], counts[agent.VerdictRejected])
	}()
}
