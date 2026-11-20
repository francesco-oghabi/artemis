# Benchmark: open-weight local model vs frontier

This document is the honest account of the project's core experiment: how far a
**weak open-weight model**, run locally, can be pushed as the decision-maker of an
autonomous pentest loop, measured against a **frontier** reference on the same target.

## Setup

- **Target: OWASP Juice Shop**, a deliberately vulnerable app with many *obvious*
  vulnerabilities across classes (SQLi, XSS, IDOR, broken auth, and more). It is used as
  a **diagnostic** target: the signal is clean, so if the model finds nothing here the
  limit is the model, not the plumbing. The image is pinned by digest for repeatability.
  It is isolated on the `artemis_default` Docker network and reached by container name.
- **Local model:** a ~30B open-weight coder model served locally on a single consumer
  GPU via Ollama (an OpenAI-compatible endpoint). Serving config is versioned under
  [`../deploy/ollama/`](../deploy/ollama/).
- **Frontier reference:** a frontier model driven directly, as the ceiling to aim at.

## The metric: coverage, as a union over runs

Run-to-run variance in this stack is high and **loop-dominated**: the divergence lives in
a minority of high-entropy decision tokens that the autoregressive loop amplifies. Fixing
the sampling seed makes a *single call* reproducible but not a *whole run*, because
numerical cold-vs-warm effects flip an early low-margin fork and the loop amplifies from
there. Per-run reproducibility is therefore not a realistic goal in this stack.

The conclusion reframed the objective. What matters for a pentest tool is not that two
runs agree, it is **how many real distinct vulnerabilities surface**. So the metric is
**coverage taken as the union over N runs**, and the direction is **broad exploration
plus aggregation**, not pinning one trajectory. High variance is only a problem when it
correlates with low coverage.

## The ceiling

Driven directly, the frontier model confirmed **18 distinct vulnerabilities** on Juice
Shop (critical through low) with real exploitation: UNION dumps, JWT `alg:none` forgery,
mass assignment, NoSQL, path traversal, and more. Early local-model runs landed at
roughly **2 to 6** vulnerabilities with high variance, concentrated in the "obvious
injection / IDOR / XSS" tier, without chains or exfiltration.

The gap decomposes into two parts:

- **breadth** (classes never attempted but detectable by a 30B): prompt- and
  surface-addressable;
- **depth** (exploitation and chains): closer to the model's capability ceiling.

## The central pattern

> To make a **weak** model usable, every behavioral rule it ignores must become a
> **structural guarantee in code** (a level-5 fix). A frontier model needs none of them.

Each guardrail below was found by inspecting a real failure, fixed at the right level
(see [ARCHITECTURE.md](ARCHITECTURE.md)), then measured.

## The "truth defect" and its two halves

The dominant failure was not path, it was **recognition**: the same vector was sometimes
confirmed and sometimes filed as a false negative between identical runs. Replaying the
agent's own payloads against the live instance showed many "negatives" were **false**
(the exact login payload returned an admin JWT; a basket IDOR returned another user's
basket), yet recorded as failures.

With real traffic captured, the defect split cleanly into two problems with different
cures:

- **Reach** (the correct request was never sent). An oracle cannot help, because there is
  no winning response to recognize. Cured by **active endpoint discovery**.
- **Judge** (a winning response was received but recorded as negative). Cured by a
  **deterministic oracle**. Measurement showed reach dominated, so judge was largely
  deferred.

## Levers and measured effects

| Lever | Level | What it does | Measured effect |
|---|---|---|---|
| Tool-name tolerance | code | maps weak-model tool-name variants to the real tool | "unknown tool" errors to 0 |
| English model-facing context | prompt/code | removes a mixed-language confounder | cleaner output, fewer trivial facts |
| Finding / intent / fact dedup | code | robust target-key extraction collapses rephrased duplicates | fact duplication from ~8-14% to 0% |
| Context-compaction scaling | code | scales summarizer thresholds to a small window | stops constant summarization that poisoned context |
| `goal_met` termination (`StopContinuation`) | code | a completed task closes the session deterministically | from thousands of `goal_met` calls per run (timeout) to a clean close |
| Semantic KB retrieval (pgvector + Ollama embeddings) | code/runtime | replaces keyword lookup that returned nothing for NL queries | keyword hits 0 to semantic hits; SQLi/XSS false-negative "myths" flipped to real findings |
| `endpoint_discover` | code | mines real endpoints from the captured JS bundle, zero hardcoding | reached the correct endpoint; noise collapsed; new real findings (exposed `.env`, business logic) |
| `xss_verify` oracle | code | headless-Chromium rendering oracle, deterministic DOM-execution verdict | reflected XSS confirmed with oracle evidence |
| Deterministic intent expansion | code | expands the discovered surface into concrete self-contained intents | XSS/redirect coverage no longer depends on planner luck |
| Frontier drain + per-intent budget | code | executes queued breadth before closing; frees runaway-intent workers | breadth executed and measured instead of orphaned |

A representative before/after: one noisy run produced **22 "findings" (19 of them
low-value "blocked by SPA" noise)**; after the reach fix, a comparable run produced
**4 substantial findings** (a critical SQLi, a real negative-quantity business-logic flaw,
an exposed `.env`, and a genuinely tested reflected XSS), with the "blocked by the SPA"
alibi gone.

## Honest limitations

- The local model still trails the frontier's 18. This is ongoing research, not a
  "we beat the frontier" claim.
- Recognition variance is **reduced, not eliminated**. Coverage remains a union over runs.
- Single-run numbers are noisy; every lever's effect is read on aggregated runs, not a
  one-to-one comparison.
- Some engine source comments remain in the upstream's original language; model-facing
  context has been fully translated to English.
- The published results were produced on one hardware/serving configuration; absolute
  numbers will shift on other setups.

## Reproducing

1. Start the target: `docker compose -f targets/juice-shop/docker-compose.yml up -d`.
2. Point a local OpenAI-compatible endpoint (for example Ollama) at the serving config in
   [`../deploy/ollama/`](../deploy/ollama/), or configure a hosted LLM in the UI.
3. Create a task against `http://juice-shop:3000` and run it several times; take the
   union of real distinct findings as the coverage figure.

See [ROADMAP.md](ROADMAP.md) for what is being measured next.
