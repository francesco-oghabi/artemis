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
injection / IDOR / XSS" tier, without chains or exfiltration. After the deterministic
verifier suite (below), extended to real UNION dumps, MD5 cracking and JWT forgery, plus
the leaked-tool-call salvage fix, oracle-confirmed coverage reaches **~16 of the 18
classes as a union over runs**, and a single coherent run now confirms **14 classes at
once**. This is a real jump, not parity: see "Where it stands now".

The gap used to decompose into two parts:

- **breadth** (classes never attempted but detectable by a 30B): prompt- and
  surface-addressable, now largely covered;
- **depth** (exploitation and chains): the local model now dumps, cracks and forges
  (V02/V12/V04), so depth is largely closed too; what is left is one atypical class (V08)
  and residual noise.

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
| Deterministic verifier suite (`VulnClass`) | code | in-code oracles `exposure_verify` / `csp_verify` / `injection_verify` / `captcha_verify` / `traversal_verify` / `jwt_verify` / `idor_verify` / `buslogic_verify` / `massassign_verify` / `stored_xss_verify`, each a deterministic verdict | oracle-confirmed classes from ~2-6 to ~16 of 18 |
| UNION dump + `hash_crack` | code | `injection_verify` dumps the 25 `email:hash` rows; `hash_crack` cracks unsalted MD5 offline (built-in + user wordlists) | V02 closed beyond injectability; V12 closed (`admin123` recovered) |
| `jwt_verify` forgery | code | `alg:none` on tight gates with a corrupted-signature baseline, plus RS256→HS256 key confusion with the exposed pubkey | V04 confirmed (was a false "unbroken" from a loose oracle) |
| Leaked tool-call salvage | code | recovers weak-model tool calls that arrive as text `<function=...>` and the gateway parser dropped | at harness parity recovered 13 calls in one run (incl. the lost `jwt_verify`); stabilizes variance |
| No-progress worker terminator | code | `record_fact` frees a worker that stops making new progress on an intent | runaway intents no longer burn the budget in place |
| Deterministic intent expansion | code | expands the discovered surface into concrete self-contained intents | XSS/redirect coverage no longer depends on planner luck |
| Frontier drain + per-intent budget | code | executes queued breadth before closing; frees runaway-intent workers | breadth executed and measured instead of orphaned |

A representative before/after: one noisy run produced **22 "findings" (19 of them
low-value "blocked by SPA" noise)**; after the reach fix, a comparable run produced
**4 substantial findings** (a critical SQLi, a real negative-quantity business-logic flaw,
an exposed `.env`, and a genuinely tested reflected XSS), with the "blocked by the SPA"
alibi gone.

## Where it stands now

After the deterministic verifier suite, the UNION dump / hash-crack / JWT-forgery
extensions and the leaked-tool-call salvage fix, coverage on Juice Shop stands roughly as
follows against the frontier's 18 classes, as a union over runs. Legend: ✅ confirmed by an
in-code oracle, 🟡 asserted by the model (real, no oracle, varies run to run), 🔴 attempted
but not broken, ⬜ not reached.

- **✅ oracle-confirmed (~16):** V01 SQLi login bypass, V02 SQLi UNION (real dump of 25
  `email:hash` rows), V04 JWT forgery (`alg:none` + RS256→HS256), V05 mass assignment, V06
  IDOR, V09 null-byte path traversal, V10 `/ftp`, V11 `/encryptionkeys`, V12 weak MD5
  (cracked, `admin123` recovered), V13 open redirect, V15 `/metrics`, V16 negative quantity,
  V17 missing CSP, V18 CAPTCHA, plus reflected/DOM XSS.
- **🟡 asserted, no oracle:** V03 (not distinguished from V01), V07 NoSQL (partial), V14
  verbose SQL errors (inconsistent).
- **🔴 genuinely not reached (1):** V08 stored XSS. The generic store-then-render oracle
  (`stored_xss_verify`) runs but returns an honest negative: Juice Shop's persistent vector
  is atypical (not a generic review/comment), so it needs a non-generic vector for this
  target.

Trajectory of oracle-confirmed coverage across the work: 2 → 5 → ~9 → ~10-11 → ~12 (V06/V16)
→ ~13 (V05) → ~15 (UNION dump V02 + hashes V12) → ~16 (V04 JWT). A further note on density:
the salvage fix produced the first single coherent run with 14 classes confirmed at once
(task 69), rather than a union assembled across separate runs, because real tool calls
(including the `jwt_verify` for V04) no longer disappear as unparsed text.

One gap is closed and two remain:

1. **Depth: closed.** The oracles no longer only prove a class *exists*. The local model
   dumps the 25 users (V02), cracks the unsalted MD5 hashes (V12: `admin123` recovered from
   the dump with the built-in dictionary; larger user dictionaries crack more), and forges
   JWTs (V04).
2. **V08 stored XSS.** The one genuinely unreached class: oracle ready, honest negative on
   Juice Shop's atypical persistent vector.
3. **Noise (readability).** The count is cleaner than before (noise fell sharply with the
   IDOR/business-logic work and is no longer the urgent bottleneck), but negatives recorded
   as findings and duplicates are not fully suppressed; the code-level guardrail remains a
   useful safety net.

And the comparison is **not at harness parity**: the frontier model was driven in a direct
session with a full shell, the local model inside OpenArtemis's constrained planner/worker
loop. The gap measured here is therefore model *plus* harness. Isolating the model gap
needs the still-missing third data point: the frontier model driven *inside* OpenArtemis on the
same target.

## Honest limitations

- The local model still trails the frontier's 18 in robustness and consistency. The
  ~16-of-18 figure is a union over runs, not a stable average, and it is not parity. This is
  ongoing research, not a "we beat the frontier" claim.
- One class (V08 stored XSS) is genuinely unreached on this target.
- Recognition variance is **reduced** (the salvage fix removed a class of parser-miss false
  negatives) **but not eliminated**. Coverage remains a union over runs.
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
