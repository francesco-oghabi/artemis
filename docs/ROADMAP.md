# Roadmap

Artemis is research in progress. The north star is simple: **close the coverage gap
between a local open-weight model and a frontier reference on authorized targets**, using
deterministic structural controls rather than hoping a weak model behaves. Items are
grouped by theme, not hard-dated.

## Coverage toward frontier parity

- **Deterministic verifiers.** The rendering oracle (`xss_verify`) and endpoint discovery
  (`endpoint_discover`) proved the pattern: take a technique out of the weak model's hands
  and make the verdict deterministic. The suite over a `VulnClass` interface now covers
  `exposure_verify`, `csp_verify`, `injection_verify` (SQL/NoSQL probing **plus a real
  UNION dump**), `captcha_verify`, `traversal_verify`, `jwt_verify` (now breaking V04 via
  `alg:none` on tight gates plus RS256→HS256 key confusion), `idor_verify` (V06),
  `buslogic_verify` (V16), `massassign_verify` (V05) and `stored_xss_verify` (V08), plus
  the offline `hash_crack` (V12) chained off the dump. This lifts oracle-confirmed coverage
  to **~16 of the 18 classes**. The one class still genuinely unreached is **V08 stored
  XSS**: the generic store-then-render oracle returns an honest negative because Juice
  Shop's persistent vector is atypical, so it needs a non-generic vector for this target.
  Remaining asserted-only (needing a tighter oracle or distinction): V03, V07 NoSQL, V14.
- **`hash_crack` beyond MD5.** The offline cracker handles unsalted MD5 today; add further
  algorithms (bcrypt/SHA families, salts) and support larger user wordlists under
  `data/wordlists/`.
- **Breadth that gets executed.** Finish tuning the frontier drain and per-intent budget
  so the planner's breadth is actually executed before a run closes, and scale throughput
  with multiple workers.
- **Per-target thin knowledge layer.** A small, discovered (never hardcoded) per-target
  map layered over the global methodology, so the agent knows where to look without
  baking a specific target into the code.

## Robustness and hygiene

- **Negative-as-finding guardrail (code).** A filter that refuses, or demotes to a fact,
  "findings" that are negative observations ("not vulnerable to X"), which otherwise
  inflate the count. To be added carefully so it does not hide real analysis. Noise fell
  sharply with the IDOR/business-logic work, so this is **no longer the urgent bottleneck**
  but remains a useful safety net: the oracles do not suppress leftover negatives recorded
  as findings and duplicates, because the weak model ignores the "negative, record a fact"
  rule.
- **"Already-done" overview + anti-contamination.** A synthetic view of classes already
  tested / confirmed / excluded, distinguishing a tested-and-blocked result with concrete
  proof from an unproven generalization, so a hallucinated belief cannot suppress a whole
  class.
- **Durable live traffic-capture toggle.** Make the capture toggle invalidate the
  per-profile agent cache so it propagates without a restart.
- **Finding dedup per sink, not per route**, so one physical vulnerability confirmed from
  several routes is recorded once.

## Open-weight model research

- **Pentest-specialized open-weight models.** Evaluate downloadable cyber/offensive
  fine-tunes, and the more ambitious path of a LoRA fine-tune on a capable open-weight
  base (the capability-ceiling, "level 6" lever).
- **Serving larger models on modest hardware.** Study MoE sparsity and offloading
  (llama.cpp CPU-MoE, and similar) to run larger mixtures on limited VRAM, weighing the
  latency cost inside an agentic loop.
- **Reproducible measurement harness.** Keep the seed/temperature findings as measurement
  tools (A/B on single calls), while treating per-run reproducibility as out of reach and
  measuring on aggregated runs. The leaked-tool-call salvage already removed one class of
  spurious variance (real calls arriving as unparsed `<function=...>` text and being
  dropped); watch for other parser-level losses of the same kind.

## Documentation and project

- Regenerate UI screenshots and the app logo/wordmark under the new name.
- Translate the remaining engine source comments still in the upstream's original language.
- Optional: a same-harness comparison (the frontier model driven *inside* Artemis) to
  isolate the model gap from the harness gap.

## Non-goals

- Beating the frontier on raw capability. The durable advantages of local open-weight
  models are **no refusals** and **data privacy**, not pure quality.
- Any use against systems without explicit authorization. See the responsible-use notice
  in the README.
