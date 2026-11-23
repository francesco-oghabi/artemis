# Roadmap

Artemis is research in progress. The north star is simple: **close the coverage gap
between a local open-weight model and a frontier reference on authorized targets**, using
deterministic structural controls rather than hoping a weak model behaves. Items are
grouped by theme, not hard-dated.

## Coverage toward frontier parity

- **Deterministic verifiers for more classes.** The rendering oracle (`xss_verify`) and
  endpoint discovery (`endpoint_discover`) proved the pattern: take a technique out of the
  weak model's hands and make the verdict deterministic. A first suite now ships over a
  `VulnClass` interface, `exposure_verify` (exposed files/directories/metrics),
  `csp_verify` (missing CSP), `injection_verify` (SQL/NoSQL probing), `captcha_verify`,
  `traversal_verify` (null-byte path traversal) and `jwt_verify`, lifting the best run to
  ~9-11 of the 18 classes. Still only *asserted* and needing their own oracle: V06 IDOR and
  V16 negative quantity. Not yet reached at all: V05 mass assignment (no verifier) and V08
  stored XSS (plant + render, reusing `xss_verify`). V04 JWT forgery has an oracle that
  does not break the Juice Shop variant; it needs the RS256→HS256 key-confusion technique
  (sign HS256 with the public key), which is less generic.
- **Breadth that gets executed.** Finish tuning the frontier drain and per-intent budget
  so the planner's breadth is actually executed before a run closes, and scale throughput
  with multiple workers.
- **Per-target thin knowledge layer.** A small, discovered (never hardcoded) per-target
  map layered over the global methodology, so the agent knows where to look without
  baking a specific target into the code.

## Robustness and hygiene

- **Negative-as-finding guardrail (code).** A filter that refuses, or demotes to a fact,
  "findings" that are negative observations ("not vulnerable to X"), which otherwise
  inflate the count. To be added carefully so it does not hide real analysis. This is the
  **current bottleneck**: the oracles raised coverage but the finding count is still dirty
  (negatives recorded as findings plus duplicates make up a large share of a run), and the
  oracles do not suppress it because the weak model ignores the "negative, record a fact"
  rule. It needs a code-level guardrail.
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
  measuring on aggregated runs.

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
