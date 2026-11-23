# Changelog

All notable changes to Artemis. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

Artemis is a fork of [AntiFox](https://github.com/AntiFox-AI/antifox) (itself a fork of
ARTEX). This changelog records the Artemis-specific work on top of that base; see
[NOTICE](NOTICE) for lineage.

## [Unreleased]

### Added
- **`endpoint_discover`**: active endpoint discovery from the target's captured JS bundle
  (zero hardcoded paths) so workers reach the correct URL instead of giving up.
- **`xss_verify`**: a deterministic headless-Chromium rendering oracle that confirms DOM
  execution of canonical non-`<script>` payloads.
- **Deterministic verifier suite over a `VulnClass` interface**: in-code oracles
  `exposure_verify` (exposed files/directories/metrics), `csp_verify` (missing CSP),
  `injection_verify` (SQL/NoSQL probing), `captcha_verify`, `traversal_verify` (null-byte
  path traversal) and `jwt_verify`, each returning a deterministic verdict instead of
  trusting the model's assertion. Lifts the best single run on Juice Shop from ~2-6 to
  ~9-11 of the frontier's 18 classes (oracle-confirmed; see `docs/BENCHMARK.md` for the
  honest caveats on depth, noise and harness parity).
- **No-progress worker terminator** in `record_fact`: frees a worker that stops making new
  progress on an intent instead of burning the per-intent budget in place.
- **Deterministic intent expansion**: code expands the discovered surface into concrete,
  self-contained intents so coverage does not depend on planner luck.
- **Semantic knowledge retrieval** via pgvector plus local Ollama embeddings, replacing a
  keyword lookup that returned nothing for natural-language queries.
- **Versioned open-weight serving config** under `deploy/ollama/`.
- English/Italian/Chinese UI with English as the default language.

### Changed
- **Full English model-facing context** (system prompts, injected messages, tool
  descriptions and result strings) to remove a mixed-language confounder for weak models.
- **Context-compaction thresholds scaled to the context window**, so small windows are no
  longer summarized constantly and poisoned.
- Project rebranded from AntiFox to **Artemis** (module path, binary, env vars, image,
  UI).

### Fixed
- **`goal_met` now terminates the session deterministically** (`StopContinuation`),
  instead of a weak model looping on `goal_met` until the task budget runs out.
- **Frontier drain + per-intent worker budget**: queued breadth is executed before a run
  closes on goal-met, and a runaway intent no longer sequesters a worker indefinitely.
- **Dedup across findings, intents, and facts** via robust target-key extraction,
  collapsing rephrased duplicates (fact duplication reduced to 0%).
- Tool-name tolerance: weak-model tool-name variants map to the real tool.

> This project continues active development. Pre-1.0: interfaces and defaults may change.
