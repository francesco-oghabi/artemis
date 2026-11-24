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
  trusting the model's assertion.
- **Verifier suite extended to depth and new classes**, lifting oracle-confirmed coverage
  on Juice Shop to **~16 of the frontier's 18 classes** (union over runs), with only V08
  stored XSS genuinely unreached:
  - `injection_verify` now performs a **real UNION dump** (extracts the 25 `email:hash`
    rows from Users), closing V02 (beyond mere injectability) and feeding V12.
  - `hash_crack`: offline MD5 dictionary crack (embedded common-password list plus any
    `*.txt` user wordlists under `data/wordlists/`), auto-invoked on a dump. Recovers
    `admin123` from the Juice Shop dump, closing V12.
  - `jwt_verify` now breaks V04: tight endpoint gates plus a corrupted-signature baseline
    make `alg:none` forgery a deterministic verdict, and it adds the RS256->HS256 key
    confusion using the public key exposed at `/encryptionkeys`.
  - `idor_verify` (V06): self-provisions two throwaway sessions and proves cross-account
    object reads.
  - `buslogic_verify` (V16): confirms a persisted negative-quantity basket item against a
    positive baseline.
  - `massassign_verify` (V05): differential registration proving a privileged field
    (role/admin) is accepted.
  - `stored_xss_verify` (V08): a generic store-then-render oracle. Ready, but an honest
    negative on Juice Shop (its persistent vector is atypical), so V08 remains the one
    unreached class.
- **No-progress worker terminator** in `record_fact`: frees a worker that stops making new
  progress on an intent instead of burning the per-intent budget in place.
- **Deterministic intent expansion**: code expands the discovered surface into concrete,
  self-contained intents so coverage does not depend on planner luck.
- **Semantic knowledge retrieval** via pgvector plus local Ollama embeddings, replacing a
  keyword lookup that returned nothing for natural-language queries.
- **Versioned open-weight serving config** under `deploy/ollama/`.
- Operator-facing UI and backend messages in Italian (the web UI also carries EN/ZH).

### Changed
- **Full English model-facing context** (system prompts, injected messages, tool
  descriptions and result strings) to remove a mixed-language confounder for weak models.
  The model reasons in English; operator-facing strings are localized separately.
- **Context-compaction thresholds scaled to the context window**, so small windows are no
  longer summarized constantly and poisoned.
- Project rebranded from AntiFox to **Artemis** (module path, binary, env vars, image,
  UI).

### Fixed
- **Leaked tool-call salvage in the harness**: some weak-model tool calls arrive as plain
  text (`<function=...>`) that the gateway parser silently dropped. The harness now
  recovers and dispatches them. Measured at harness parity (same task, salvage the only
  variable) this recovered 13 tool calls in one run, including the `jwt_verify` that had
  been lost as text, turning a parser-miss false negative (V04) into a confirmation and
  stabilizing run-to-run variance.
- **`goal_met` now terminates the session deterministically** (`StopContinuation`),
  instead of a weak model looping on `goal_met` until the task budget runs out.
- **Frontier drain + per-intent worker budget**: queued breadth is executed before a run
  closes on goal-met, and a runaway intent no longer sequesters a worker indefinitely.
- **Dedup across findings, intents, and facts** via robust target-key extraction,
  collapsing rephrased duplicates (fact duplication reduced to 0%).
- Tool-name tolerance: weak-model tool-name variants map to the real tool.

> This project continues active development. Pre-1.0: interfaces and defaults may change.
