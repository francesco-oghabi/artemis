<div align="center">

# Artemis

**An AI autonomous penetration-testing platform, built to make open-weight models usable as the reasoning core.**

English | [Italiano](README.it.md)

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](go.mod)
[![Status](https://img.shields.io/badge/status-research%20%2F%20WIP-orange.svg)](docs/ROADMAP.md)

</div>

---

## What is Artemis

Artemis is a platform for **autonomous penetration testing**. Given an authorized
target, a team of agents (a planner, N workers, a main agent) drives the full loop,
recon, attack-surface discovery, exploitation, vulnerability recording, and report
delivery, around a **dual-graph architecture** (a global asset graph plus a
per-task exploration graph). The engine is event-driven: a change in the graph wakes
the planner, which dispatches intents; a worker executes an intent and writes results
back; the write-back triggers the next round, until a goal is proven.

Unlike tools that are strong at *finding* but stop there, Artemis keeps the
reproduction steps and evidence fixed as it works: every step is recorded with its
real request, response, and verdict, and each step is linked to the actual MITM-captured
traffic packet. The engineer's job shifts from "assemble a report from scratch" to
"verify what the agent already proved".

## Why Artemis exists

The frontier of this field is dominated by closed, hosted models. Artemis asks a
different question:

> **How far can an open-weight model, run locally, be pushed as the decision-maker
> of an autonomous pentest loop, and what does it take to get there?**

This matters for two concrete reasons that a hosted frontier model cannot offer:

- **No refusals.** Offensive-security tasks are routinely refused by hosted
  safety filters. A local open-weight model does not gate the work.
- **Data privacy.** Target traffic, findings, and client context never leave the
  machine.

The central finding of the project, measured run after run, is blunt and useful:

> A **weak** open-weight model does not need a better personality, it needs a
> **structural guarantee in code** for every rule it keeps ignoring. A frontier
> model does not need those guardrails; a weak one needs one per failure mode.

Artemis is the accumulation of those guardrails plus the prompt, tool, and
knowledge-base levers around them, measured against a frontier reference so the
progress is honest rather than anecdotal.

## Where it comes from (lineage)

Artemis is a derivative work and says so plainly:

```
ARTEX  (by @Autumn-27)
  └── AntiFox  (by AntiFox-AI)  — re-centered on evidence-driven delivery
        └── Artemis  (this project)  — focused on open-weight local models
```

It inherits a strong base from AntiFox and ARTEX (the exploration-graph engine, MITM
traffic recording, rule-based human-in-the-loop interception, multi-agent
orchestration). Full attribution is in [NOTICE](NOTICE). Per AGPL-3.0, the complete
source of Artemis is in this repository.

## How it works

Go single binary (Next.js frontend embedded via `go:embed`) plus PostgreSQL. The core
is the **dual-graph** model: a globally shared asset graph (the cross-task source of
truth for assets) and a per-task exploration graph (the lineage of goals, intents,
facts, and vulnerabilities). The two are joined by anchors.

```mermaid
flowchart TB
  subgraph FE[Next.js frontend, embedded in one binary]
    UI[Dashboard · Tasks · Findings · Assets · Traffic · Reports · Knowledge]
  end
  subgraph SRV[server · Go net/http]
    API[REST /api · JWT · SSE]
    ENG[event-driven engine]
  end
  subgraph AG[multi-agent orchestration]
    PL[planner · the only intent producer]
    WK[worker · executes ×N]
    MA[main agent · human interface]
  end
  subgraph DB[PostgreSQL]
    AGRAPH[asset graph · global]
    EGRAPH[exploration graph · per task]
  end
  SUB[MITM capture · HITL interception · report builder · pgvector knowledge base]

  UI --> API --> ENG --> PL & WK
  API --> MA
  PL & WK & MA --> DB
  WK --> SUB
```

A design principle runs through the whole project, the **intervention-levels
taxonomy**: fix each problem at the shallowest level that gives the right generality
and guarantee, from task config (0), to prompts (1), tools (2), skills/knowledge (3),
runtime/serving (4), engine code (5), and model weights (6). Structural guarantees and
bugs go to code; tunable behavior and knowledge go to prompts/tools/skills. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## The benchmark: open-weight local vs frontier

Progress is measured on **OWASP Juice Shop**, a deliberately vulnerable app with many
*obvious* vulnerabilities, used as a **diagnostic** target: if the model finds nothing
here, the limit is the model, not the plumbing.

- **Frontier reference (ceiling).** A frontier model, driven directly, confirmed
  **18 distinct vulnerabilities** on Juice Shop (critical through low) with real
  exploitation (UNION dumps, JWT `alg:none` forgery, mass assignment, NoSQL, path
  traversal). This is the yardstick Artemis measures the local model against.
- **Local open-weight model.** A ~30B open-weight coder model served locally on a
  single consumer GPU via Ollama. Early runs landed at roughly 2 to 6 vulnerabilities
  with high run-to-run variance. After the deterministic-verifier suite below (now
  extended to real UNION dumps, MD5 cracking and JWT forgery) plus the leaked-tool-call
  salvage fix, oracle-confirmed coverage reaches **~16 of the 18 classes as a union over
  runs**, and a single coherent run now confirms **14 classes at once** (a real jump, not
  parity, see the honest caveats). The one class genuinely unreached is V08 stored XSS.

The metric that matters for a pentest tool is **coverage**: how many *real* distinct
vulnerabilities surface, taken as the **union over N runs** (not a single run, where
variance dominates). The research direction is therefore broad exploration plus
aggregation, not chasing a single reproducible trajectory.

### The 18 classes, class by class (best local run vs frontier)

The frontier reference exploited **18 distinct vulnerabilities** (5 critical, 7 high, 5
medium, 1 low). The table below is the honest per-class standing of the local 30B, taken
as the **union over runs** (a single coherent run now confirms 14 classes at once).
Legend: ✅ confirmed by a deterministic in-code oracle, 🟡 asserted by the model (real,
but no oracle, so it varies run to run), 🔴 attempted but not broken, ⬜ not reached.

| # | Class | Frontier | Local | How the local model is judged |
|---|---|:---:|:---:|---|
| V01 | SQLi login bypass | ✓ | ✅ | `injection_verify` (auth-bypass tautology) |
| V02 | SQLi UNION dump | ✓ | ✅ | `injection_verify` (real UNION dump: 25 `email:hash` rows from Users) |
| V03 | SQLi, targeted login as chosen user | ✓ | ⬜ | not distinguished from V01 |
| V04 | JWT `alg:none` forgery | ✓ | ✅ | `jwt_verify` (`alg:none` on tight gates + corrupted-signature baseline, plus RS256→HS256 confusion with the exposed pubkey) |
| V05 | Mass assignment of role | ✓ | ✅ | `massassign_verify` (differential registration, `role=admin` accepted) |
| V06 | IDOR basket | ✓ | ✅ | `idor_verify` (two-account cross-read, owner-id differential) |
| V07 | NoSQL mass-update | ✓ | 🟡 | `injection_verify` NoSQL mode, partial |
| V08 | **Stored** XSS in reviews | ✓ | 🔴 | `stored_xss_verify` ready, honest negative (Juice Shop's persistent vector is atypical) |
| V09 | Path traversal null-byte | ✓ | ✅ | `traversal_verify` |
| V10 | Confidential document `/ftp` | ✓ | ✅ | `exposure_verify` |
| V11 | Directory `/encryptionkeys` | ✓ | ✅ | `exposure_verify` |
| V12 | Weak MD5 hashes | ✓ | ✅ | V02 dump + `hash_crack` (25 unsalted MD5; `admin123` recovered via the built-in dictionary) |
| V13 | Open redirect | ✓ | ✅ | `redirect_verify` |
| V14 | Verbose SQL errors | ✓ | 🟡 | `injection_verify` error-based (inconsistent) |
| V15 | `/metrics` endpoint | ✓ | ✅ | `exposure_verify` |
| V16 | Negative quantity (business logic) | ✓ | ✅ | `buslogic_verify` (positive baseline vs persisted negative quantity) |
| V17 | Missing CSP | ✓ | ✅ | `csp_verify` |
| V18 | CAPTCHA in the response | ✓ | ✅ | `captcha_verify` |
|  | Reflected / DOM XSS | ✓ | ✅ | `xss_verify` (rendering oracle) |

**Honest reading.** Oracle-confirmed: **~16** (union over runs). Additionally asserted,
no oracle: V03, V07, V14. Genuinely not reached: **1** (V08 stored XSS: the oracle is
ready but Juice Shop's persistent vector is atypical, so it returns an honest negative).
The **depth** gap is now largely closed: the local model dumps the 25 users (V02), cracks
the unsalted MD5 hashes (V12), and forges JWTs (V04) rather than only proving a class
exists. What remains: **noise** (negatives recorded as findings plus duplicates; much
lower since the IDOR/business-logic work but not eliminated), and the fact that the
comparison is **not at harness parity**, the frontier model was driven in a direct session
(full shell), the local model inside Artemis's constrained planner/worker loop, so the gap
is model *plus* harness. Isolating the model gap needs the still-missing third data point:
the frontier model driven *inside* Artemis.

Full methodology and the honest results in [docs/BENCHMARK.md](docs/BENCHMARK.md).

## What Artemis adds over its upstreams

Everything below is engineering to make a weak open-weight model actually deliver. Each
item is either a structural guarantee in code or a measured lever:

- **`endpoint_discover`** (engine): active endpoint discovery from the JS bundle the
  target itself serves and the proxy already captured, with zero hardcoded paths, so
  the worker reaches the *right* URL instead of giving up ("blocked by the SPA").
- **`xss_verify`** (engine): a deterministic rendering oracle (headless Chromium) that
  fires canonical non-`<script>` payloads and reports, deterministically, whether one
  executes in the DOM, taking the technique out of the weak model's hands.
- **Deterministic verifier suite over a `VulnClass` interface**: a family of in-code
  oracles (`exposure_verify` for exposed files/dirs/metrics, `csp_verify` for a missing
  CSP, `injection_verify` for SQL/NoSQL probing plus a real UNION dump, `captcha_verify`,
  `traversal_verify` for null-byte path traversal, `jwt_verify`, `idor_verify`,
  `buslogic_verify`, `massassign_verify`, `stored_xss_verify`) that each return a
  deterministic verdict instead of trusting what the weak model asserts. This is what
  lifts coverage from ~2 to 6 up to ~16 of the 18 classes (see the table above).
- **Depth, not just presence**: `injection_verify` performs a real UNION dump (25
  `email:hash` rows from Users), `hash_crack` cracks the unsalted MD5 hashes offline
  (built-in dictionary plus any `*.txt` user wordlists under `data/wordlists/`, recovering
  `admin123`), and `jwt_verify` forges tokens (`alg:none` plus RS256→HS256 key confusion),
  so the local model chains dump → crack → forge instead of only proving a class exists.
- **Leaked tool-call salvage**: some weak-model tool calls arrive as plain text
  (`<function=...>`) that the gateway parser dropped silently. The harness recovers and
  dispatches them, turning parser-miss false negatives into confirmations (V04 among them)
  and stabilizing run-to-run variance without waiting on an upstream serving fix.
- **No-progress worker terminator**: `record_fact` detects a worker making no new
  progress on an intent and frees it, instead of burning the budget in place.
- **Deterministic intent expansion**: code expands the discovered surface into
  concrete, self-contained intents (exact URL plus the exact verifier to call), so
  coverage no longer depends on the planner happening to generate the right intent.
- **Goal-met termination fix**: a completed task now closes the session deterministically
  (`StopContinuation`) instead of a weak model looping on `goal_met` until the budget
  runs out.
- **Frontier drain + per-intent budget**: the engine executes the queued breadth before
  closing on goal-met, and a per-intent budget frees a worker stuck on one runaway
  intent.
- **Dedup across findings, intents, and facts**: robust target-key extraction collapses
  duplicates that a weak model re-phrases.
- **Context-compaction scaling** for small context windows, so a 32k window is not
  summarized constantly and poisoned.
- **Semantic knowledge retrieval** (pgvector plus local Ollama embeddings), replacing a
  keyword lookup that returned nothing for natural-language queries.
- **Full English model-facing context** (system prompts, injected messages, tool
  descriptions and results), so a mixed-language context stops confusing a weak model.
  Operator-facing strings are localized separately (Italian UI and backend messages, with
  EN/ZH also in the web UI).
- **Versioned open-weight serving config** under [`deploy/ollama/`](deploy/ollama/)
  (context window, sampling, parallelism, with the reasoning written down).

Several of these subsystems do not exist in the upstreams at all (the knowledge base,
fact dedup, the termination wiring); the rest are new verifiers and controls layered on
top. See [docs/BENCHMARK.md](docs/BENCHMARK.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## Quick start

Requires **PostgreSQL**; exploration needs an **LLM** (a hosted key, or a local
OpenAI-compatible endpoint such as Ollama). Generating `.docx` reports needs `python3`
plus `python-docx` (bundled in the Docker image).

### Option 1: Docker Compose

```bash
cp .env.example .env          # set POSTGRES_PASSWORD
docker compose up -d
```

Open **http://localhost:8787** and set the admin password at `/setup` on first run.

> No prebuilt image is published to `ghcr.io/francesco-oghabi/artemis` yet. Until a
> release is cut, build locally (below) or with `scripts/build-image.sh`.

### Option 2: from source

Full source is open (AGPL-3.0). Requires Go 1.26+, Node 20+, PostgreSQL, Python 3:

```bash
cd web && npm ci && npm run build:static && cd ..   # static frontend
rm -rf server/webui/dist && mkdir -p server/webui/dist && cp -r web/out/. server/webui/dist/
CGO_ENABLED=0 go build -tags embedui -o artemis ./cmd/artemis
export ARTEMIS_PG_DSN="postgres://artemis:artemis@localhost:5432/artemis?sslmode=disable"
./artemis -addr :8787 -data ~/artemis-data
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the containerized rebuild and development
workflow.

### Running the benchmark target

```bash
docker compose -f targets/juice-shop/docker-compose.yml up -d   # OWASP Juice Shop
```

The target joins the `artemis_default` Docker network and Artemis reaches it by
container name (`http://juice-shop:3000`). See [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): dual-graph model, agents, and the
  intervention-levels taxonomy.
- [docs/BENCHMARK.md](docs/BENCHMARK.md): methodology, the frontier reference, the levers,
  and honest results.
- [docs/ROADMAP.md](docs/ROADMAP.md): where this is going.

## License and responsible use

Artemis is released under **AGPL-3.0** (see [LICENSE](LICENSE)). Use, modification, and
redistribution (including offering it as a network service) must comply with that
license.

**Artemis is an offensive, dual-use tool. Use it only against systems you are
explicitly authorized to test** (your own lab, deliberately vulnerable targets such as
Juice Shop, or engagements with written permission). You are solely responsible for
complying with all applicable laws on computer security, data protection, and computer
crime. The software is provided "AS IS", without warranty of any kind; the authors and
contributors accept no liability for any use of it.
