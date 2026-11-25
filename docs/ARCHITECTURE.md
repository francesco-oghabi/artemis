# Architecture

OpenArtemis is a Go single binary (with the Next.js frontend embedded via `go:embed`)
backed by PostgreSQL. This document explains the two ideas that matter most: the
**dual-graph** model that the engine runs on, and the **intervention-levels taxonomy**
that decides where every change belongs.

## Dual-graph model

There are two graphs, joined by anchors:

- **Asset graph (global).** The cross-task source of truth for assets (hosts, services,
  endpoints, credentials). Shared across tasks so knowledge about a target accumulates.
- **Exploration graph (per task).** The lineage of a single engagement: goals, intents,
  facts, and findings, with the edges that connect a discovery to the action that caused
  it.

Node kinds in the exploration graph:

| kind | meaning | produced by |
|---|---|---|
| **goal** | something to prove about the target | the goals agent |
| **intent** | a concrete instruction for a worker | the planner (`add_intent`) |
| **fact** | an observation anchored to a real tool call | a worker (`record_fact`) |
| **finding** | a confirmed vulnerability with evidence | a worker (`report_finding`) |

## The agents

The engine is **event-driven**. A change in the graph wakes the planner; the planner
dispatches intents; a worker executes an intent and writes facts/findings back; the
write-back triggers the next round. The loop continues until every goal is proven.

- **Planner.** The only producer of intents. It decomposes the surface into directions
  and dispatches them, one per worker turn. It does not execute tools against the target.
- **Worker (×N).** Executes an intent end to end: issues real requests, escalates on a
  first signal (a SQL error into a UNION dump, an IDOR into another user's data), and
  records facts or findings. Multiple workers drain the frontier in parallel.
- **Main agent.** The human interface: answers questions, accepts guidance, and surfaces
  what the automated loop is doing.
- **Verifier (independent, shadow).** A skeptical, read-only reviewer that adjudicates a
  finding from its recorded evidence and tags it (`exploit-proven` / `verified` /
  `needs-manual-verification` / `rejected`), rejecting only what the evidence positively
  fails and preserving anything inconclusive. It cannot create findings, dispatch intents,
  or re-test the target, so it can only remove spurious certainty, never invent a
  confirmation. Today it runs on demand (`cmd/verifyfindings`) as a shadow pass over
  findings (writing `findings.verdict`); it does not yet change the confirmed count or the
  loop. A live run also leaves an audit trail on the exploration graph: its reasoning and
  verdict are recorded as activity (`worker=verifier`) anchored to the finding node, so a
  demotion is always traceable to its evidence.

Agents communicate **through the graph**, not by chatting: an intent is an instruction
for the worker, a fact/finding is data for the planner.

## Evidence-driven delivery

As a worker exploits, it records each step (request, response, expected result, verdict)
in order, rather than reconstructing a report afterward. Every request the agents send is
captured by the MITM proxy and stored in full; each reproduction step is then linked to
its corresponding real packet by time window and step order. For a class like sensitive
information disclosure, the packet itself is the evidence.

## Intervention-levels taxonomy

The project's recurring design question is *at which level* to make a change. Fixing a
problem too deep wastes effort; fixing it too shallow leaves it dependent on a weak
model's good behavior. The taxonomy:

| # | Level | Lives in | How it changes | Reversible | Solves |
|---|---|---|---|---|---|
| 0 | **Task** | DB `tasks`, UI | config, no rebuild | immediately | goal/scope/profile of one run |
| 1 | **Prompt** (agent role) | DB `agent_prompts`, UI | live, no rebuild | immediately | planner/worker behavior across tasks |
| 2 | **Tool** (the menu) | DB `tools`, UI | live, no rebuild | immediately | tool names/descriptions/schema/binding |
| 3 | **Skill / Knowledge** | skill files + pgvector KB | file/DB | immediately | domain knowledge (OWASP playbooks, target maps) |
| 4 | **Runtime / serving** | Ollama (context, sampling, parallelism), env | config/restart | immediately | how the model runs |
| 5 | **Engine code** | Go (`server/engine.go`, `engine/...`) | rebuild + commit | slow, versioned | loop, closing, dispatch, concurrency, dedup, retries, context curation |
| 6 | **Weights** | the model | fine-tune / swap | heavy | the capability ceiling of the decision-maker |

**Rule of placement.** Fix each problem at the shallowest level that gives the right
generality and guarantee:

- structural guarantees and bugs (must not depend on the model) go to **code (5)**;
- tunable behavior and knowledge go to **prompts / tools / skills (1-3)**;
- run-specific choices go to **task (0)**;
- weights (6) only when levels 1-5 do not close the gap.

The practical consequence, measured repeatedly: making a **weak** open-weight model
usable means turning each behavioral rule it ignores into a **structural guarantee in
code**. A frontier model does not need them.

## Live-editable mechanisms

Three mechanisms are editable hot from the DB/UI, each with its own correct use.
Choosing the wrong one (for example, putting domain knowledge into tool descriptions)
costs wasted context and mixed concerns.

- **Tools (`tools`, level 2).** The menu: key, description, schema, agent binding. For
  short, universal rules of *use* (when/how to call a tool), not for domain knowledge.
- **Skills / Knowledge (`knowledge_docs` + `search_knowledge`, level 3).** Knowledge
  documents, global or per-task, retrieved by relevance. Retrieval is semantic (pgvector)
  when an embeddings backend is configured, and degrades to keyword search otherwise.
  This is the home for durable domain knowledge (pentest methodology, per-class success
  signatures, target maps), kept global so it survives a change of target.
- **Interception rules (`intercept_rules`, level 5, editable live).** Guardrails
  evaluated in PreToolUse, by priority, on the tool name or input, with `allow` / `deny`
  / `ask` actions. They see only the tool name and input (not responses), so they are for
  surgical hard-stops of a few known bad patterns, not general knowledge. The built-ins
  block destructive commands.

A true oracle on *responses* (a 2xx carrying a JWT or another entity's data is a
vulnerability) cannot live in an interception rule because rules do not see output: that
belongs in engine code on the MITM/traffic path (level 5). `xss_verify` and
`endpoint_discover` are exactly such code-level verifiers.
