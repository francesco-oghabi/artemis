---
name: db-project-export
description: >-
  Use when a change has been made to DB-resident state that is part of the PRODUCT
  itself (a built-in agent's system prompt, or any built-in/default that ships with
  the project) rather than a client-specific config or task-specific data. Also use
  when asked whether a fresh install reproduces the current behaviour, or about
  keeping the database and the repository in sync. It explains the DB-authoritative
  prompt model and runs the exporter that writes those changes back into the Go
  source so a clean checkout seeds them. Triggers: "edited a prompt", "tuned the
  planner/worker", "does a fresh install get this", "export prompts", "DB vs repo",
  "reproducible install".
---

# Keep project-level DB state in the repository

## Why this exists

This platform treats the **database as the authoritative, editable source** for each
built-in agent's system prompt. The in-code `<agent>DefaultTmpl` consts
(`agent/goals.go`, `agent/planner.go`, `agent/worker.go`, `agent/mainagent.go`,
`agent/promptcatalog.go`) are only the **seed** (inserted when an agent has no prompt
yet, see `db/config.go`) and the render fallback. The same pattern applies to other
built-in seeds (`seedBuiltins` in `db/db.go`, `db/schema.sql`).

Consequence: once a prompt is edited through the UI, a **new version is written to the
local Postgres and becomes the active one**, while the Go const is left untouched. That
tuned prompt then lives **only in that one database**. A fresh clone or a new install
seeds the old const and behaves differently. The repository would not contain the
prompts the project actually runs on.

## The rule

Decide whether a DB change belongs to the **project** or to a **deployment**:

- **Project-level (MUST be exported into the repo):** a change to a built-in agent's
  prompt, or any built-in/default meant to ship with the product and apply to every
  install. These are part of the product; the repo is wrong until they are in it.
- **Deployment-level (do NOT export):** anything specific to one environment,
  customer, or engagement. For example `llm_profiles` (they point at a specific
  local/hosted endpoint), a one-off prompt tweak for a single client engagement,
  per-task pins, and all operational data (`tasks`, `explorations`,
  `exploration_nodes`, `findings`, `activity`, user accounts, API tokens). This data
  is local and must never be baked into the repo.

If in doubt, ask: "would every installation of this product want this change?" If yes,
it is project-level and must be exported.

## What to do

Whenever a **project-level** prompt change has been made (by you or reported by the
user), before considering the work done:

1. Run the exporter from the repo root, with the stack running:

   ```bash
   python3 scripts/export-prompts.py
   ```

   It reads each built-in agent's current prompt from the live DB and rewrites the
   matching Go const in place (comments and layout preserved). Env overrides:
   `ARTEMIS_PG_CONTAINER` (default `artemis-postgres-1`), `PGUSER` (default `antifox`),
   `PGDATABASE` (default `artemis`).

2. Review the diff. Only the prompts you intend to standardise should change. If an
   unexpected const changed, that is a deployment-level edit that leaked in: revert it
   and keep only the intended one.

3. Build to confirm the source is valid (project standard: build in the container):

   ```bash
   docker run --rm -e GOFLAGS=-buildvcs=false -e GOCACHE=/tmp/gocache \
     -e GOPATH=/tmp/gopath -v "$PWD":/src -w /src golang:1.26.3 go build ./...
   ```

4. Commit the changed `agent/*.go` consts together with the feature/change they
   belong to, so the repo and the running database stay in sync.

Use `python3 scripts/export-prompts.py --check` to verify (exit 1 if any const is
stale) without writing, which is also suitable as a CI gate.

## Scope and extension

The exporter currently covers the six built-in agent prompts (`goals`, `planner`,
`worker`, `mainagent`, `auto`, `pentest`), which are the known DB-authoritative,
editable project state. If another project-level default becomes live-editable in a
way the seed does not capture, extend `scripts/export-prompts.py` (and this skill)
rather than hand-copying values out of the database.
