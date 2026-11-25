#!/usr/bin/env python3
"""Export the live, DB-resident built-in agent prompts back into the Go source.

The platform treats the DB as the authoritative, editable source for each built-in
agent's system prompt: the in-code `<agent>DefaultTmpl` consts are only the seed
(inserted when an agent has no prompt yet) and the render fallback. That means a
prompt tuned through the UI lives ONLY in the local Postgres, so a fresh checkout /
install would seed the old default and behave differently.

This script closes that gap. It reads each built-in agent's CURRENT prompt from the
running database and rewrites the matching `const <name>DefaultTmpl = ` + "`...`" + `
raw-string literal in the Go source, in place (comments and file layout untouched).
Run it whenever a built-in prompt has been changed in a way that should become the
project standard (not for client-specific or task-specific tweaks), then commit the
resulting diff. See .claude/skills/db-project-export/SKILL.md.

Config via env (sensible defaults for the dev stack):
  ARTEMIS_PG_CONTAINER (default: artemis-postgres-1)
  PGUSER               (default: antifox)
  PGDATABASE           (default: artemis)

Usage:
  python3 scripts/export-prompts.py           # rewrite the Go consts from the DB
  python3 scripts/export-prompts.py --check    # exit 1 if the Go consts are stale (CI)
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

# agent key (agents.key) -> (source file, Go const name)
AGENTS = {
    "goals": ("agent/goals.go", "goalsDefaultTmpl"),
    "planner": ("agent/planner.go", "plannerDefaultTmpl"),
    "worker": ("agent/worker.go", "workerDefaultTmpl"),
    "mainagent": ("agent/mainagent.go", "mainAgentDefaultTmpl"),
    "auto": ("agent/promptcatalog.go", "autoDefaultTmpl"),
    "pentest": ("agent/promptcatalog.go", "pentestDefaultTmpl"),
    "verifier": ("agent/verifier.go", "verifierDefaultTmpl"),
}

CONTAINER = os.environ.get("ARTEMIS_PG_CONTAINER", "artemis-postgres-1")
PGUSER = os.environ.get("PGUSER", "antifox")
PGDATABASE = os.environ.get("PGDATABASE", "artemis")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fetch_prompt(key: str) -> str:
    """Return the agent's current (active) prompt body from the live DB."""
    sql = (
        "SELECT p.template_text FROM agents a "
        "JOIN agent_prompts p ON p.id = a.current_prompt_id "
        f"WHERE a.key = '{key}';"
    )
    out = subprocess.run(
        ["docker", "exec", CONTAINER, "psql", "-U", PGUSER, "-d", PGDATABASE,
         "-t", "-A", "-c", sql],
        check=True, capture_output=True, text=True,
    ).stdout
    # psql -t -A appends a trailing newline; also normalise leading/trailing
    # blank lines so the committed const stays clean and diff-friendly.
    return out.strip("\n")


def rewrite_const(path: str, const_name: str, body: str) -> bool:
    """Replace the raw-string body of `const <const_name> = `...`` in `path`.

    Returns True if the file content changed. Raises if the const is not found
    or the body contains a backtick (which a Go raw-string literal cannot hold).
    """
    if "`" in body:
        raise SystemExit(
            f"ERROR: prompt for const {const_name} contains a backtick; a Go "
            f"raw-string literal cannot represent it. Resolve manually."
        )
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    pattern = re.compile(r"(const " + re.escape(const_name) + r" = `).*?(`)", re.DOTALL)
    if not pattern.search(text):
        raise SystemExit(f"ERROR: const {const_name} not found in {path}")
    new_text = pattern.sub(lambda m: m.group(1) + body + "`", text, count=1)
    if new_text == text:
        return False
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new_text)
    return True


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    stale = []
    changed = []
    for key, (rel_path, const_name) in AGENTS.items():
        path = os.path.join(REPO_ROOT, rel_path)
        body = fetch_prompt(key)
        if not body:
            print(f"  [!] {key}: empty prompt in DB, skipped")
            continue
        if check_only:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            m = re.search(
                r"const " + re.escape(const_name) + r" = `(.*?)`", text, re.DOTALL)
            current = m.group(1) if m else None
            if current != body:
                stale.append(key)
                print(f"  [stale] {key} ({const_name})")
            else:
                print(f"  [ok]    {key}")
        else:
            if rewrite_const(path, const_name, body):
                changed.append(key)
                print(f"  [updated] {key} ({const_name})")
            else:
                print(f"  [same]    {key}")

    if check_only:
        if stale:
            print(f"\n{len(stale)} prompt(s) differ from the DB: run "
                  f"scripts/export-prompts.py and commit.")
            return 1
        print("\nAll built-in prompts are in sync with the DB.")
        return 0

    if changed:
        print(f"\nUpdated {len(changed)} const(s): {', '.join(changed)}.")
        print("Review the diff and commit it as part of the project.")
    else:
        print("\nNo changes: Go consts already match the live DB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
