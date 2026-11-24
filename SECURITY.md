# Security Policy

OpenArtemis is an autonomous penetration-testing platform. It is offensive
security tooling: it must only ever be pointed at systems you are explicitly
authorized to test. This policy covers vulnerabilities **in OpenArtemis itself**
(the engine, API, web UI, and supporting code), not findings produced by running
it against a target.

## Supported versions

OpenArtemis is research / work-in-progress software with no stable release line
yet. Security fixes land on the `main` branch. Always run the latest `main`.

| Version | Supported |
| ------- | --------- |
| `main` (latest) | ✅ |
| older commits / forks | ❌ |

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public GitHub issue
for a vulnerability.

- Email: **francesco@oghabi.it**
- Please use a subject line starting with `[SECURITY]`.

Include as much of the following as you can:

- A description of the issue and its impact.
- The component affected (engine, API endpoint, web UI, auth/RBAC, MITM proxy,
  report builder, etc.) and the relevant commit hash.
- Steps to reproduce, a proof of concept, or a minimal test case.
- Any suggested remediation.

You will receive an acknowledgement of your report. We will work with you to
understand and resolve the issue, and will credit you in the fix unless you
prefer to remain anonymous.

## Disclosure

Please give us a reasonable window to investigate and ship a fix before any
public disclosure. We aim to triage promptly and to coordinate a disclosure
timeline with you.

## Scope

In scope:

- Authentication, session, and RBAC bypasses.
- Remote code execution, SSRF, path traversal, or injection in the engine, API,
  or web UI.
- Exposure of secrets, tokens, or stored credentials.
- Flaws that let an unauthorized party reach the orchestration engine, the MITM
  proxy, or the agents' tool execution.

Out of scope:

- Vulnerabilities in the **targets** you point OpenArtemis at (that is the
  tool's job to find, not a bug in OpenArtemis).
- Issues that require a pre-compromised host or already-authenticated admin
  misusing documented, intended capabilities.
- Reports from scanning third-party systems without authorization.

## Responsible use

OpenArtemis is released under AGPL-3.0 and is intended for authorized security
testing, research, and education only. Running it against systems you do not own
or lack written permission to test may be illegal. You are responsible for how
you use it.
