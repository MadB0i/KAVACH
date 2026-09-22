# KAVACH Implementation State

Last audited: 2026-07-22

This document records behavior observed in the current working tree. It
replaces the former phase checklist, whose test counts and several security
claims were stale.

## Implemented security path

The production runtime validates a `ToolRequest`, evaluates deterministic
policy with deny precedence, persists approval requests when required, issues
request-bound expiring permits, enforces them in filesystem/command/network
adapters, redacts output, and appends to a tamper-evident audit chain.

Confirmed invariants:

- malformed and unmatched requests fail closed;
- explicit deny outranks approval and allow;
- approval tokens and permits are request-bound, expiring, and single-use;
- mismatched requests do not consume a valid approval token or permit;
- the gateway never reconstructs execution authority from client metadata;
- filesystem adapters check workspace containment at execution time;
- network enforcement retains scheme, address, DNS, redirect, and cloud
  metadata protections;
- required redaction and audit failures stop execution;
- approval transitions use the runtime's dashboard-visible audit chain;
- corrupt approval/audit rows and query failures are returned as errors rather
  than silently skipped.

## Gateway and production dashboard

- `KAVACH_GATEWAY_TOKEN` is required at startup and must be exactly 64 hex
  characters. It is hashed for constant-time verification and is never
  generated or printed.
- `/health` and `/ready` remain public probes. `/api/*` requires bearer auth.
- `/dashboard`, `/dashboard/`, and deep dashboard routes serve the SPA shell.
  Missing `/dashboard/assets/*` paths remain 404 and never receive the shell.
- The shell is `no-store`; fingerprinted assets can use immutable caching; API
  and probe responses are not intercepted by SPA fallback.
- The dashboard uses the existing gateway contracts and real API data. Its
  bearer token exists only in React/module memory; a 401 or page refresh clears
  the authenticated session.
- The premium shell provides overview, live activity, approvals, audit,
  verification, policy, and health views in dark and light themes with desktop
  and mobile layouts.

## Persistence

Audit events and approval records persist in separate configured SQLite files.
Both stores create missing parent directories. Pending approvals and the audit
chain survive restart. Raw approved tokens and issued permits intentionally do
not; an approved request whose exchange did not happen before restart must be
requested again.

## Configuration and examples

`config/default-policy.toml`, `config/policy.example.toml`, and
`config/kavach.example.toml` use the parser's current schema. The example
configuration enables redaction, fail-closed behavior, audit startup
verification, and persistent approvals. The documented request fixture is
`tests/fixtures/request_allow.json`.

The workspace contains six executable example binaries and one PowerShell
orchestrator (`scripts/demo.ps1`). The separate `demo-agent` binary contains ten
scenarios. All examples use local or temporary resources.

## Verification snapshot

The final command matrix for this audit is recorded in
`docs/agent-handoff.md`. Local results do not imply that remote GitHub Actions
ran successfully. `cargo-deny`, `cargo-audit`, and nightly fuzzing are reported
separately when unavailable rather than installed automatically.

## Known limits

- KAVACH is not an OS sandbox. Run the gateway with least-privilege OS and
  network controls.
- Policy path matching is lexical; containment is enforced at the filesystem
  adapter boundary.
- Redaction rejects non-UTF-8 and oversized output rather than risking a leak.
- Entropy-based secret detection is heuristic.
- The MCP CLI currently uses a fixed local server identity unless embedded via
  the library API.
- Browser authentication is intentionally not persistent.
- No load, penetration, or hyperscale performance certification is claimed.
