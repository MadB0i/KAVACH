# KAVACH Agent Handoff

Last updated: 2026-07-19

## State

The principal repository audit, security-flow repair, real gateway exercise,
dashboard redesign, and requested local verification matrix are complete.
Changes are intentionally uncommitted.

Do not rely on the former “phase complete” document. The independently verified
state is recorded in [implementation-state.md](implementation-state.md), and
the actual trust boundaries are in [architecture.md](architecture.md).

## Highest-impact fixes

- Runtime/adapters no longer double-consume execution permits.
- The gateway no longer trusts serialized client permits; permit execution uses
  a bounded server-side take-once registry.
- Runtime redaction and audit failures now fail closed.
- The CLI and approval broker share the runtime audit store, so approval
  transitions appear in the dashboard database.
- Approval transitions are preflighted before audit append; empty expiry sweeps
  do not write false events.
- Approval tokens are not exposed by the dashboard API. Approval and token
  exchange are separate endpoints, with the raw token retained in process
  memory.
- The gateway requires an operator-supplied exact 64-hex bearer token and never
  prints it.
- Dynamic approval routes, response envelopes, readiness checks, policy
  metadata, newest-first audit pagination, static dashboard routes, and SPA deep
  links were corrected.
- Config loading now preserves all policy files, persists the approval database
  setting, configures redaction, distinguishes timeouts from permit TTL, and
  verifies the audit chain before startup.
- Example policies/configuration and the documented request fixture are valid.
- The PowerShell demo resolves its own repository root and reports native
  command failures correctly.
- Tracked runtime SQLite artifacts were removed.
- The dashboard was rebuilt as a real dark enterprise security console, with
  memory-only authentication and no fabricated data.

## Verification

All requested Rust commands pass, including debug/release tests (633 listed
tests), docs, Clippy with warnings denied, and benchmark compilation. A clean
dashboard install reports 0 vulnerabilities; lint, 38 tests, and production
build pass. The direct demo passes 10/10 and `scripts/demo.ps1` passes every
example.

The live HTTP flow was also verified using fresh temporary databases:
evaluate → approval → approve → token exchange → server-held permit → real
filesystem execution → correlated audit events → valid chain. Pending approval
persistence across restart was checked.

## Operational notes

- Set `KAVACH_GATEWAY_TOKEN` to exactly 64 hexadecimal characters before
  `kavach serve`.
- Build the dashboard before expecting `/dashboard/` to be served.
- Browser authentication is intentionally lost on refresh.
- Pending approvals persist; raw approved tokens and permits do not survive a
  gateway restart.
- The repository contains one PowerShell demo script and one separate
  `demo-agent` binary, not two script files.
- On this Windows host, use `npm.cmd` and an explicit PowerShell execution-policy
  bypass because the `.ps1` command shims are machine-blocked.

## Worktree

No commit, push, tag, release, or publication was performed. The dirty worktree
contains the audited implementation/docs/dashboard changes and intentional
deletions of tracked database artifacts. Inspect `git status --short` before any
future staging.
