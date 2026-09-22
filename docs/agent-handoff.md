# KAVACH Agent Handoff

Last updated: 2026-07-22

## Current state

The hostile local release audit is implemented in the working tree and remains
intentionally uncommitted. The current branch is
`codex-release-verification`, based on dashboard redesign commit `a14c10e`.
Security work from `codex-final-audit` was independently reviewed and repaired
in this worktree rather than merged wholesale.

## High-impact corrections

- Runtime and adapters consume execution permits once at the enforcement
  boundary instead of invalidating them early.
- The gateway uses bounded server-held permits and approval tokens; clients
  cannot mint authority by serializing permit fields.
- Request mismatches leave legitimate one-time credentials usable for the
  correctly bound request.
- Output redaction covers filesystem, command, and network results and fails
  closed for binary, oversized, or redaction-error cases.
- Required audit writes fail closed, corrupt rows are not skipped, and approval
  events share the dashboard-visible chain.
- Approval transitions validate configuration, bounds, state, expiry, request
  digest, and matched rule identifiers without exposing raw tokens through API
  records.
- Gateway startup requires an operator-supplied exact 64-hex token. Credentials
  are neither generated nor printed.
- Static production routing handles `/dashboard/`, deep links, cache policy,
  and missing assets without swallowing API or probe routes.
- CLI startup loads every configured policy, wires persistent approvals and
  redaction, creates database parents, and verifies audit integrity before
  binding.
- The example configuration/policies, documented fixture, demo agent, and
  PowerShell runner now follow real schemas and native exit codes.
- Tracked SQLite database, WAL, and SHM runtime artifacts are removed; ignore
  rules retain generated databases, build output, dependencies, logs, and
  environment files outside version control.
- The dashboard preserves the premium redesign and uses real gateway data with
  memory-only bearer authentication.

## Operator notes

- Build `dashboard/dist` before production dashboard route checks.
- Set `KAVACH_GATEWAY_TOKEN` to exactly 64 hex characters before `kavach serve`.
- A dashboard refresh requires token re-entry by design.
- Pending approvals persist across restart. Raw tokens and permits do not.
- The repository has one PowerShell demo script and a separate `demo-agent`
  binary, not two script files.
- On Windows hosts that block script shims, use `npm.cmd` and invoke the demo
  with `powershell -ExecutionPolicy Bypass -File scripts/demo.ps1`.

## Final local verification

All requested local commands passed after the final fixes:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- debug and release workspace test suites: 644 tests each, zero failures
- `cargo doc --workspace --no-deps`
- `cargo bench --workspace --no-run`
- `npm.cmd --prefix dashboard ci`: 269 packages installed, 270 audited,
  zero vulnerabilities
- dashboard lint: zero warnings; dashboard tests: 39/39; production build:
  1,626 modules transformed
- every example binary: 6/6, 3/3, 4/4, 3/3, 6/6, and demo-agent 10/10
- `scripts/demo.ps1`: all six binaries passed
- default/example policies, example configuration, and request fixture validate;
  CLI doctor and audit verification pass
- all five GitHub workflow YAML files parse and contain `name`, `on`, and jobs
- `git diff --check` passes

`cargo-deny` and `cargo-audit` were not installed and were not installed by the
audit. `npm ci` reported zero known vulnerabilities. Remote GitHub Actions,
nightly fuzzing, Linux, and macOS did not run locally.

The fresh temporary gateway exercise produced 20 real audit events and covered
allow, deny, approval, approval-token exchange, real file read/create,
single-use replay rejection, full-chain verification, restart persistence,
wrong-token 401, dashboard deep links, shell/asset cache policy, and token-free
logs. Browser review covered login, all navigation pages, dark/light desktop,
390px mobile, populated/empty states, audit detail and approval dialogs, with
zero console errors.

No commit, merge, push, tag, release, or publication was performed. Review
`git diff`, `git diff --check`, and `git status --short` before staging.
