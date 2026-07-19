# KAVACH Implementation State

Last independently audited: 2026-07-19

## Current status

KAVACH is a working local zero-trust runtime, not a release artifact or an OS
sandbox. The workspace compiles with all targets and features, all 633 Rust
tests pass in debug and release profiles, the 38 dashboard tests pass, all
benchmarks compile, and every example completes using local or temporary
resources.

The repository contains eleven production Rust crates, one example crate, a
React/TypeScript dashboard, seven out-of-workspace fuzz targets, CI/security
workflows, policies, configuration examples, and one PowerShell demo script.

## Security-sensitive execution flow

The audited flow is:

```text
ToolRequest
  -> domain validation
  -> deterministic policy evaluation
  -> approval state transition when required
  -> request-bound permit issuance
  -> server-side permit lookup
  -> adapter verification and one-time permit consumption
  -> filesystem / command / network enforcement
  -> output redaction
  -> append-only audit event
```

The following invariants are implemented and covered by tests:

- Unknown, malformed, unmatched, expired, replayed, or incorrectly bound
  requests fail closed.
- Explicit deny takes precedence over approval and allow.
- Approval tokens are CSPRNG values, hashed at rest, compared in constant time,
  request-digest bound, and single use.
- The gateway never accepts a client-supplied permit as authority. Issued
  permits are retained in a bounded, process-local registry and removed on
  execution.
- A runtime permit is validated without consuming it; the selected enforcement
  adapter consumes it exactly once immediately before the side effect.
- Filesystem enforcement canonicalizes and contains paths at execution time.
- Network enforcement rejects blocked address classes, metadata endpoints,
  unsafe schemes/headers, DNS rebinding targets, and unsafe redirects.
- Redaction and audit failures prevent a successful raw response.
- Approval and runtime events use the same dashboard-visible audit chain.
- Empty or invalid approval transitions do not produce false transition events.
- The audit chain is SHA-256 hash linked and can be verified before startup.

See [architecture.md](architecture.md) for component and trust boundaries.

## Gateway and dashboard

The gateway:

- binds to loopback by default;
- requires `KAVACH_GATEWAY_TOKEN` to contain exactly 64 hexadecimal characters;
- never generates or prints an operator token;
- creates missing database parent directories;
- verifies the audit chain before binding;
- exposes public `/health` and `/ready` probes;
- returns the standard response envelope from API endpoints;
- serves the production SPA at `/dashboard/`, including deep routes;
- keeps raw approval tokens and issued permits only in process memory.

The dashboard is a real API client. It does not contain mock metrics or sample
events. Its gateway bearer token is held only in React memory, never in
`localStorage` or `sessionStorage`, so refresh requires re-authentication.

The redesigned interface uses a dark graphite/navy KAVACH identity, dense
metrics sourced from the latest 100 audit events, a compact command bar and
sidebar, a correlated event timeline, real tables and filters, accessible
drawers/dialogs, loading/empty/error states, restrained motion, responsive
breakpoints, and reduced-motion support.

## Configuration and examples

- `config/policy.example.toml`: valid default-deny example policy, 8 rules.
- `config/default-policy.toml`: valid default-deny runtime policy, 6 rules,
  including explicit sensitive-file denies.
- `config/kavach.example.toml`: valid gateway/runtime/approval configuration.
- `tests/fixtures/request_allow.json`: valid request accepted by the documented
  policy check command.
- `cargo run -p kavach-examples --bin demo-agent`: 10/10 scenarios pass with a
  valid 12-event audit chain.
- `scripts/demo.ps1`: resolves the repository from the script location,
  propagates native command failures, and passes from outside the repository
  root. It runs all six binaries: 6/6 basic policy, 3/3 filesystem, 4/4
  command, 3/3 network, 6/6 approval, and 10/10 end-to-end scenarios.

There is one PowerShell demo script in the repository. The end-to-end
`demo-agent` binary is the separate second real-run entry point.

## Real gateway verification

A production dashboard build and gateway were exercised on
`127.0.0.1:7421` with isolated, initially absent nested SQLite paths:

- startup created the audit and approval database directories;
- no bearer token appeared in gateway output;
- unauthenticated and incorrect authentication returned 401;
- authenticated status, policies, audit events, and verification used real
  data;
- `/dashboard/`, assets, and deep SPA routes returned 200;
- a file-create request returned `ApprovalRequired`;
- approve, token exchange, and execute completed through HTTP;
- the server-held permit was consumed once;
- the local temporary file was created and removed;
- correlated approval and execution events appeared in the same audit database;
- full audit-chain verification remained valid;
- a pending approval survived a gateway restart.

## Visual review

The production dashboard was inspected in the in-app browser against the real
gateway. Reviewed states included login, overview, audit timeline, event detail
drawer, approvals table, and approval confirmation dialog. Visual inspection
caught and fixed an inherited white button surface in the dark event timeline.

The browser viewport override reported success but retained a 1280-pixel layout,
so no genuine mobile screenshot was produced. Mobile behavior is covered by
responsive CSS and code review, not claimed as device-level visual validation.

## Verification results

Executed from a clean dependency install on Windows:

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace --all-targets --all-features` | PASS |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS, zero warnings |
| `cargo test --workspace --all-features` | PASS, 633 listed tests |
| `cargo test --release --workspace --all-features` | PASS |
| `cargo doc --workspace --no-deps` | PASS |
| `cargo bench --workspace --no-run` | PASS |
| `npm --prefix dashboard ci` | PASS via `npm.cmd`, 268 packages, 0 vulnerabilities |
| `npm --prefix dashboard run lint` | PASS via `npm.cmd` |
| `npm --prefix dashboard run test` | PASS via `npm.cmd`, 38/38 |
| `npm --prefix dashboard run build` | PASS via `npm.cmd`, 71 modules |
| `cargo run -p kavach-examples --bin demo-agent` | PASS, 10/10 |
| `scripts/demo.ps1` | PASS, all six examples |

On this Windows host, the `npm` and direct `.ps1` PowerShell shims are blocked
by the machine execution policy. Verification used the equivalent
`npm.cmd` executable and
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/demo.ps1`.
Cargo emitted non-fatal Windows incremental-cache garbage-collection warnings
during the final script run; the build and all examples exited successfully.

## Known limitations

- Policy path matching is lexical. Filesystem-aware containment is enforced by
  the adapter, including symlink/canonical-path checks.
- KAVACH is not an OS-level sandbox and does not provide container, seccomp, or
  process-namespace isolation.
- Audit and approval records use separate SQLite databases. Broker transitions
  are serialized and audit-first, but there is no cross-database atomic
  transaction.
- Raw approved tokens and issued permits are intentionally process-local. A
  restart preserves pending approvals and records but invalidates an
  already-approved token awaiting exchange and every issued permit.
- Entropy-based redaction is statistical. Invalid UTF-8 output is rejected
  rather than lossily converted.
- Fuzz targets require nightly Rust and were not executed in this audit.
- `cargo deny`, `cargo audit`, CI runners, release packaging, and
  platform-matrix jobs were not part of this local command matrix.
- No load, penetration, or hyperscale performance test was performed.
- Mobile responsive behavior did not receive a real viewport screenshot because
  of the browser tooling limitation described above.

## Repository hygiene

Tracked runtime SQLite files under `data/` were identified as generated junk and
removed. Generated `target/`, `dashboard/node_modules/`, `dashboard/dist/`, and
runtime databases remain ignored. No commit, push, tag, package publication, or
release action was performed.
