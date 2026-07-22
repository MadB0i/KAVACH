# KAVACH

**KAVACH** is an open-source zero-trust security runtime for AI agents. It sits
between an AI agent and the tools that agent wants to use, evaluating every
tool call against explicit security policies before it reaches the filesystem,
shell, network, or secrets.

## Features

- **Policy engine** — declarative TOML policies with allow/deny/require-approval effects, 8-dimension AND-semantics matching (operation, resource kind, agent identity, trust level, capabilities, intent prefix, path globs, executables), deterministic evaluation, and fail-closed defaults.
- **Filesystem enforcement** — read, write, create, delete, move, list with lexical path normalization, workspace containment, atomic writes, size and entry limits.
- **Command enforcement** — executable allowlisting, destructive-operation detection, argument-length limits, timeout enforcement.
- **Network enforcement** — SSRF-protected HTTP/HTTPS with custom DNS resolver, scheme gating, header validation, redirect reauthorization, metadata endpoint blocking.
- **Secret redaction** — 8 detector modules (Bearer tokens, JWT, PEM keys, API-key assignments, GitHub tokens, AWS keys, exact secrets, entropy), deterministic and idempotent.
- **Tamper-evident audit chain** — SHA-256 hash-linked append-only event log with full-chain verification.
- **Human approval broker** — SQLite-backed 6-state approval machine with 256-bit CSPRNG tokens, SHA-256 at rest, single-use enforcement, configurable TTL.
- **Runtime orchestration** — end-to-end flow: evaluate → approve → permit → execute → redact → audit.
- **Local HTTP gateway** — Axum-based REST API with rate limiting, concurrency limiting, request timeout, body limit, CORS, security headers, bearer auth.
- **MCP security adapter** — Model Context Protocol proxy that evaluates tool calls against policy before forwarding.
- **CLI** — 13 subcommands with stable exit codes, JSON and human output modes, secret-sanitized errors.
- **Dashboard** — React/TypeScript SPA with live request view, audit timeline, pending approvals, policy management, system health, SSRF/redaction verification.
- **Property tests** — 17 proptest functions across 5 crates (core, policy, redaction, audit, approval).
- **Fuzz targets** — 7 cargo-fuzz targets for JSON, TOML, path, URL, redaction, audit, and MCP inputs.
- **Criterion benchmarks** — 8 benchmarks for validation, policy evaluation, glob matching, digest, redaction, audit, approval lookup, and runtime.

## Repository structure

```
kavach-core         Domain model, validation, permits, identifiers
kavach-policy       Declarative policy engine with TOML parsing
kavach-config       Layered configuration (defaults, TOML file, env overrides)
kavach-enforcement  Filesystem, command, and network enforcement adapters
kavach-redaction    Secret detection and redaction (8 detector modules)
kavach-audit        Tamper-evident append-only audit chain
kavach-approval     Human approval broker (SQLite-backed)
kavach-runtime      End-to-end runtime orchestration
kavach-gateway      Local HTTP REST gateway (Axum)
kavach-mcp          Model Context Protocol security proxy
kavach-cli          Command-line binary (13 subcommands)
kavach-examples     Working example binaries (6 examples, 10 scenarios)
dashboard           React/TypeScript SPA dashboard
fuzz/               Cargo-fuzz targets (nightly only)
```

## Quick start

```bash
# Build everything
cargo build --workspace --all-features

# Run all tests
cargo test --workspace --all-features

# Validate a policy
cargo run -p kavach-cli -- policy validate --file config/policy.example.toml

# Check a request against policy
cargo run -p kavach-cli -- policy check \
    --policy config/policy.example.toml \
    --request tests/fixtures/request_allow.json

# Build the dashboard served by the gateway
npm --prefix dashboard ci
npm --prefix dashboard run build

# Start the HTTP gateway after supplying a private 32-byte token.
# The gateway rejects missing/malformed tokens and never prints it.
KAVACH_GATEWAY_TOKEN="$(openssl rand -hex 32)" \
  cargo run -p kavach-cli -- serve --config config/kavach.example.toml

# Run the end-to-end demo
powershell -ExecutionPolicy Bypass -File scripts/demo.ps1
```

Open `http://127.0.0.1:7421/dashboard/` and enter the same token. The dashboard
keeps it in memory only; refreshing the page requires authentication again.
On PowerShell, use `npm.cmd` for the dashboard commands if script shims are
blocked, and generate the gateway token without printing it:

```powershell
$bytes = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:KAVACH_GATEWAY_TOKEN = [Convert]::ToHexString($bytes).ToLowerInvariant()
cargo run -p kavach-cli -- serve --config config/kavach.example.toml
```

## CLI exit codes

| Code | Meaning                     |
|------|-----------------------------|
| 0    | Success / request allowed   |
| 10   | Request denied              |
| 11   | Request requires approval   |
| 20   | Invalid input or config     |
| 21   | Policy error                |
| 22   | Audit error                 |
| 30   | Internal error              |
| 40   | Unavailable                 |

## Security principles

- **Default deny** — unknown requests, malformed input, and unmatched rules all fail closed.
- **Deny precedes** — explicit deny always overrides allow and require_approval.
- **Deterministic** — decisions depend only on policy and request, never on iteration order.
- **Fail-closed** — any I/O or audit error results in denial.
- **No secret logging** — secrets and raw credentials never appear in logs, errors, or debug output.
- **No unsafe code** — `#![forbid(unsafe_code)]` across the entire workspace.
- **No cloud required** — KAVACH operates fully offline.

## Supported platforms

| Platform | Status |
|----------|--------|
| Linux (x86_64) | CI workflow configured; not run in this local audit |
| macOS (x86_64) | CI workflow configured; not run in this local audit |
| Windows (x86_64) | Full local release matrix verified |

**Minimum Rust version**: 1.85 (edition 2024).

## Honest limitations

- **Symlink resolution**: Path normalization is lexical only. A symlink pointing outside the workspace cannot be detected by the policy engine itself; enforcement detects it at execution time.
- **Entropy detection**: Statistical by nature. UUIDs and hashes are excluded where possible, but not guaranteed.
- **No sandboxing**: Enforcement operates at the OS API level, not via containers or seccomp.
- **Performance**: Not tested at hyperscale. Benchmarks available in each crate's `benches/` directory.
- **Fuzz targets**: Require nightly Rust. Run separately via `cd fuzz && cargo fuzz run <target>`.
- **Gateway restart boundary**: Pending approval records and audit events persist, but raw approved tokens and issued permits are process-memory only and do not survive restart.
- **Dashboard sessions**: The bearer token is not persisted in browser storage. Refreshing or reopening the dashboard requires re-entry.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
