# Changelog

All notable changes to KAVACH are documented in this file.

## [0.1.0] — 2026-07-16

### Added

- Domain model: agent subjects, tool requests, operations, resources, permits, authorization decisions
- Declarative policy engine with TOML parsing, 8-dimension matching, precedence rules
- Filesystem enforcement with workspace containment and atomic writes
- Command enforcement with executable allowlisting and timeout
- Network enforcement with SSRF protection, DNS validation, redirect reauthorization
- Secret redaction: 8 detector modules (Bearer, JWT, PEM, assignments, GitHub, AWS, exact, entropy)
- Tamper-evident audit chain with SHA-256 hash linking and full verification
- Human approval broker: SQLite-backed, 256-bit tokens, 6-state machine, configurable TTL
- Runtime orchestration: evaluate → approve → permit → execute → redact → audit
- Local HTTP gateway: Axum REST API with rate limiting, auth, CORS, security headers
- MCP security adapter: intercepts tool calls, evaluates against policy
- CLI: 13 subcommands with stable exit codes, JSON/human output
- Dashboard: React/TypeScript SPA with 10 pages
- Property tests: 17 proptest functions across 5 crates
- Fuzz targets: 7 cargo-fuzz targets (nightly only)
- Criterion benchmarks: 8 benchmarks across 6 crates
- CI/CD: GitHub Actions for fmt, check, clippy, test, doc, bench, dashboard
- Security scanning: cargo-deny, cargo audit, CodeQL, npm audit, dependency review
- Release workflow: cross-platform builds with SHA-256 checksums
- Working examples: 6 example binaries covering all enforcement scenarios

### Security

- `#![forbid(unsafe_code)]` across the entire workspace
- Default-deny policy evaluation with fail-closed on errors
- No secret logging: credentials never appear in errors, logs, or debug output
- SHA-256 audit chain with tamper detection
- CSPRNG 256-bit approval tokens, SHA-256 hashed at rest, constant-time comparison
- Input validation with `deny_unknown_fields` on all deserialization
- SSRF protection via custom DNS resolver and metadata endpoint blocking
