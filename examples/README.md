# KAVACH Working Examples

These examples demonstrate KAVACH's zero-trust runtime enforcement using
production crate APIs. Each is a standalone Rust binary under
`kavach-examples/src/bin/`.

## Prerequisites

- Rust 1.85+ (edition 2024)
- Standard build tools (`cargo`, `rustc`)

## Running All Examples

```powershell
# From the repository root:
cargo build --package kavach-examples --bins
cargo run --package kavach-examples --bin basic-policy
cargo run --package kavach-examples --bin guarded-filesystem
cargo run --package kavach-examples --bin guarded-command
cargo run --package kavach-examples --bin guarded-network
cargo run --package kavach-examples --bin approval-flow
cargo run --package kavach-examples --bin demo-agent
```

Or use the demo orchestration script:

```powershell
.\scripts\demo.ps1
```

## Example Index

### `basic-policy`
Policy evaluation using `PolicyEngine` directly. No filesystem needed.
- Policy construction with allow/deny/approval-required rules
- Glob pattern matching (`src/**`, `**/.env`)
- Default deny when no rule matches
- No runtime or I/O required

### `guarded-filesystem`
Filesystem read enforcement with `KavachRuntime`.
- **Setup**: Creates temp workspace with `src/main.rs` and `.env`
- **Allowed**: `src/main.rs` read via `allow-src-read` rule
- **Denied**: `.env` read via `deny-env` rule
- **Denied (default)**: Non-matching paths like `target/debug/app.exe`
- **Cleanup**: Removes temp directory

### `guarded-command`
Command execution enforcement.
- **Allowed**: `echo`/`cmd.exe /c echo` (harmless) via `allow-echo` rule
- **Denied**: `shutdown` (dangerous) via `deny-shutdown` rule
- **Denied (default)**: Unknown executables
- **Dry-run mode**: Policy still evaluated, execution blocked

### `guarded-network`
Local HTTP enforcement with SSRF protection.
- **Setup**: Starts a minimal TCP server on `127.0.0.1:0` (random port)
- **Allowed**: `http://127.0.0.1:<port>/` via `allow-localhost` rule
- **Denied**: `http://169.254.169.254/latest/meta-data/` (SSRF)
- **Denied (default)**: Non-allowlisted hosts like `example.com`
- **Cleanup**: Stops the HTTP server

### `approval-flow`
Full approval lifecycle.
- **Evaluate**: File deletion → `ApprovalRequired`
- **Approve**: Human approves → gets `ApprovalToken`
- **Consume**: First use succeeds
- **Replay**: Same token rejected on second use
- **Audit verify**: Chain validated after all operations

### `demo-agent`
End-to-end demo combining all scenarios. The scripted `demo.ps1`
orchestrates all 10 checks:
1. Allowed project-file read
2. Denied secret-file read (with sanitization verified)
3. Approval-required file deletion
4. Allowed harmless command
5. Denied dangerous command
6. Allowed local HTTP request
7. Blocked SSRF destination
8. Response secret redaction
9. Single-use approval replay rejection
10. Audit-chain verification

## Safety

All examples use:
- **Temporary directories** (`std::env::temp_dir()`) — never touch real files
- **In-memory databases** where possible, isolated SQLite files otherwise
- **Local HTTP server** on random ports — no public internet access
- **Non-destructive commands** — denied commands never execute
- **Safe cleanup** — all temp files removed on exit

## No Fake Data

Every result is produced by real KAVACH enforcement:
- `KavachRuntime::evaluate()` with compiled `PolicyEngine`
- `KavachRuntime::execute()` dispatching to `FilesystemEnforcer`,
  `CommandEnforcer`, and `NetworkEnforcer`
- `ApprovalBroker::approve()` and `consume_approval()` for approval flow
- `AuditStore::verify_full()` for chain verification
- `CompositeRedactor::redact_text()` for secret redaction
