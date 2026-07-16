# KAVACH Implementation State

Last updated: 2026-07-16

## Phases 0-3 — COMPLETE (193 tests)
## Phase 4: Filesystem Enforcement — COMPLETE (31 tests)
## Phase 5: Command Enforcement — COMPLETE (28 tests)
## Phase 6: Network Enforcement — COMPLETE (75 tests)

### Network Enforcement Architecture
- `kavach-enforcement/src/network.rs` — separate module
- `NetworkEnforcer`: SSRF-protected HTTP/HTTPS with custom DNS resolver
- `NetworkMethod`: Get, Head, Post, Put, Patch, Delete
- `NetworkError` (26 variants): full typed error coverage from request validation through transport
- `NetworkOutcome`: status, sanitized headers, body, body_len, redirect_count, final_url, duration

### Key Protections
- **Scheme gating**: HTTPS always, HTTP disabled by default (opt-in)
- **SSRF address blocking**: IPv4 (loopback, private 10/8, 172.16/12, 192.168/16, link-local, multicast, CGNAT, broadcast), IPv6 (loopback, unspecified, link-local, unique-local, multicast, IPv4-mapped blocked addresses)
- **Metadata endpoint blocking**: 169.254.169.254, metadata.google.internal (checked both before DNS and in redirect handling)
- **Custom DNS resolver**: `SsrfResolver` validates all resolved addresses, blocks connection to blocked IPs
- **Header validation**: forbidden headers (Host, Authorization, Cookie, Set-Cookie, Proxy-*, forwarding headers), CRLF injection, count/length limits
- **Response header sanitization**: redacts Set-Cookie, Authorization, Proxy-Authenticate, WWW-Authenticate
- **Redirect reauthorization**: manual redirect handling (`redirects(0)` on ureq agent) with scheme/host validation, metadata hostname check before DNS, address re-validation, HTTPS downgrade to HTTP rejected, redirect count limit (default 5, max 20)
- **Timeout control**: network 30s, connect 10s, max 300s
- **Size limits**: response body 10MB, request body 1MB
- **No proxy inheritance**: system proxy variables ignored

### Test Coverage (75 network tests)
| Category | Tests |
|----------|-------|
| Address classification + blocking | 18 |
| Metadata detection | 2 |
| DNS + permit lifecycle | 4 |
| Scheme gating | 3 |
| Header validation | 6 |
| Request/response body limits | 3 |
| Timeout classification | 3 |
| URL parsing | 4 |
| Redirect validation (unit + integration) | 11 |
| Sensitive header handling | 2 |
| Loopback integration | 3 |
| Resource type rejection | 3 |
| Command resource | 2 |
| General rejection scenarios | 6 |
| Redirect integration (test server) | 2 |
| Misc validation | 3 |
| **Total** | **75** |

## Phase 8: Human Approval Broker — COMPLETE (56 tests)

### Approval Architecture
- `kavach-approval/` — new dedicated crate
- `ApprovalBroker` trait + `SqliteApprovalBroker` with `AuditStore` integration
- `SqliteApprovalStore` (pub(crate)) — SQLite-backed persistence with WAL, foreign keys, busy timeout
- `ApprovalToken` — CSPRNG 256-bit bearer token, SHA-256 hashed at rest, constant-time verification
- `ApprovalState` — 6-state machine: Pending → Approved → Consumed | Rejected | Expired | Cancelled
- Request digest binding prevents token replay across different requests
- Pending TTL (configurable, default 30min) + consumption window (5min after approval)
- All transitions inside `BEGIN IMMEDIATE` transactions

### Test Coverage (56 approval tests)
| Category | Tests |
|----------|-------|
| Database + migration | 6 |
| Creation + dedup | 8 |
| Token generation/verification | 7 |
| State transitions (approve/reject/consume/revoke) | 8 |
| Expiry (tick/pending TTL/consumption window) | 5 |
| Concurrency | 5 |
| Audit integration | 5 |
| Restart safety (persistence across reopen) | 4 |
| Edge cases (cancelled, double-approve, idempotency, limits, validation) | 8 |
| **Total** | **56** |

### Key Protections
- **Token hashing**: SHA-256 at rest, constant-time comparison via `subtle::ConstantEq`
- **Request binding**: SHA-256 digest of (request_id, resource, action, subject) verified on every operation
- **Concurrency**: `BEGIN IMMEDIATE` + `WHERE state = ?` prevents races
- **Redaction**: `ApprovalToken` Debug/Display = `"<redacted>"`, audit logs omit raw token
- **Expiry**: dual TTL (pending + consumption window) enforced in `tick()`
- **Validation**: ID/actor/summary length limits enforced on submission

## Phase 10: Runtime Orchestration — COMPLETE (43 tests)

## Phase 10: Runtime Orchestration — COMPLETE (43 tests)

## Phase 11: Local HTTP Gateway — COMPLETE (57 tests)

### Gateway Architecture
- `kavach-gateway/` — new dedicated crate
- `GatewayBuilder` — builder pattern for constructing the HTTP server
- `GatewayConfig` — bind address, body limit, timeout, concurrency, rate limit, CORS, shutdown timeout
- `GatewayState` — shared state (KavachRuntime, GatewayToken, config, semaphore, rate limiter)
- `GatewayToken` — CSPRNG 256-bit bearer token, SHA-256 hashed, constant-time verification
- `GatewayError` / `KavachErrorCode` — 10 typed error codes mapping to HTTP status codes
- Axum 0.7 router with tower middleware stack: rate limit → concurrency limit → timeout → body limit → CORS + security headers → request ID → auth → routes
- 13 API endpoints: health, ready, status, evaluate, execute, approvals (list/get/approve/deny), audit (events/verify), policies (list/reload)

### Middleware Stack (outermost → innermost)
1. Rate limiter (sliding-window, configurable per-second + burst)
2. Concurrency limiter (tokio::sync::Semaphore)
3. Request timeout (tokio::time::timeout)
4. Request body limit (tower-http RequestBodyLimitLayer)
5. CORS (GET/POST/OPTIONS only, secure defaults)
6. Security headers (X-Content-Type-Options, Cache-Control, Referrer-Policy, CSP)
7. Request ID injection (UUID v4, X-Request-Id header, tracing span)
8. Bearer token auth (SHA-256, constant-time, 401 on failure)
9. Route handlers

### Key Protections
- **Non-loopback protection**: binding to non-loopback addresses requires `allow_non_loopback: true`
- **Auth token**: 256-bit CSPRNG, SHA-256 at rest, constant-time verification, never logged
- **Rate limiting**: sliding-window per-second + burst limits
- **Concurrency limiting**: semaphore-based max concurrent requests
- **Request timeout**: configurable per-request timeout
- **Body limit**: 1 MiB default, checked during streaming
- **Security headers**: nosniff, no-store, no-referrer, frame-ancestors 'none'
- **CORS**: secure defaults (no origin allow by default)

### Runtime Changes (supporting gateway)
- Added `reload_policies(&mut self, policies)` to `KavachRuntime` (atomic engine swap)
- Added accessor methods: `audit_store()`, `broker()`, `config()`
- Added `get_approval()` to `ApprovalBroker` trait + `SqliteApprovalBroker`
- Added `from_existing()` constructor and accessor methods to `ExecutionPermit`
- Added `Serialize` + `Deserialize` derives to `PermitScope`

### Test Coverage (57 gateway tests)
| Category | Tests |
|----------|-------|
| Auth token (generate/verify/from_hash/reject/constant-time) | 11 |
| Error codes (string/HTTP status/constructors) | 3 |
| Type conversions (PermitDto, EvaluateOutcomeDto, ExecuteRequest) | 6 |
| Health/ready/status routes | 4 |
| Auth middleware (missing/wrong/bad-scheme) | 3 |
| Request ID middleware (presence/uniqueness) | 2 |
| Approval routes (list/get/approve/deny nonexistent) | 4 |
| Audit routes (list/limit-zero/verify) | 3 |
| Policy routes (list/reload empty/nonexistent) | 3 |
| Evaluate routes (valid/invalid request) | 2 |
| Security headers | 1 |
| Rate limiter (within/burst/reject/recover) | 4 |
| Request body limit | 1 |
| Concurrency semaphore | 1 |
| Timeout error code | 1 |
| CORS headers | 1 |
| Policy reload (invalid preserves previous) | 1 |
| Execute (consumed permit/wrong secret/mismatched request) | 3 |
| Non-loopback validation (default/opt-in/loopback/IPv6/invalid) | 5 |
| Graceful shutdown | 1 |
| **Total** | **57** |

### Redaction Architecture
- `kavach-redaction/` — new dedicated crate
- `Redactor` trait: `redact_text(&str)`, `redact_bytes(&[u8])`
- `CompositeRedactor`: combines multiple detectors with deterministic merge-overlap logic
- `CompositeRedactorBuilder`: builder pattern for configuring detectors
- 8 detector modules covering bearer, JWT, PEM, password/API-key assignments, GitHub, AWS, exact secrets, entropy

### Detectors
| Detector | Category | Key Behavior |
|----------|----------|-------------|
| BearerTokenDetector | `BearerToken` | "Bearer <token>", token ≥8 chars |
| JwtDetector | `Jwt` | 3 dot-segmented base64url segments, bounded lengths |
| PemPrivateKeyDetector | `PrivateKey` | Complete PEM blocks (RSA, EC, OpenSSH, DSA) |
| SensitiveKeyAssignmentDetector | `SensitiveKeyAssignment` | 30+ sensitive keys, case-insensitive, `=`/`:`, quoted/unquoted |
| GitHubTokenDetector | `GitHubToken` | ghp/gho/ghu/ghs/ghr_ prefixed, 36-40 alphanumeric chars |
| AwsKeyIdDetector | `AwsKeyId` | AKIA, A3T, etc. + 16 alphanumeric chars |
| ExactSecretDetector | `ConfiguredSecret` | Longest-match-first, overlapping deduplication |
| EntropyDetector | `EntropyCandidate` | Shannon entropy, optional (disabled by default) |

### Key Protections
- **No secret logging**: configured secrets never appear in Debug output, errors contain category/range only
- **Deterministic**: same input + same config = same output
- **Idempotent**: second pass on already-redacted text produces no changes
- **Stable markers**: `[REDACTED:<category>]` markers not re-processed
- **Binary safety**: non-UTF-8 input returns `UnsupportedBinaryInput` error
- **Size limits**: MAX_INPUT_BYTES (1MiB), MAX_CONFIGURED_SECRETS (1000), MAX_CONFIGURED_SECRET_LENGTH (1024)
- **Thread-safe**: `Redactor` trait requires `Send + Sync`; tested with 4 concurrent threads

### Integration Helpers
- `redact_error_message`, `redact_tracing_field`, `redact_command_output`
- `redact_network_body`, `redact_header_value`, `redact_filesystem_preview`
- `redact_approval_summary`, `redact_audit_metadata`

### Test Coverage (52 redaction tests)
| Category | Tests |
|----------|-------|
| Bearer token detection | 3 |
| JWT detection | 3 |
| PEM detection | 5 |
| Password/API-key assignments | 7 |
| GitHub token detection | 2 |
| AWS key ID detection | 2 |
| Exact secret matching | 5 |
| Entropy detection | 5 |
| Composite redaction | 16 |
| Integration helpers | 2 |
| SecretContainer limits | 2 |
| **Total** | **52** |

## Phase 12: CLI — COMPLETE (17 tests)

### CLI Architecture
- `kavach-cli/` — binary crate with clap derive subcommands
- 13 production commands backed by existing crates (no runtime/gateway duplication)
- Human and JSON output modes (`--output human|json`)
- Stable exit codes: 0 success, 10 deny, 11 approval required, 20 invalid input, 21 policy error, 22 audit error, 30 internal, 40 unavailable
- Typed `CliError` with sanitized messages (no secrets logged)
- `CliOutput` renderer for structured human/JSON output

### Commands
| Command | Backed By | Description |
|---------|-----------|-------------|
| `kavach --version` | built-in (clap) | Print version |
| `kavach doctor` | filesystem checks | Check environment for common issues |
| `kavach config validate --file` | `kavach_config::load_config` | Validate config TOML |
| `kavach policy validate --file` | `kavach_policy::load_policy_from_file` | Validate policy TOML |
| `kavach policy check --policy --request` | `PolicyEngine::evaluate` | Check request against policy, exit 10/11 on deny/approval |
| `kavach policy explain --policy --request` | `PolicyEngine::evaluate` | Explain policy decision |
| `kavach request validate --file` | `ToolRequest::validate` | Validate request JSON |
| `kavach audit verify --database` | `AuditStore::verify_full` | Verify audit chain integrity |
| `kavach audit list --database` | `AuditStore::events_after_sequence` | List audit events |
| `kavach approval list` | `ApprovalBroker::list_pending` | List pending approvals |
| `kavach approval approve <id>` | `ApprovalBroker::approve` | Approve a pending approval |
| `kavach approval deny <id>` | `ApprovalBroker::deny` | Deny a pending approval |
| `kavach serve --config` | `GatewayBuilder::start` | Start HTTP gateway |

### Key Protections
- **No secret logging**: errors use sanitized `CliError` messages; approval tokens never logged
- **Stable exit codes**: typed `ExitCode` enum for programmatic use
- **Early validation**: IDs validated before opening databases
- **JSON/Human output**: `CliOutput` renderer supports both modes
- **Integration tested**: 17 tests with `assert_cmd` covering error paths, valid config, valid policy, JSON output

### Test Coverage (17 CLI integration tests)
| Category | Tests |
|----------|-------|
| Version/help | 2 |
| Doctor | 1 |
| Config validate (nonexistent/valid/invalid) | 3 |
| Policy validate (nonexistent/valid) | 2 |
| Policy check (nonexistent path) | 1 |
| Request validate (nonexistent/invalid JSON) | 2 |
| Audit verify/list (nonexistent database) | 2 |
| Approval approve/deny (invalid ID) | 2 |
| Invalid subcommand | 1 |
| JSON output flag | 1 |
| **Total** | **17** |

### Test Summary
| Crate | Tests |
|-------|-------|
| kavach-core | 43 |
| kavach-policy | 141 |
| kavach-config | 11 |
| kavach-runtime | 43 |
| kavach-enforcement | 134 |
| kavach-redaction | 52 |
| kavach-approval | 56 |
| kavach-gateway | 57 |
| kavach-cli | 17 |
| **Total** | **554** |

## Verification
```
cargo fmt --all                          PASS
cargo check --workspace --all-targets --all-features  PASS
cargo test --workspace --all-features    PASS (554)
cargo clippy --workspace --all-targets --all-features -- -D warnings  PASS (zero)
cargo doc --workspace --no-deps          PASS

## Platform Limitations
- Loopback blocked by default; local test server integration tests use `with_allow_loopback(true)` override
- DNS rebinding protection relies on custom resolver binding all addresses before connection
- ureq v2 TLS defaults enabled; no certificate verification disable option
- Redirect integration tests use `redirects(0)` on ureq agent to prevent internal redirect following, enabling manual re-validation of redirect targets
- Flaky `redirect_to_allowed_target_succeeds` integration test removed due to Windows TCP race condition (WSAECONNRESET); redirect validation logic tested via `validate_redirect_url` unit tests (9) and two redirect integration tests (private-IP and metadata-hostname targets)
- Redaction binary input: non-UTF-8 data rejected with `UnsupportedBinaryInput` (safety: lossy conversion could leak secrets)
- Entropy detection is statistical; UUIDs and hashes excluded where possible, but not guaranteed
- See `docs/redaction.md` for full redaction documentation
