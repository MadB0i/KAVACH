# KAVACH Implementation Roadmap

Last updated: 2026-07-13

This document outlines the ordered implementation phases for completing KAVACH
as a production-grade zero-trust security runtime for AI agents. Each phase
derives from the actual state of the repository, not assumptions.

---

## Existing Capabilities (Completed)

### kavach-core (`crates/kavach-core`)

| Component | Status | Tests |
|-----------|--------|-------|
| Validated identifier newtypes (AgentId, SessionId, RequestId, RuleId, PolicyId, ApprovalId) | Done | 0 |
| Domain error hierarchy (DomainError, DomainErrorKind, FieldPath, DomainValidationError) | Done | 0 |
| Agent subject model (Capability, TrustLevel, CapabilitySet, AgentSubject, AgentSubjectBuilder) | Done | 0 |
| Lexical path normalization (NormalizedPath, PathError, PathErrorKind) — no filesystem access, no symlink resolution | Done | 0 |
| Network resource types (NetworkScheme, NetworkHost, NetworkPort, NetworkResource) | Done | 0 |
| Command resource type (CommandResource — executable + arguments separated) | Done | 0 |
| Resource enum (File, Directory, Command, NetworkEndpoint, Secret, ExternalTool, Unknown) | Done | 0 |
| Request metadata (RequestMetadata — bounded BTreeMap with invariant validation) | Done | 0 |
| Operation enum (12 variants: file_*, directory_*, command_execute, network_request, secret_access, tool_invoke) | Done | 0 |
| Request context (RequestContext — timestamp, working_directory, declared_intent, parent_request_id, metadata, dry_run) | Done | 0 |
| Tool request envelope (ToolRequest) with `deny_unknown_fields`, deep invariant validation, operation/resource compatibility matrix | Done | 31 |
| Authorization decision (DecisionEffect, ReasonCode, ApprovalRequirements, AuthorizationDecision) | Done | 0 |
| Defense-in-depth: constructor validation, serde `try_from` validation, explicit `validate_invariants()` | Done | — |
| `#![forbid(unsafe_code)]` | Done | — |

### kavach-policy (`crates/kavach-policy`)

| Component | Status | Tests |
|-----------|--------|-------|
| Policy data model (Policy, Rule, Effect, DefaultEffect, RuleConditions) | Done | 0 |
| Deterministic evaluation engine (PolicyEngine) with compile-once path-glob matching | Done | 60 |
| TOML policy parsing (load_policy_from_str, load_policy_from_file) with `deny_unknown_fields` | Done | 39 |
| File-size enforcement (MAX_POLICY_FILE_SIZE = 1 MiB) | Done | 1 |
| Schema version gate (only `schema_version = 1` accepted) | Done | 1 |
| 8-dimension AND-semantics matching: operation, resource_kind, agent_id, min_trust_level, required_capabilities, intent_prefix, path_globs, executables | Done | 60 |
| Path glob matching with explicit semantics (literal_separator, no filesystem access, no canonicalization) | Done | 9 |
| Deterministic command executable matching (exact string comparison against CommandResource.executable()) | Done | 13 |
| Cross-policy duplicate rule ID detection | Done | 1 |
| Comprehensive validation: empty conditions, empty paths/executables, length limits, duplicate detection, null-byte/control-char rejection, glob syntax validation | Done | 20 |
| Re-exported public API from lib.rs | Done | — |

### Repository infrastructure

| Component | Status |
|-----------|--------|
| Cargo workspace (4 crates) | Done |
| Rust edition 2024, MSRV 1.85 | Done |
| `#![forbid(unsafe_code)]` (workspace-wide) | Done |
| Clippy `-D warnings` with comprehensive deny list | Done |
| rustfmt configuration | Done |
| .editorconfig | Done |
| LICENSE (Apache-2.0) | Done |
| README.md | Done |

### Test summary

| Crate | Tests |
|-------|-------|
| kavach-core | 33 |
| kavach-policy | 99 |
| kavach-cli | 0 |
| kavach-config | 0 |
| **Total** | **132** |

---

## Missing Systems

These systems are referenced by the README or by the domain model but have
**zero implementation**:

| System | Current state |
|--------|--------------|
| **configuration layer** (`kavach-config`) | Empty placeholder. No config schema, no layered loading, no env-var overrides. `src/lib.rs` is one doc comment line. |
| **CLI** (`kavach-cli`) | Empty placeholder. `fn main() {}`. No clap subcommands. No config validation, no policy checking, no `--version`. All 9 runtime dependencies unused. |
| **docs/** directory | Does not exist. README references `docs/architecture.md`, `docs/security-model.md`, `docs/policy-format.md`. None exist. |
| **config/** directory | Does not exist. README references `config/kavach.example.toml`, `config/policy.example.toml`. Neither exists. |
| **tests/fixtures/** | Does not exist. README references `tests/fixtures/request_allow.json`. |
| **audit chain** | Zero code. `ApprovalRequirements` exists as a type but no event record, no tamper-evident storage, no hash chaining. |
| **secret detection / redaction** | Zero code. No scanning, no masking, no regex patterns. |
| **approval broker** | Zero code. `DecisionEffect::RequireApproval` is produced by the engine but no interactive flow, no TTL, no callback exists. |
| **HTTP gateway** | Zero code. No HTTP server, no request forwarding, no policy injection point. |
| **MCP adapter** | Zero code. No Model Context Protocol integration. |
| **local dashboard** | Zero code. |
| **enforcement adapters** | Zero code. The engine *evaluates* decisions and *reports* them; it does not block operations at the OS level. |
| **fuzzing / benchmarks** | Zero code. |
| **CI/CD** | Zero `.github/` config. |

---

## Phase 1: Remaining Policy Matchers

### Objective
Add the final policy-condition matchers so the policy engine covers every
dimension of the `ToolRequest`. The engine currently handles 8 dimensions;
this phase adds the remaining resource-specific matchers for network endpoints,
secrets, and external tools.

### Required Modules
- `crates/kavach-policy/src/model.rs`:
  - `network_hosts: Option<Vec<String>>` — host pattern matcher in `RuleConditions`
  - `network_schemes: Option<Vec<String>>` — scheme matcher in `RuleConditions`
  - `secret_identifiers: Option<Vec<String>>` — secret ID matcher in `RuleConditions`
  - `tool_identifiers: Option<Vec<String>>` — external-tool ID matcher in `RuleConditions`
  - Constants: `MAX_NETWORK_HOST_PATTERNS`, `MAX_SECRET_IDENTIFIER_PATTERNS`, `MAX_TOOL_IDENTIFIER_PATTERNS`
  - Validation error variants: `EmptyNetworkHosts(RuleId)`, `TooManyNetworkHosts(RuleId, usize)`, etc.
  - `validate_network_hosts()`, `validate_secret_identifiers()`, `validate_tool_identifiers()` methods
- `crates/kavach-policy/src/io.rs`:
  - `TomlRuleConditions`: add `network_hosts`, `network_schemes`, `secret_identifiers`, `tool_identifiers`
  - `convert()`: copy new fields
- `crates/kavach-policy/src/engine.rs`:
  - `rule_matches()`: add matching logic for each new field
  - Network: match `Resource::NetworkEndpoint(nr)` — check `nr.scheme().as_str()`, `nr.host().as_str()`
  - Secret: match `Resource::Secret { identifier }` — exact string membership
  - ExternalTool: match `Resource::ExternalTool { identifier }` — exact string membership
  - All use simple exact string comparison (similar to executables); no glob compilation needed

### Public APIs
- `RuleConditions.network_hosts: Option<Vec<String>>`
- `RuleConditions.network_schemes: Option<Vec<String>>`
- `RuleConditions.secret_identifiers: Option<Vec<String>>`
- `RuleConditions.tool_identifiers: Option<Vec<String>>`
- New `PolicyValidationError` variants re-exported from `lib.rs`

### Security Invariants
- Non-command, non-network, non-secret, non-tool resources return `false` when the respective matcher is configured (fail-closed)
- All size limits enforced at validation time
- Duplicate detection
- Null-byte and control-character rejection
- `deny_unknown_fields` on TOML input structs

### Tests Required
- Engine tests: match by network host/scheme, non-match by wrong host/scheme, non-network resource with network matcher → no match, secret ID match/no-match, external-tool ID match/no-match
- Validation tests: empty list, too many, empty string, too long, duplicate, null byte, control char — programmatic and TOML
- IO tests: parse network_hosts from TOML, parse secret_identifiers from TOML, parse tool_identifiers from TOML
- Precedence tests: deny-over-allow with network matchers
- AND semantics: network matcher combined with operation matcher

### Dependencies
- None beyond existing workspace dependencies

### Completion Criteria
- [ ] `network_hosts: Option<Vec<String>>` on `RuleConditions` with validation
- [ ] `network_schemes: Option<Vec<String>>` on `RuleConditions` with validation
- [ ] `secret_identifiers: Option<Vec<String>>` on `RuleConditions` with validation
- [ ] `tool_identifiers: Option<Vec<String>>` on `RuleConditions` with validation
- [ ] TOML parsing for all four new fields
- [ ] Engine matching logic for all four new fields
- [ ] 24+ new tests (6 per resource type: match, no-match, non-resource, validation × programmatic × TOML)
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --all-features` passes
- [ ] `cargo doc --workspace --no-deps` passes

### Explicit Non-Goals
- No network IP/port matching (host-only, scheme-only)
- No regex patterns (exact string match only, same as executables)
- No argument-risk analysis (executables are matched by name, arguments are not inspected)
- No shell parsing

### Implementation Order
1. Add model constants and error variants
2. Add fields to `RuleConditions` + `is_empty()` update + validation methods
3. Update `Policy::validate()` to call new validations
4. Add fields to `TomlRuleConditions` + `convert()` wiring
5. Add engine matching in `rule_matches()`
6. Add engine tests
7. Add TOML parsing tests
8. Add validation tests

---

## Phase 2: Enforcement Adapters

### Objective
Build OS-level enforcement adapters that actually block operations, not just
evaluate policy decisions. Current engine evaluates but does not enforce.
This phase creates filesystem, command, network, secret, and tool enforcement
layers that consume `AuthorizationDecision` and gate real operations.

### Required Modules (New Crate: `kavach-enforcer`)
- `crates/kavach-enforcer/` — new library crate
- `src/fseal.rs` — filesystem enforcement: intercepts file/directory operations,
  resolves symlinks at enforcement time, checks workspace containment
- `src/cmdseal.rs` — command enforcement: gates `CommandExecute` using the
  engine's decision, blocks disallowed executables, no argument injection
- `src/netseal.rs` — network enforcement: gates `NetworkRequest`, validates
  scheme/host/port against policy
- `src/sealseal.rs` — secret enforcement: gates `SecretAccess`, validates
  identifier, masks secret values before they leave the process
- `src/toolseal.rs` — external-tool enforcement: gates `ToolInvoke`, validates
  tool identifier against policy
- `src/seal.rs` — unified `Seal` trait: `fn enforce(&self, request: &ToolRequest, decision: &AuthorizationDecision) -> Result<(), EnforcementError>`
- `src/lib.rs` — re-exports, `EnforcementError` type

### Public APIs
- `Seal` trait
- `FileSeal`, `CmdSeal`, `NetworkSeal`, `SecretSeal`, `ToolSeal` structs
- `Enforcer::new(config) -> Self`
- `Enforcer::enforce(request, decision) -> Result<(), EnforcementError>`
- `EnforcementError` enum (AccessDenied, PathEscapesWorkspace, SymlinkDetected, etc.)

### Security Invariants
- **Default deny with no decision**: If no decision is available, all operations are blocked
- **Symlink resolution at enforcement time**: The core normalizes lexically (no filesystem access); enforcement resolves real paths and symlinks
- **Workspace containment**: File/directory operations must stay within configured workspace roots
- **No argument injection**: Command enforcement never modifies or inspects arguments; it only gates the executable
- **Secret masking**: Secret values are never logged, never serialized, never leaked to error messages
- **Fail-closed**: Any I/O error during enforcement results in deny
- Dual-use: library for embedding + CLI integration

### Tests Required
- Filesystem: read allowed file, deny read of disallowed file, symlink traversal detected, path escape detected, workspace containment, filesystem errors → deny
- Command: execute allowed executable, deny disallowed executable, non-command resource with command enforcer → error
- Network: allowed scheme+host, denied scheme, denied host, port matching, non-network resource
- Secret: read allowed secret identifier, deny disallowed identifier, value never appears in errors
- Tool: invoke allowed tool, deny disallowed tool
- Unified: multiple seals composed, enforcement error propagation

### Dependencies
- New workspace dependencies: `canonical_path` or `dunce` for symlink-aware canonicalization
- Consider `fs2` or equivalent for advisory file locking (optional, future)

### Completion Criteria
- [ ] `kavach-enforcer` crate scaffolded with Cargo.toml
- [ ] `Seal` trait defined
- [ ] `FileSeal` with workspace containment and symlink detection
- [ ] `CmdSeal` with executable-only gating
- [ ] `NetworkSeal` with scheme/host/port gating
- [ ] `SecretSeal` with value masking
- [ ] `ToolSeal` with identifier gating
- [ ] `Enforcer` compose-all struct
- [ ] `EnforcementError` comprehensive enum
- [ ] 30+ tests across all seals
- [ ] All standard checks pass

### Explicit Non-Goals
- No sandboxing / containerization / seccomp (orthogonal concern)
- No process-level isolation (ptrace, cgroups)
- No filesystem overlay or copy-on-write
- No command argument sanitization or shell parsing
- No kill-switch or emergency revoke (future phase)

### Implementation Order
1. Scaffold `kavach-enforcer` crate
2. Implement `Seal` trait and `EnforcementError`
3. Implement `FileSeal` (highest priority — most agent operations are file-based)
4. Implement `CmdSeal`
5. Implement `NetworkSeal`
6. Implement `SecretSeal`
7. Implement `ToolSeal`
8. Implement `Enforcer` compose-all
9. Write all tests
10. Wire into CLI (Phase 8)

---

## Phase 3: Tamper-Evident Audit Chain and Secure Event Storage

### Objective
Record every policy decision, enforcement action, and approval event in a
tamper-evident append-only log with cryptographic integrity guarantees.

### Required Modules (New Crate: `kavach-audit`)
- `crates/kavach-audit/` — new library crate
- `src/event.rs` — `AuditEvent` enum (Decision, Enforcement, Approval, Error, ConfigChange)
- `src/chain.rs` — `AuditChain`: append-only log with SHA-256 tree or linear hash chain
- `src/storage.rs` — `AuditStore` trait + `FileAuditStore` implementation (append-only file storage)
- `src/verify.rs` — chain verification and integrity check
- `src/lib.rs` — re-exports, `AuditError` type

### Public APIs
- `AuditEvent` type: timestamp, event_kind, decision_effect, rule_ids, request_id_short, hash_of_previous
- `AuditChain::append(event) -> Result<(), AuditError>`
- `AuditChain::verify() -> Result<(), AuditError>` — traverse chain, recompute hashes
- `AuditStore` trait: `append(bytes)`, `read_all()`, `truncate(pos)`
- `FileAuditStore: AuditStore` — append-only file, fsync after each write
- `AuditError` enum: IoError, ChainIntegrityViolation, StorageFull, SerializationFailed

### Security Invariants
- **Hash chaining**: Each event includes SHA-256 of the previous event in its own hash; any single-byte modification invalidates the chain
- **Append-only**: Storage layer refuses to overwrite or truncate except via explicit `truncate()` for rotation
- **Fsync guarantee**: Every write is fsync'd before returning success
- **Immediate event recording**: Events are written synchronously, not batched, before the caller proceeds
- **No log of secrets**: `AuditEvent` never includes raw secrets, command arguments, file contents, or request bodies — only identifiers and outcomes
- **Rotation support**: Configurable max file size; when exceeded, close current file, open new file, write chain-continuation marker with previous-file hash

### Tests Required
- Append + verify single event
- Append + verify multi-event chain
- Tampered middle event → verification fails
- Tampered final event → verification fails
- Reordered events → verification fails
- Missing event → verification fails
- Empty chain → verify succeeds (trivially)
- Rotation: chain verification across files
- Concurrent writes → consistency
- Storage full → error returned
- Fsync failure → error returned

### Dependencies
- `ring` or `sha2` for SHA-256
- `hex` for hash formatting (optional, display only)
- `serde` for event serialization
- No async runtime required (synchronous, local-only)

### Completion Criteria
- [ ] `kavach-audit` crate scaffolded
- [ ] `AuditEvent` type with serialization
- [ ] `AuditChain` with `append`, `verify`
- [ ] `AuditStore` trait + `FileAuditStore` with fsync
- [ ] Rotation support (configurable max size)
- [ ] 12+ tests covering chain integrity, rotation, tampering
- [ ] All standard checks pass

### Explicit Non-Goals
- No streaming/cloud export (disk-only)
- No encryption-at-rest (full-disk encryption is the OS's job)
- No Merkle tree (linear chain only — sufficient for agent audit)
- No real-time alerting or SIEM integration
- No retention policy engine (user rotates files manually)

### Implementation Order
1. Scaffold crate + Cargo.toml
2. `AuditEvent` type with serde
3. `AuditStore` trait + `FileAuditStore`
4. `AuditChain` with SHA-256 append + verify
5. Rotation logic
6. Tests (integrity, tampering, rotation)
7. Wire into CLI and future gateway (log every decision)

---

## Phase 4: Secret Detection and Redaction

### Objective
Detect potential secrets (API keys, tokens, passwords) in agent I/O and request
payloads, and redact them before they are logged, serialized, or transmitted.

### Required Modules (New Crate: `kavach-secrets`)
- `crates/kavach-secrets/` — new library crate
- `src/detect.rs` — `SecretDetector`: scans strings/bytes for secrets using configurable patterns and entropy heuristics
- `src/redact.rs` — `SecretRedactor`: replaces detected secrets with `[REDACTED]`
- `src/patterns.rs` — built-in regex patterns (AWS keys, GitHub tokens, JWT, private keys, generic high-entropy strings)
- `src/lib.rs` — re-exports, `SecretDetector`, `SecretRedactor`

### Public APIs
- `SecretDetector::new(config) -> Self`
- `SecretDetector::detect(&self, input: &str) -> Vec<SecretMatch>` — find all matches
- `SecretRedactor::redact(&self, input: &str) -> String` — replace secrets with `[REDACTED]`
- `SecretRedactor::redact_json(&self, input: &str) -> String` — redact values in JSON
- `SecretMatch`: offset, length, pattern_name, confidence (high/medium/low)
- `SecretDetectorBuilder`: configure built-in patterns, custom regex patterns, entropy threshold

### Security Invariants
- **No false-negative by design**: Default configuration includes comprehensive built-in patterns
- **No secret logging**: Detector output never includes the matched secret value (only offset, length, pattern_name)
- **Deterministic**: Same input always produces same matches (no non-deterministic entropy sampling)
- **Streaming-friendly**: `detect()` works on chunks; no unbounded buffering
- **Configurable**: Users can add custom regex patterns and adjust entropy thresholds
- **JSON-aware**: `redact_json()` operates on parsed JSON values, not string-matching the JSON serialization

### Tests Required
- AWS access key detection
- AWS secret key detection
- GitHub personal access token detection (classic + fine-grained)
- JWT detection (3-part base64 with signature)
- Private key PEM detection (RSA, EC, Ed25519)
- Generic high-entropy base64 string detection
- Redaction replaces matched text
- Redaction of JSON preserves structure
- No match on normal text
- Configurable patterns addition
- Entropy threshold tuning

### Dependencies
- `regex` for pattern matching
- No `secrecy` or cryptographic libraries (detection only, not key management)

### Completion Criteria
- [ ] `kavach-secrets` crate scaffolded
- [ ] `SecretDetector` with 8+ built-in patterns
- [ ] `SecretRedactor` with plain-text and JSON modes
- [ ] Configurable pattern set
- [ ] Entropy heuristic for unknown formats
- [ ] 15+ tests covering all built-in patterns, redaction, JSON mode
- [ ] All standard checks pass

### Explicit Non-Goals
- No secret storage or vault
- No key rotation management
- No secret generation
- No network-transmitted secret scanning (local only)
- No ML-based secret detection

### Implementation Order
1. Scaffold crate
2. Implement built-in regex patterns
3. Implement `SecretDetector::detect()`
4. Implement entropy heuristic
5. Implement `SecretRedactor::redact()` + `redact_json()`
6. Configurability (builder pattern)
7. Tests

---

## Phase 5: Human Approval Broker

### Objective
Implement an interactive human approval flow that pauses agent execution when
a `RequireApproval` decision is returned, presents the request to a human,
and records the outcome.

### Required Modules (New Crate: `kavach-approval`)
- `crates/kavach-approval/` — new library crate
- `src/broker.rs` — `ApprovalBroker`: manages pending approvals, timeouts, callbacks
- `src/pending.rs` — `PendingApproval`: approval ID, request summary, timeout, callback channel
- `src/decision.rs` — `ApprovalDecision`: Approve, Deny, Timeout (auto-deny)
- `src/lib.rs` — re-exports, `ApprovalError` type

### Public APIs
- `ApprovalBroker::new(config) -> Self`
- `ApprovalBroker::submit(request_summary) -> ApprovalReceiver`
- `ApprovalReceiver`: `fn wait(self) -> Result<ApprovalDecision, ApprovalError>` — blocks until approved, denied, or timed out
- `ApprovalBroker::approve(id)`, `ApprovalBroker::deny(id)` — human-facing methods
- `PendingApproval`: id, agent_id, operation, resource, declared_intent, created_at, expires_at
- `ApprovalDecision` enum: Approved { by, at }, Denied { by, at }, TimedOut
- `ApprovalError` enum: Timeout, BrokerShutdown, AlreadyDecided

### Security Invariants
- **Auto-deny on timeout**: All pending approvals have a TTL; expiration = deny
- **No re-approval**: Once decided, an approval cannot be changed
- **Audit integration**: Every approval decision is logged to the audit chain
- **No credential exposure**: Approval request summaries must not contain paths, arguments, or identifiers from disallowed operations
- **Single use**: Each approval ID is consumed once and cannot be reused

### Tests Required
- Submit approval → approve → returns Approved
- Submit approval → deny → returns Denied
- Submit approval → timeout → returns TimedOut
- Double-decide → AlreadyDecided error
- Broker shutdown with pending → error
- Approval ID uniqueness
- TTL enforcement

### Dependencies
- `std::sync::mpsc` or `crossbeam-channel` for in-process communication
- `kavach-audit` for event recording
- No external IPC/RPC protocol (local, in-process only)

### Completion Criteria
- [ ] `kavach-approval` crate scaffolded
- [ ] `ApprovalBroker` with submit/approve/deny
- [ ] TTL-based auto-deny
- [ ] Audit event emission on every decision
- [ ] 8+ tests
- [ ] All standard checks pass

### Explicit Non-Goals
- No UI implementation (text UI in CLI phase, graphical in dashboard phase)
- No network approval (local only)
- No multi-approver quorum
- No approval policies (who-can-approve-what)
- No delegation

### Implementation Order
1. Scaffold crate
2. `PendingApproval` + `ApprovalDecision` types
3. `ApprovalBroker` with submit/approve/deny
4. Timeout handling
5. Audit integration
6. Tests

---

## Phase 6: Local HTTP Gateway

### Objective
Build a local HTTP server that exposes KAVACH as a standalone security runtime.
Agents send JSON `ToolRequest` payloads over HTTP and receive `AuthorizationDecision`
responses. Enforcement adapters (Phase 2) are invoked inline.

### Required Modules (New Crate: `kavach-gateway`)
- `crates/kavach-gateway/` — new library or binary crate
- `src/server.rs` — HTTP server (axum or tiny_http), routes, middleware
- `src/routes.rs` — endpoint handlers: POST /evaluate, GET /health, GET /metrics
- `src/middleware.rs` — request validation, audit logging, tracing
- `src/lib.rs` or `src/main.rs` — entry point

### Public APIs (HTTP)
- `POST /v1/evaluate` — body: `ToolRequest` JSON, response: `AuthorizationDecision` JSON
- `GET /v1/health` — `{"status": "ok"}`
- `GET /v1/metrics` — Prometheus-format metrics (request count, latency, decisions by effect)

### Security Invariants
- **Bind to localhost only** (127.0.0.1) — never expose on network interfaces
- **No authentication** (localhost-only is the security boundary)
- **Request size limit**: Enforce maximum request body size (64 KiB default)
- **Timeout**: All requests time out after configurable duration (30s default)
- **Fail-closed**: Any server error returns HTTP 500 with `Deny` decision
- **Audit integration**: Every evaluation is logged
- **Secret redaction**: Gateway invokes Phase 4 redaction before logging request bodies
- **No caching**: Every request is evaluated fresh

### Tests Required
- Valid request → 200 OK with Allow decision
- Denied request → 200 OK with Deny decision
- Oversized request → 413 or 400
- Malformed JSON → 400
- Invalid ToolRequest (validation fails) → 422 with Deny decision
- Health check → 200 OK
- Metrics endpoint → 200 OK
- Concurrent requests → correct decisions
- Server startup/shutdown

### Dependencies
- `axum` or `tiny_http` for HTTP server
- `tokio` for async runtime
- `tower` or manual middleware for request limits

### Completion Criteria
- [ ] `kavach-gateway` crate scaffolded
- [ ] HTTP server on localhost
- [ ] POST /v1/evaluate endpoint with policy evaluation
- [ ] GET /v1/health endpoint
- [ ] GET /v1/metrics endpoint
- [ ] Request size limit enforcement
- [ ] Audit logging of every request
- [ ] 10+ integration tests
- [ ] All standard checks pass

### Explicit Non-Goals
- No HTTPS/TLS (localhost only)
- No authentication (no API keys, no OAuth)
- No multi-tenancy
- No request queuing or rate limiting (future)
- No WebSocket support

### Implementation Order
1. Scaffold crate + Cargo.toml
2. HTTP server setup with axum
3. POST /v1/evaluate route
4. Health + metrics routes
5. Request validation, size limits, timeouts
6. Audit integration
7. Tests
8. Docker image (future)

---

## Phase 7: MCP Adapter

### Objective
Build a Model Context Protocol (MCP) security gateway that intercepts MCP
tool-call requests from AI models, evaluates them against KAVACH policies,
and forwards only approved requests to the tool server.

### Required Modules (New Crate: `kavach-mcp`)
- `crates/kavach-mcp/` — new library/binary crate
- `src/gateway.rs` — MCP proxy: receives MCP requests, evaluates, forwards or denies
- `src/adapt.rs` — MCP ↔ KAVACH type conversion (MCP tool_call → ToolRequest)
- `src/lib.rs` — re-exports

### Public APIs
- `McpGateway::new(config, policy_engine) -> Self`
- `McpGateway::evaluate(mcp_request) -> McpResponse` — evaluates and either forwards or returns deny
- MCP protocol types (tool_call, tool_result, error)

### Security Invariants
- **Default deny**: Unknown MCP tools are denied
- **Policy per tool**: Each MCP tool maps to a `ToolInvoke { tool_id }` operation; policies can gate individually
- **No tool output inspection** (phase 1): The gateway evaluates requests only, not responses
- **Audit integration**: All MCP evaluations logged
- **Tool ID validation**: MCP tool names are validated as `ToolId` before policy lookup

### Tests Required
- Known tool → evaluated against policy → allowed/denied
- Unknown tool → denied
- MCP request ↔ ToolRequest conversion
- Audit logging of MCP decisions

### Dependencies
- MCP protocol types (potentially a dependency on an MCP Rust SDK, or manual JSON-RPC handling)
- `kavach-gateway` for HTTP serving (shared infrastructure)

### Completion Criteria
- [ ] `kavach-mcp` crate scaffolded
- [ ] MCP ↔ ToolRequest conversion
- [ ] Policy evaluation integrated
- [ ] 6+ tests
- [ ] All standard checks pass

### Explicit Non-Goals
- No full MCP server implementation (only proxy/gateway)
- No tool response filtering or transformation
- No MCP session management
- No streaming MCP support (initial version)

### Implementation Order
1. Scaffold crate
2. Define MCP protocol types
3. MCP ↔ KAVACH type conversion
4. Gateway proxy logic
5. Tests

---

## Phase 8: CLI and Configuration Completion

### Objective
Finish the `kavach` CLI and `kavach-config` crate so that the binary can load
configuration, validate policies, and evaluate requests from the command line.

### Required Modules
- `crates/kavach-config/src/` — complete the config crate
  - `config.rs`: `KavachConfig` struct, TOML deserialization, env-var overrides
  - `lib.rs`: public API
- `crates/kavach-cli/src/` — complete the CLI
  - `main.rs`: clap CLI with subcommands
  - `commands/config.rs`: `config validate`
  - `commands/policy.rs`: `policy validate`, `policy check`
  - `commands/serve.rs`: `serve` (starts HTTP gateway from Phase 6)
  - `commands/audit.rs`: `audit verify` (verifies chain from Phase 3)
  - `tracing.rs`: tracing-subscriber setup

### Public APIs (CLI)
```
kavach --version
kavach config validate --file <path>
kavach policy validate --file <path>
kavach policy check --policy <path> --request <path>
kavach serve --config <path>
kavach audit verify --file <path>
```

### Config Schema (kavach-config)
- `KavachConfig`:
  - `gateway.port: u16` (default 9090)
  - `gateway.max_request_size: u64` (default 65536)
  - `policy_dir: PathBuf` — directory of .toml policy files
  - `workspace_roots: Vec<PathBuf>` — allowed filesystem roots
  - `audit.path: PathBuf` — audit log file or directory
  - `audit.max_file_size: u64` — rotation threshold
  - `secrets.enable_redaction: bool`
  - `secrets.custom_patterns: Vec<String>`
  - Environment overrides: `KAVACH_GATEWAY_PORT`, `KAVACH_POLICY_DIR`, etc.

### Exit Codes
| Code | Meaning |
|------|---------|
| 0 | Success / request allowed |
| 10 | Request denied |
| 11 | Request requires approval |
| 20 | Invalid input or configuration |
| 30 | Internal error |

### Tests Required
- CLI: `--version` prints version, `config validate` on valid file passes, on invalid file fails, `policy validate` on valid file passes, on invalid file fails, `policy check` with allow/deny/approval fixtures returns correct exit codes
- Config: parse from TOML, env var override, missing file → error, invalid TOML → error

### Dependencies
- `clap` (already declared)
- `tracing-subscriber` (already declared)
- Already-declared workspace crates
- Test deps: `assert_cmd`, `predicates` (already declared)

### Completion Criteria
- [ ] `kavach-config` with `KavachConfig` struct, TOML parsing, env-var overrides
- [ ] `kavach` binary with all subcommands
- [ ] `--version` subcommand
- [ ] `config validate` subcommand
- [ ] `policy validate` subcommand
- [ ] `policy check` subcommand with stable exit codes
- [ ] `serve` subcommand (wired to Phase 6 gateway)
- [ ] `audit verify` subcommand (wired to Phase 3 audit)
- [ ] Tracing/logging setup
- [ ] Example config files in `config/`
- [ ] Test fixtures in `tests/fixtures/`
- [ ] 15+ CLI integration tests
- [ ] 10+ config unit tests
- [ ] All standard checks pass

### Explicit Non-Goals
- No daemonization / service management (systemd unit provided separately)
- No config hot-reload (restart to reload)
- No config migration between versions
- No interactive CLI (pure command-line)

### Implementation Order
1. Complete `kavach-config` (config struct, TOML parsing, env overrides)
2. Implement `config validate` subcommand
3. Implement `policy validate` subcommand
4. Implement `policy check` subcommand
5. Implement `--version`
6. Implement `serve`
7. Implement `audit verify`
8. Create example config files and test fixtures
9. CLI integration tests

---

## Phase 9: Local Dashboard

### Objective
Build a local web-based dashboard for observing KAVACH state: recent decisions,
audit log, pending approvals, policy status, and metrics.

### Required Modules (New Crate: `kavach-dashboard`)
- `crates/kavach-dashboard/` — new binary or library crate
- Static web assets (HTML, CSS, JS) — simple SPA or server-rendered
- API routes serving dashboard data from gateway/audit/approval subsystems

### Public APIs
- Web UI at `http://localhost:9091` (or configurable port)
- API endpoints: GET /api/decisions, GET /api/approvals, GET /api/policies, GET /api/audit
- Real-time updates via polling or SSE (no WebSocket requirement)

### Security Invariants
- **Localhost only** — same as gateway
- **Read-only**: Dashboard never modifies policy, decisions, or audit log
- **No credential exposure**: Dashboard never shows paths, arguments, or secret identifiers from denied operations
- **No third-party CDN**: All frontend assets bundled locally

### Tests Required
- Dashboard serves on configured port
- API returns decision history
- API returns pending approvals
- API returns policy list
- Audit log browsing
- Responsive layout

### Dependencies
- `axum` (shared with gateway) for serving
- `maud` or `askama` for server-side HTML rendering (or static files)
- `htmx` or vanilla JS for interactivity (no React/Angular/Vue)
- No database — reads from gateway's in-memory state and audit files

### Completion Criteria
- [ ] Web UI renders on browser
- [ ] Decision timeline view
- [ ] Pending approvals view with approve/deny buttons
- [ ] Policy list view
- [ ] Audit log viewer with chain verification status
- [ ] Metrics summary (total decisions, deny ratio, etc.)
- [ ] 6+ integration tests
- [ ] All standard checks pass

### Explicit Non-Goals
- No authentication (localhost-only)
- No persistent dashboard state (reads from live gateway)
- No alerting or notification
- No multi-user support
- No dark mode (nice-to-have, not required)

### Implementation Order
1. Scaffold crate
2. Static assets build pipeline
3. API routes serving dashboard data
4. Decision timeline UI
5. Approval management UI
6. Policy list UI
7. Audit log viewer UI
8. Integration tests

---

## Phase 10: Testing, Fuzzing, Benchmarks, Threat-Model Review, and Releases

### Objective
Harden the entire codebase with fuzzing, benchmarks, a formal threat-model
document, CI/CD pipeline, and prepare for first release.

### Sub-Phase 10a: Unit and Integration Test Expansion
- Ensure every public function has at least one test
- Add edge-case tests: empty policy files, 1000-policy engine, 10,000-rule engine
- Test concurrent `PolicyEngine::evaluate()` (it's `&self` so should be safe)
- Test `NormalizedPath` with Unicode, very long paths, edge cases

### Sub-Phase 10b: Property-Based Testing
- Use `proptest` or `bolero` for:
  - `NormalizedPath` normalization idempotency: `normalize(normalize(p)) == normalize(p)`
  - `PolicyEngine` determinism: same (policy, request) always produces same decision
  - `RuleConditions::is_empty()` ↔ `Policy::validate()` consistency
  - Glob matcher: no false-positives on paths that don't match patterns
  - Executable matcher: exact string match is symmetric

### Sub-Phase 10c: Fuzzing
- Use `cargo-fuzz` (libfuzzer) for:
  - TOML policy parsing (`load_policy_from_str`) — must never panic, must return error or Ok
  - `NormalizedPath::new()` — must never panic on arbitrary bytes
  - `ToolRequest` JSON deserialization — must never panic
  - `PolicyEngine::evaluate()` — must never panic on valid request
  - `AuthorizationDecision` serialization round-trip

### Sub-Phase 10d: Benchmarks
- Use `criterion` for:
  - `PolicyEngine::new()` with N policies and M rules
  - `PolicyEngine::evaluate()` with various rule counts
  - `NormalizedPath::new()` throughput
  - TOML parsing throughput
  - GlobSet matching throughput
  - Audit chain append throughput (writes per second)

### Sub-Phase 10e: Threat-Model Documentation
- Write `docs/security-model.md`:
  - Assets: agent data, source code, credentials, audit log
  - Threat actors: compromised agent, malicious tool, network adversary, insider
  - Attack surfaces: TOML parsing, JSON deserialization, path normalization, glob matching, HTTP endpoints
  - Mitigations: type-safety, fail-closed, deny-by-default, input validation, no-unsafe, lexical-only paths
  - Residual risks: symlink TOCTOU (until enforcement layer), side-channel timing, DoS via oversized inputs

### Sub-Phase 10f: Architecture Documentation
- Write `docs/architecture.md`:
  - Crate dependency graph
  - Data flow: agent → CLI/gateway → policy engine → enforcement → audit
  - Module responsibilities
  - Design decisions and trade-offs

### Sub-Phase 10g: Policy Format Documentation
- Write `docs/policy-format.md`:
  - Complete TOML schema reference
  - All condition fields with examples
  - Effect precedence explanation
  - Schema version compatibility policy

### Sub-Phase 10h: CI/CD Pipeline
- Create `.github/workflows/ci.yml`:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --all-features`
  - `cargo doc --workspace --no-deps`
  - `cargo audit` (dependency vulnerability scan)
  - `cargo deny check` (license compliance)
- Create `.github/workflows/fuzz.yml` (periodic fuzz runs)
- Create `.github/workflows/bench.yml` (benchmark regression tracking)

### Sub-Phase 10i: Release Preparation
- Changelog generation
- Version tagging scheme (semver)
- `cargo release` configuration
- Docker image build (`kavach-gateway` + `kavach` binary)
- Release checklist: all phases complete, all tests pass, docs generated, audit passes

### Dependencies
- `proptest` (dev-dependency)
- `criterion` (dev-dependency)
- `cargo-fuzz` (CI tool, not library)
- `cargo-audit` (CI tool)
- `cargo-deny` (CI tool)

### Completion Criteria
- [ ] 20+ additional edge-case and concurrency tests
- [ ] 5+ property-based test suites
- [ ] 5+ fuzz targets
- [ ] 5+ benchmark suites with baseline results
- [ ] `docs/security-model.md` written and reviewed
- [ ] `docs/architecture.md` written and reviewed
- [ ] `docs/policy-format.md` written and reviewed
- [ ] CI/CD pipeline passing on every push
- [ ] Fuzz corpus seeded and running
- [ ] Benchmark baseline recorded
- [ ] Docker image published
- [ ] First release tagged

### Explicit Non-Goals
- No formal verification
- No penetration testing (future)
- No compliance certification (SOC2, FedRAMP)
- No performance SLAs
- No distributed deployment

---

## Summary of Phase Dependencies

```
Phase 1 (Policy Matchers)
 └─ No dependencies — extends existing crate

Phase 2 (Enforcement Adapters)
 └─ Depends on Phase 1 (uses all matchers)

Phase 3 (Audit Chain)
 └─ No hard dependencies — independent crate

Phase 4 (Secret Detection)
 └─ No hard dependencies — independent crate

Phase 5 (Approval Broker)
 └─ Depends on Phase 3 (audit integration)

Phase 6 (HTTP Gateway)
 └─ Depends on Phases 2, 3, 4 (enforcement, audit, redaction)

Phase 7 (MCP Adapter)
 └─ Depends on Phase 6 (shared HTTP infrastructure)

Phase 8 (CLI + Config)
 └─ Depends on Phases 2, 3, 5, 6 (wires everything together)

Phase 9 (Dashboard)
 └─ Depends on Phases 6, 8 (reads from gateway, uses config)

Phase 10 (Testing + Release)
 └─ Depends on all prior phases
```

## Test Count Targets

| Phase | New Tests (minimum) |
|-------|---------------------|
| Phase 1 | 24 |
| Phase 2 | 30 |
| Phase 3 | 12 |
| Phase 4 | 15 |
| Phase 5 | 8 |
| Phase 6 | 10 |
| Phase 7 | 6 |
| Phase 8 | 25 |
| Phase 9 | 6 |
| Phase 10 | 50+ |
| **Total at completion** | **318+** (from 132 current) |

## Recommended Next Implementation Phase

**Phase 1: Remaining Policy Matchers.** It extends the existing `kavach-policy`
crate with no new dependencies, completes the policy matching surface, and
unblocks enforcement adapters (Phase 2) which depend on the full matcher set.
Estimated effort: 2-3 focused sessions.
