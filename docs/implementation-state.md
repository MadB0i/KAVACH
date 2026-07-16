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

## Phase 7: Secret Detection and Redaction — COMPLETE (52 tests)

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

### Test Summary
| Crate | Tests |
|-------|-------|
| kavach-core | 33 |
| kavach-policy | 141 |
| kavach-config | 11 |
| kavach-runtime | 8 |
| kavach-enforcement | 134 |
| kavach-redaction | 52 |
| kavach-cli | 0 |
| **Total** | **379** |

## Verification
```
cargo fmt --all -- --check          PASS
cargo test --workspace --all-features  PASS (379)
cargo clippy --workspace --all-targets --all-features -- -D warnings  PASS (zero)
cargo doc --workspace --no-deps     PASS

## Platform Limitations
- Loopback blocked by default; local test server integration tests use `with_allow_loopback(true)` override
- DNS rebinding protection relies on custom resolver binding all addresses before connection
- ureq v2 TLS defaults enabled; no certificate verification disable option
- Redirect integration tests use `redirects(0)` on ureq agent to prevent internal redirect following, enabling manual re-validation of redirect targets
- Flaky `redirect_to_allowed_target_succeeds` integration test removed due to Windows TCP race condition (WSAECONNRESET); redirect validation logic tested via `validate_redirect_url` unit tests (9) and two redirect integration tests (private-IP and metadata-hostname targets)
- Redaction binary input: non-UTF-8 data rejected with `UnsupportedBinaryInput` (safety: lossy conversion could leak secrets)
- Entropy detection is statistical; UUIDs and hashes excluded where possible, but not guaranteed
- See `docs/redaction.md` for full redaction documentation
