# KAVACH Redaction Module

Last updated: 2026-07-16

## Overview

`kavach-redaction` is a deterministic, local-only secret detection and redaction
subsystem. It prevents secrets from leaking into logs, tracing fields, errors,
audit metadata, approval summaries, and outbound network text.

**No cloud services or external AI models are used.**

## Architecture

```
kavach-redaction/
├── Cargo.toml
└── src/
    ├── lib.rs          — crate root, re-exports
    ├── types.rs        — RedactionResult, SecretMatch, DetectorCategory, SecretContainer, constants
    ├── error.rs        — RedactionError, RedactionErrorKind
    ├── redactor.rs     — Redactor trait, CompositeRedactor, CompositeRedactorBuilder
    ├── helpers.rs      — redact_error_message, redact_tracing_field, redact_command_output, etc.
    └── detectors/
        ├── mod.rs      — Detector trait
        ├── bearer.rs   — Bearer token detection
        ├── jwt.rs      — JWT-like token detection
        ├── pem.rs      — PEM private key detection
        ├── assignments.rs — Sensitive key=value assignment detection
        ├── github.rs   — GitHub token detection
        ├── aws.rs      — AWS key ID detection
        ├── exact.rs    — Configured exact secret matching
        └── entropy.rs  — High-entropy candidate detection (optional, disabled by default)
```

## Detector Categories

| Category | Detects | Example |
|----------|---------|---------|
| `BearerToken` | `Authorization: Bearer <token>` | Bearer tokens ≥8 chars |
| `Jwt` | 3-dot-segmented base64url tokens | JWT, OAuth access tokens |
| `PrivateKey` | PEM-encoded private keys | RSA, EC, OpenSSH, DSA |
| `SensitiveKeyAssignment` | `key=value` pairs with sensitive keys | `password=...`, `token=...` |
| `GitHubToken` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefixed tokens | GitHub PATs |
| `AwsKeyId` | `AKIA`..., `A3T`..., etc. | AWS access key IDs |
| `ConfiguredSecret` | Exact-match configured strings | User-supplied secrets |
| `EntropyCandidate` | High-entropy strings (optional) | Random-looking tokens |

## Supported Detectors

- **Bearer tokens**: Matches `Bearer <token>` with token length ≥8 characters
- **JWT-like tokens**: Three dot-separated base64url segments with bounded lengths; avoids version strings and short filenames
- **PEM private keys**: Complete `-----BEGIN ... PRIVATE KEY-----` blocks (RSA, EC, OpenSSH, DSA, generic)
- **Password/API-key assignments**: Case-insensitive detection of 30+ sensitive key names with `=` or `:` separated values
- **GitHub tokens**: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefixed tokens
- **AWS key IDs**: Standard AWS access key ID formats (AKIA, A3T, etc.)
- **Configured exact secrets**: User-provided secret strings with longest-match-first overlapping resolution
- **Entropy detection**: Optional Shannon-entropy-based detection for high-entropy candidates; disabled by default

## False Positive and False Negative Limitations

### False Negatives
- Obfuscated secrets (Base64-encoded, ROT13'd, reversed) are not detected
- Encrypted secrets are not detected
- Secrets split across multiple fields/lines are not detected
- Truncated or partial secrets may not match
- Environment variable names containing secrets (e.g., `export SECRET=x`) are detected via assignment detector; standalone variable names are not
- Binary data is rejected with `UnsupportedBinaryInput` error instead of being redacted

### False Positives
- Assignment detector may match values that contain sensitive keywords (e.g., `name=token-123` matches if `token` is a word boundary)
- JWT detector may match some URL-safe base64 triplets that are not JWTs
- Entropy detector (when enabled) may flag naturally high-entropy strings (hashes, UUIDs - though these are excluded where possible)
- Bearer token detector requires ≥8 character tokens; shorter tokens are not detected

## Entropy Detection Limitations

- Entropy detection is **disabled by default** and must be explicitly enabled
- Shannon entropy is a statistical measure; it cannot distinguish between a random password and a random hash
- UUIDs and SHA hashes are excluded where possible, but not all formats are filtered
- Entropy threshold, min/max length are configurable
- Does not prove a string is a secret; only that it is high-entropy
- False positives increase as threshold is lowered

## Binary Input Behavior

- `redact_bytes` first attempts UTF-8 conversion
- Non-UTF-8 binary input returns `RedactionError::UnsupportedBinaryInput`
- This is a safety measure: blindly converting binary data with lossy UTF-8 could leak secrets via replacement characters
- All detectors operate on `&str` text; binary data without valid UTF-8 cannot be processed

## Configured Secret Storage Behavior

- Configured secrets are stored as plain `String` values internally for deterministic matching
- `Debug` implementation on `SecretContainer` reveals only the count, not the values
- `SecretContainer` never implements `Display` or `Serialize`
- Secrets are protected from accidental logging via custom `Debug` impl
- Overlapping secrets are resolved by longest match first
- Empty secrets are rejected; max 1000 secrets; max 1024 bytes per secret

## Integration Helpers

| Function | Purpose |
|----------|---------|
| `redact_error_message` | Redact error message strings before logging |
| `redact_tracing_field` | Redact tracing span fields |
| `redact_command_output` | Redact command stdout/stderr |
| `redact_network_body` | Redact network request/response bodies |
| `redact_header_value` | Redact individual header values |
| `redact_filesystem_preview` | Redact file read previews |
| `redact_approval_summary` | Redact approval summary text |
| `redact_audit_metadata` | Redact audit metadata |

## Security Notes

- **Redaction is not encryption**: Redacted values are replaced with static markers like `[REDACTED:password]`; the original source is not modified
- **Redaction does not erase secrets**: The original input remains intact; only copies passed through the redactor are safe
- **Redaction is deterministic**: Same input + same configuration = same output
- **Redaction is idempotent**: Running redaction on already-redacted text produces no additional changes
- **Already-redacted markers are stable**: Markers like `[REDACTED:bearer_token]` are not re-processed by detectors
