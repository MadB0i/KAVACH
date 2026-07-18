# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in KAVACH, please report it privately
by emailing the project maintainers. **Do not** open a public GitHub issue.

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

The following are in scope:
- Code execution or privilege escalation via crafted policy files or requests
- Bypass of policy enforcement (e.g., accessing denied resources)
- Secret leakage through logs, errors, or audit events
- Audit chain integrity bypass
- SSRF bypass in network enforcement

The following are out of scope:
- Social engineering of project contributors
- Attacks requiring physical access to the machine running KAVACH
- DoS via resource exhaustion (rate limiting is configurable)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |

## Security Features

KAVACH is designed with security as the default:
- `#![forbid(unsafe_code)]` across the entire workspace
- Default-deny policy evaluation
- Fail-closed on any error
- Deterministic decision ordering
- No secret logging (secrets never appear in errors, logs, or debug output)
- SHA-256 hashed audit chain
- CSPRNG 256-bit approval tokens, hashed at rest
- Constant-time token comparison
- Input validation with `deny_unknown_fields` on all deserialization
