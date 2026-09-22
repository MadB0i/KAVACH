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

## Gateway and Dashboard Credentials

The gateway requires `KAVACH_GATEWAY_TOKEN` to contain exactly 64 hexadecimal
characters. Startup rejects a missing or malformed value. The server stores a
hash for constant-time comparison and does not generate or print a token.

The dashboard keeps the entered token in process memory only. It must not be
placed in `localStorage`, `sessionStorage`, URLs, logs, audit events, or rendered
operator data. A page refresh therefore requires re-authentication.

Approval tokens and execution permits are separate from the gateway token.
Approval API records omit raw tokens, and execution uses gateway-held permits
rather than trusting client-supplied permit metadata.

## Security Boundaries

- KAVACH is an authorization and enforcement layer, not an operating-system
  sandbox. It does not replace process isolation, containers, seccomp, or
  least-privilege service accounts.
- Policy path matching is lexical. Filesystem enforcement performs the
  filesystem-aware containment check at execution time.
- Network protection revalidates resolved addresses and redirect targets, but
  operators should still apply outbound network controls for defense in depth.
- Audit hashes make tampering detectable; they do not prevent an attacker with
  database write access from deleting or replacing the database.
- Raw approved tokens and issued permits are deliberately process-local and do
  not survive a gateway restart. Pending approval records do persist.
