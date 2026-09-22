# Human Approval Broker

KAVACH turns a `require_approval` policy decision into a persistent pending
record. Approval is an intermediate decision: it does not directly authorize a
tool side effect.

## Lifecycle

```text
Pending -> Approved -> Consumed
   |          |
   +-> Denied +-> Expired
   +-> Expired
   +-> Cancelled
```

The library exposes request, list, get, approve, deny, cancel, consume, and
expiry-sweep operations. The gateway exposes the operator-facing pending,
approve, deny, and token-exchange workflow.

1. The broker persists the canonical request digest, redacted summary, matched
   policy rules, creation time, and expiry.
2. Approval creates a 256-bit CSPRNG token. SQLite stores only its SHA-256 hash.
3. In the gateway, the raw token remains server-side and is not returned in
   approval list or detail responses.
4. Token exchange presents the original request. The digest is verified before
   the one-time token is consumed, so a mismatched request cannot destroy a
   valid token.
5. Successful consumption issues a new request-bound, scoped, expiring
   execution permit. The approval token itself cannot execute a tool.

The default approval TTL is 3,600 seconds in the library. Configuration can set
`approval.default_ttl_seconds` up to 86,400 seconds and `max_pending` up to the
implemented bound. `config/kavach.example.toml` chooses a shorter 300-second
TTL for demonstration.

## Concurrency and persistence

The SQLite store uses guarded state transitions and conditional updates. A
broker-level transition mutex serializes the audit/state sequence within a
process. Approval and audit data are separate SQLite databases, so there is no
cross-database atomic transaction; an audit append failure causes the requested
transition to fail closed.

Pending records, decisions, token hashes, and consumed state survive restart.
Raw tokens do not. Consequently, a pending approval can be decided after a
restart, but a token approved before the restart cannot be exchanged afterward
and the request must be submitted again.

## Audit and redaction

Request, approval, denial, consumption, cancellation, and expiry transitions
append structured events to the runtime's audit chain. Audit metadata contains
identifiers and sanitized summaries, never the raw approval token. Corrupt
database rows or audit failures are returned as errors instead of skipped.

## Security properties and limits

- Token comparison and request-digest comparison are constant-time.
- Tokens are single-use and bound to one approval/request digest.
- Actor, reason, summary, TTL, query, and pending-count limits are validated.
- An expiry sweep is idempotent and does not create an event when nothing
  expires.
- The gateway's in-memory raw-token registry is bounded.
- Approval records are durable, but raw token availability is intentionally a
  process boundary.
