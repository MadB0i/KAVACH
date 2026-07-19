# KAVACH Architecture

KAVACH is a local, default-deny authorization and enforcement runtime for AI
agent tool calls. The workspace separates pure request/policy logic from
side-effecting enforcement, persistence, transport, and presentation.

## Runtime flow

```text
ToolRequest
  -> deep domain validation
  -> deterministic policy evaluation
     -> deny: append DecisionDeny and stop
     -> require approval: persist request digest and append ApprovalRequested
     -> allow: issue a request-bound, expiring permit
  -> approval decision (when required)
  -> one-time approval token exchange for a permit
  -> server-side permit lookup and request/digest/scope/secret verification
  -> adapter enforcement
  -> output redaction
  -> ExecutionSucceeded or ExecutionFailed audit event
```

Every failure on this path is terminal for the attempted operation. A policy
decision alone does not perform an operation; the corresponding enforcement
adapter performs final permit verification and consumes the permit exactly
once immediately before the side effect.

## Workspace boundaries

| Crate | Responsibility |
|---|---|
| `kavach-core` | Validated requests, resources, identifiers, decisions, digests, permits |
| `kavach-policy` | TOML parsing and deterministic deny/approval/allow evaluation |
| `kavach-config` | Defaults, file configuration, environment overrides, validation |
| `kavach-enforcement` | Filesystem containment, command controls, network/SSRF controls |
| `kavach-redaction` | Secret detectors and fail-closed output/audit sanitization |
| `kavach-audit` | SQLite hash-linked append-only event chain and verification |
| `kavach-approval` | Restart-safe approval state machine and one-time token validation |
| `kavach-runtime` | Orchestration and adapter dispatch |
| `kavach-gateway` | Authenticated loopback HTTP API and dashboard static hosting |
| `kavach-mcp` | MCP interception and policy-gated forwarding |
| `kavach-cli` | Operator commands and process startup |

The React dashboard is a same-origin client of the gateway. It uses only real
gateway endpoints and retains the bearer token in memory, never in local or
session storage.

## Trust boundaries

- Agent-controlled request JSON, execution inputs, policy files, and HTTP
  headers are untrusted and deeply validated.
- Dashboard permit metadata is not authoritative. The gateway retrieves the
  original permit from a bounded, server-side, take-once registry.
- Approval tokens are returned only to the gateway process, retained in memory,
  and never serialized to the dashboard. SQLite stores only their hash.
- Filesystem policy matching is lexical; filesystem-aware enforcement
  canonicalizes paths and checks workspace containment before access.
- Network authorization is repeated across DNS resolution and every redirect
  to prevent SSRF and rebinding bypasses.
- Audit and approval databases are separate SQLite stores. The runtime shares
  one audit-chain handle with the approval broker so approval transitions
  appear in the same dashboard-visible chain.

## Persistence and restart behavior

Audit events and approval records persist in configured SQLite databases.
Database parent directories are created on startup and the audit chain can be
verified before the gateway binds.

Raw approval tokens and execution permits deliberately do not persist. A
gateway restart therefore invalidates already-issued permits and any approved
token awaiting exchange. Pending approvals remain available after restart.

## Gateway and dashboard

The gateway binds to loopback by default. Non-loopback binding requires an
explicit opt-in and does not remove the requirement for bearer authentication.
The token must be supplied through `KAVACH_GATEWAY_TOKEN` as exactly 64
hexadecimal characters; it is not generated or printed by the process.

The production dashboard is served below `/dashboard/`. `/health` and `/ready`
are public health probes; `/api/*` requires the bearer token. API responses use
the standard `{request_id,status,data,error?}` envelope.
