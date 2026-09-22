# KAVACH Architecture

KAVACH is a local, default-deny authorization and enforcement runtime for AI
agent tool calls. The workspace separates pure request and policy logic from
side-effecting enforcement, persistence, transport, and presentation.

## Security flow

```text
ToolRequest
  -> domain validation
  -> deterministic policy evaluation
     -> deny: audit DecisionDeny and stop
     -> require approval: persist request digest and audit ApprovalRequested
     -> allow: issue a request-bound, expiring permit
  -> human approval decision (when required)
  -> one-time approval-token exchange for a permit
  -> server-side permit lookup and request/digest/scope/secret verification
  -> adapter containment and enforcement
  -> output redaction
  -> audit ExecutionSucceeded or ExecutionFailed
```

A policy decision alone does not perform an operation. The selected adapter
performs the final scope, binding, expiry, and secret checks and consumes the
permit exactly once immediately before the side effect. Required audit and
redaction failures stop the operation.

## Workspace boundaries

| Component | Responsibility |
|---|---|
| `kavach-core` | Validated requests, resources, identifiers, digests, and permits |
| `kavach-policy` | TOML parsing and deterministic deny/approval/allow evaluation |
| `kavach-config` | File configuration, environment overrides, and validation |
| `kavach-enforcement` | Filesystem containment, command controls, and network SSRF controls |
| `kavach-redaction` | Secret detectors and fail-closed sanitization |
| `kavach-audit` | SQLite hash-linked event chain and verification |
| `kavach-approval` | Persistent approval state and one-time token validation |
| `kavach-runtime` | End-to-end orchestration and adapter dispatch |
| `kavach-gateway` | Authenticated HTTP API and production dashboard hosting |
| `kavach-mcp` | Policy-gated MCP forwarding |
| `kavach-cli` | Operator commands and process startup |
| `dashboard` | Same-origin React operator console using real gateway APIs |

## Trust boundaries

- Request JSON, execution input, policy files, MCP messages, and HTTP headers
  are untrusted and validated.
- Serialized permit metadata from a client is not authoritative. The gateway
  retrieves an issued permit from a bounded server-side registry.
- Approval tokens never enter list/detail API responses. The gateway retains a
  freshly approved raw token in memory and SQLite stores only its hash.
- Filesystem policy matching is lexical; enforcement resolves the filesystem
  path and verifies workspace containment before access.
- Network authorization is repeated during DNS resolution and for every
  redirect to preserve SSRF and DNS-rebinding protections.
- The runtime and approval broker share one audit-store handle so approval and
  execution events appear in the same dashboard-visible chain.

## Persistence and restart behavior

Audit events and approval records persist in their configured SQLite files.
Their parent directories are created when needed, and startup can require a
valid audit chain before binding the gateway.

Raw approval tokens and execution permits deliberately remain process-local.
A restart invalidates issued permits and approved tokens waiting for exchange.
Pending approvals remain listed after restart.

## Gateway and dashboard

The gateway binds to loopback by default. Non-loopback binding requires an
explicit opt-in and still requires bearer authentication. The operator must
set `KAVACH_GATEWAY_TOKEN` to exactly 64 hexadecimal characters; the process
does not generate or print credentials.

The production console is served under `/dashboard/`. `/health` and `/ready`
are public probes, while `/api/*` requires the bearer token. The dashboard
holds the token in React memory only, so a refresh returns to login.

## Agent security layer (cooperative hooks, not kernel interception)

The "Agent Security OS Layer" branding refers to a persistent local
convenience layer: per-tool PreToolUse hook adapters (Claude Code, Codex
CLI, OpenCode) plus the `kavach-dashboard` feed. Technically it is a
**cooperative hook-based enforcement layer**: each adapter translates the
tool's own hook payload into a ToolRequest, evaluates it with the standard
policy engine, and returns the tool's native allow/deny verdict. There is
no kernel driver, no process tracing, and no system-wide interception —
any tool without a hook API, or run with hooks disabled or bypassed,
executes outside this layer. Do not describe it as OS- or kernel-level
enforcement in technical or paper-facing text.
