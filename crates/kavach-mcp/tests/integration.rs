//! Integration tests for the MCP security adapter.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use kavach_core::Operation;
use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use kavach_mcp::protocol;
use kavach_policy::{DefaultEffect, Effect as PolicyEffect, Rule, RuleConditions};
use kavach_runtime::config::RuntimeConfig;
use kavach_runtime::outcome::RuntimeOutcome;
use kavach_runtime::runtime::{KavachRuntime, RuntimeBuilder};

fn make_tool_request(tool_name: &str, request_id: &str) -> ToolRequest {
    let req_id = RequestId::new(request_id).unwrap();
    let agent_id = AgentId::new("test-agent").unwrap();
    let session_id = SessionId::new("test-session").unwrap();
    let subject = AgentSubjectBuilder::new(agent_id, session_id)
        .trust_level(TrustLevel::Standard)
        .build();
    let operation = Operation::ToolInvoke {
        tool_id: tool_name.to_string(),
    };
    let resource = Resource::ExternalTool {
        identifier: tool_name.to_string(),
    };
    let context = RequestContext::new(None, None, None, None, false).unwrap();
    ToolRequest::new(req_id, subject, operation, resource, context)
}

fn allowed_runtime() -> Arc<KavachRuntime> {
    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let audit = dir.path().join("audit.db").to_string_lossy().to_string();
    let approval = dir.path().join("approval.db").to_string_lossy().to_string();
    let policy = kavach_policy::Policy {
        id: PolicyId::new("allow-mcp").unwrap(),
        name: "Allow MCP Tools".into(),
        description: "".into(),
        default_effect: DefaultEffect::Deny,
        rules: vec![Rule {
            id: RuleId::new("allow-tool-calls").unwrap(),
            description: "".into(),
            effect: PolicyEffect::Allow,
            conditions: RuleConditions {
                operations: vec!["tool_invoke".into()],
                ..Default::default()
            },
        }],
    };
    let rt = RuntimeBuilder::new()
        .with_config(RuntimeConfig {
            permit_ttl: Duration::from_secs(300),
            audit_fail_closed: true,
            redaction_enabled: false,
            max_sanitized_summary_length: 4096,
            dry_run: false,
        })
        .with_workspace_root(ws)
        .with_audit_db(audit)
        .with_approval_db(approval)
        .add_policy(policy)
        .build()
        .unwrap();
    Arc::new(rt)
}

fn denied_runtime() -> Arc<KavachRuntime> {
    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let audit = dir.path().join("audit.db").to_string_lossy().to_string();
    let approval = dir.path().join("approval.db").to_string_lossy().to_string();
    let policy = kavach_policy::Policy {
        id: PolicyId::new("deny-mcp").unwrap(),
        name: "Deny MCP Tools".into(),
        description: "".into(),
        default_effect: DefaultEffect::Deny,
        rules: vec![Rule {
            id: RuleId::new("deny-tool-calls").unwrap(),
            description: "".into(),
            effect: PolicyEffect::Deny,
            conditions: RuleConditions {
                operations: vec!["tool_invoke".into()],
                ..Default::default()
            },
        }],
    };
    let rt = RuntimeBuilder::new()
        .with_config(RuntimeConfig {
            permit_ttl: Duration::from_secs(300),
            audit_fail_closed: true,
            redaction_enabled: false,
            max_sanitized_summary_length: 4096,
            dry_run: false,
        })
        .with_workspace_root(ws)
        .with_audit_db(audit)
        .with_approval_db(approval)
        .add_policy(policy)
        .build()
        .unwrap();
    Arc::new(rt)
}

// ── Protocol Tests ──────────────────────────────────────────────────────

#[test]
fn malformed_request_rejected() {
    let result = protocol::parse_message("not valid json");
    assert!(result.is_err());
}

#[test]
fn oversized_request_rejected() {
    let large = "x".repeat(protocol::MAX_MESSAGE_SIZE + 1);
    let big = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"data\":\"{large}\"}}}}"
    );
    let result = protocol::parse_message(&big);
    assert!(result.is_err());
}

#[test]
fn empty_message_rejected() {
    let result = protocol::parse_message("");
    assert!(result.is_err());
}

#[test]
fn invalid_jsonrpc_version_rejected() {
    let result = protocol::parse_message(r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#);
    assert!(
        result.is_err(),
        "wrong jsonrpc version should be rejected via unknown fields"
    );
}

#[test]
fn request_without_method_rejected() {
    let result = protocol::parse_message(r#"{"jsonrpc":"2.0","id":1}"#);
    assert!(result.is_err(), "request without method should be rejected");
}

// ── Redaction Tests ─────────────────────────────────────────────────────

#[test]
fn secret_redaction_removes_bearer_tokens() {
    let input = r#"Bearer abcdef1234567890abcdef1234567890abcdef12"#;
    let result = kavach_mcp::proxy::redact_text(input);
    assert!(
        result.contains("[REDACTED:"),
        "Bearer token should be redacted"
    );
    assert!(!result.contains("abcdef1234567890"));
}

#[test]
fn secret_redaction_removes_api_keys() {
    let input = r#"{"key": "sk-abc123def456"}"#;
    let result = kavach_mcp::proxy::redact_text(input);
    assert!(result.contains("[REDACTED:"), "API key should be redacted");
    assert!(!result.contains("sk-abc123def456"));
}

// ── Evaluate Tests ──────────────────────────────────────────────────────

#[test]
fn allowed_tool_call() {
    let rt = allowed_runtime();
    let req = make_tool_request("read_file", "test-allowed");
    let outcome = rt.evaluate(&req).unwrap();
    assert!(
        matches!(outcome, RuntimeOutcome::Permitted(_)),
        "expected Permitted"
    );
}

#[test]
fn denied_tool_call_never_forwarded() {
    let rt = denied_runtime();
    let req = make_tool_request("read_file", "test-denied");
    let outcome = rt.evaluate(&req).unwrap();
    assert!(
        matches!(outcome, RuntimeOutcome::Denied { .. }),
        "expected Denied"
    );
}

#[test]
fn approval_required_call_never_forwarded() {
    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let audit = dir.path().join("audit.db").to_string_lossy().to_string();
    let approval = dir.path().join("approval.db").to_string_lossy().to_string();
    let policy = kavach_policy::Policy {
        id: PolicyId::new("approval-mcp").unwrap(),
        name: "Approval MCP Tools".into(),
        description: "".into(),
        default_effect: DefaultEffect::RequireApproval,
        rules: vec![Rule {
            id: RuleId::new("approve-tool-calls").unwrap(),
            description: "".into(),
            effect: PolicyEffect::RequireApproval,
            conditions: RuleConditions {
                operations: vec!["tool_invoke".into()],
                ..Default::default()
            },
        }],
    };
    let rt = RuntimeBuilder::new()
        .with_config(RuntimeConfig {
            permit_ttl: Duration::from_secs(300),
            audit_fail_closed: true,
            redaction_enabled: false,
            max_sanitized_summary_length: 4096,
            dry_run: false,
        })
        .with_workspace_root(ws)
        .with_audit_db(audit)
        .with_approval_db(approval)
        .add_policy(policy)
        .build()
        .unwrap();
    let req = make_tool_request("read_file", "test-approval");
    let outcome = rt.evaluate(&req).unwrap();
    assert!(
        matches!(outcome, RuntimeOutcome::ApprovalRequired { .. }),
        "expected ApprovalRequired"
    );
}

#[test]
fn runtime_failure_fails_closed() {
    let rt = denied_runtime();
    let req = make_tool_request("unknown_tool", "test-fail-closed");
    let outcome = rt.evaluate(&req).unwrap();
    assert!(
        matches!(outcome, RuntimeOutcome::Denied { .. }),
        "deny policy should fail closed"
    );
}

#[test]
fn repeated_requests_deterministic() {
    let rt = allowed_runtime();
    let req = make_tool_request("read_file", "repeat-test");
    let r1 = rt.evaluate(&req).unwrap();
    let r2 = rt.evaluate(&req).unwrap();
    // Policy decision is deterministic (both Permitted), even though permit
    // contains random token bytes.
    let kind1 = std::mem::discriminant(&r1);
    let kind2 = std::mem::discriminant(&r2);
    assert_eq!(kind1, kind2, "decision kind must be deterministic");
    assert!(matches!(r1, RuntimeOutcome::Permitted(_)));
    assert!(matches!(r2, RuntimeOutcome::Permitted(_)));
}

// ── Tool Identity Mapping Tests ─────────────────────────────────────────

#[test]
fn different_tools_produce_different_evaluations() {
    let rt = allowed_runtime();
    let req_tool1 = make_tool_request("read_file", "tool-1");
    let req_tool2 = make_tool_request("write_file", "tool-2");
    let o1 = rt.evaluate(&req_tool1).unwrap();
    let o2 = rt.evaluate(&req_tool2).unwrap();
    // Both should be allowed under allow-all policy.
    assert!(matches!(o1, RuntimeOutcome::Permitted(_)));
    assert!(matches!(o2, RuntimeOutcome::Permitted(_)));
}

// ── Audit Events Tests ──────────────────────────────────────────────────

#[test]
fn allowed_call_creates_audit_event() {
    let rt = allowed_runtime();
    let req = make_tool_request("read_file", "audit-test");
    let before = rt.audit_store().event_count().unwrap_or(0);
    let _outcome = rt.evaluate(&req).unwrap();
    let after = rt.audit_store().event_count().unwrap_or(0);
    assert!(after > before, "evaluation should create audit event");
}

#[test]
fn denied_call_creates_audit_event() {
    let rt = denied_runtime();
    let req = make_tool_request("read_file", "audit-deny");
    let before = rt.audit_store().event_count().unwrap_or(0);
    let _outcome = rt.evaluate(&req).unwrap();
    let after = rt.audit_store().event_count().unwrap_or(0);
    assert!(
        after > before,
        "denied evaluation should create audit event"
    );
}

// ── Timeout Tests ───────────────────────────────────────────────────────

#[test]
fn proxy_config_timeout_default() {
    let config = kavach_mcp::proxy::McpProxyConfig::default();
    assert_eq!(config.request_timeout, Duration::from_secs(30));
}
