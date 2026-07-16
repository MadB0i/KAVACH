#![allow(clippy::print_stdout, clippy::unwrap_used)]

//! approval-flow: Full approval lifecycle.
//!
//! Demonstrates: Evaluate → ApprovalRequired → approve → consume → replay rejection.
//! Also shows: Audit-chain verification.
//!
//! Setup:  Creates temp workspace with audit and approval databases.
//! Cleanup: Removes temp directory.
//! Expected: All 6 checks PASS.

use std::time::Duration;

use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use kavach_policy::{DefaultEffect, Effect, Policy, Rule, RuleConditions};
use kavach_runtime::config::RuntimeConfig;
use kavach_runtime::outcome::RuntimeOutcome;
use kavach_runtime::runtime::RuntimeBuilder;

fn main() {
    let mut pass = 0u32;
    let total = 6u32;

    // ── 1. Create temp workspace ──────────────────────────────────────

    let ws_root = std::env::temp_dir().join("kavach-demo-approve");
    let _ = std::fs::remove_dir_all(&ws_root);
    std::fs::create_dir_all(&ws_root).expect("create workspace");

    // ── 2. Build policy ───────────────────────────────────────────────

    let policy = Policy {
        id: PolicyId::new("approval-policy").unwrap(),
        name: "Approval Policy".into(),
        description: "Approval-required for file deletion".into(),
        default_effect: DefaultEffect::Deny,
        rules: vec![
            Rule {
                id: RuleId::new("allow-read").unwrap(),
                description: "Allow file reads".into(),
                effect: Effect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("require-approval-delete").unwrap(),
                description: "File delete requires human approval".into(),
                effect: Effect::RequireApproval,
                conditions: RuleConditions {
                    operations: vec!["file_delete".into()],
                    ..Default::default()
                },
            },
        ],
    };

    // ── 3. Build runtime (persistent approval DB) ────────────────────

    let audit_path = ws_root.join("audit.db").to_string_lossy().to_string();
    let approval_path = ws_root.join("approvals.db").to_string_lossy().to_string();

    let runtime = RuntimeBuilder::new()
        .with_config(RuntimeConfig {
            permit_ttl: Duration::from_secs(120),
            ..Default::default()
        })
        .with_workspace_root(ws_root.clone())
        .add_policy(policy)
        .with_audit_db(audit_path)
        .with_approval_db(approval_path)
        .build()
        .expect("build runtime");

    let mut ok = true;

    // ── 4. Evaluate: file read is Permitted ──────────────────────────

    {
        let req = make_req(
            "apr-1",
            Operation::FileRead {
                max_bytes: Some(1024),
            },
            Resource::file("notes.txt").unwrap(),
        );
        let outcome = runtime.evaluate(&req).unwrap();
        if matches!(outcome, RuntimeOutcome::Permitted(_)) {
            pass += 1;
            println!("  PASS 1/6: File read Permitted (allow-read rule)");
        } else {
            println!("  FAIL 1/6: expected Permitted, got {:?}", outcome);
            ok = false;
        }
    }

    // ── 5. Evaluate: file delete is ApprovalRequired (store request) ─

    let (approval_id, delete_req) = {
        let req = make_req(
            "apr-2",
            Operation::FileDelete,
            Resource::file("notes.txt").unwrap(),
        );
        let outcome = runtime.evaluate(&req).unwrap();
        match outcome {
            RuntimeOutcome::ApprovalRequired { approval_id, .. } => {
                pass += 1;
                println!(
                    "  PASS 2/6: File delete ApprovalRequired (id={})",
                    approval_id
                );
                (approval_id, req)
            }
            other => {
                println!("  FAIL 2/6: expected ApprovalRequired, got {:?}", other);
                std::process::exit(1);
            }
        }
    };

    // ── 6. Human approves → get ApprovalToken ──────────────────────

    let token = {
        let actor = kavach_approval::ApprovalActor::new("demo-admin").unwrap();
        match runtime.approve(&approval_id, &actor) {
            Ok(t) => {
                pass += 1;
                println!("  PASS 3/6: Approval granted (token=[redacted])");
                t
            }
            Err(e) => {
                println!("  FAIL 3/6: approve failed: {:?}", e);
                std::process::exit(1);
            }
        }
    };

    // ── 7. Consume approval (reuse same request = same digest) ─────

    {
        match runtime.consume_approval(&delete_req, &approval_id, &token) {
            Ok(_) => {
                pass += 1;
                println!("  PASS 4/6: Approval consumed (first use succeeds)");
            }
            Err(e) => {
                println!("  FAIL 4/6: consume failed: {:?}", e);
                ok = false;
            }
        }
    }

    // ── 8. Replay rejection: same token + same request fails ────────

    {
        match runtime.consume_approval(&delete_req, &approval_id, &token) {
            Ok(_) => {
                println!("  FAIL 5/6: replay should have been rejected");
                ok = false;
            }
            Err(_) => {
                pass += 1;
                println!("  PASS 5/6: Replay rejected (single-use token)");
            }
        }
    }

    // ── 9. Verify audit chain integrity ──────────────────────────────

    {
        let audit_store = runtime.audit_store();
        match audit_store.verify_full() {
            Ok(report) => {
                if report.chain_valid {
                    pass += 1;
                    println!(
                        "  PASS 6/6: Audit chain valid ({} events)",
                        report.event_count
                    );
                } else {
                    println!("  FAIL 6/6: Audit chain invalid");
                    ok = false;
                }
            }
            Err(e) => {
                println!("  FAIL 6/6: verify error: {:?}", e);
                ok = false;
            }
        }
    }

    // ── Cleanup ───────────────────────────────────────────────────────

    let _ = std::fs::remove_dir_all(&ws_root);

    // ── Summary ───────────────────────────────────────────────────────

    println!();
    if ok {
        println!("RESULT: approval-flow PASSED ({}/{})", pass, total);
        std::process::exit(0);
    } else {
        println!("RESULT: approval-flow FAILED ({}/{})", pass, total);
        std::process::exit(1);
    }
}

fn make_req(id: &str, operation: Operation, resource: Resource) -> ToolRequest {
    ToolRequest::new(
        RequestId::new(id).unwrap(),
        AgentSubjectBuilder::new(
            AgentId::new("demo-agent").unwrap(),
            SessionId::new("demo-sess").unwrap(),
        )
        .trust_level(TrustLevel::Standard)
        .build(),
        operation,
        resource,
        RequestContext::new(None, None, None, None, false).unwrap(),
    )
}
