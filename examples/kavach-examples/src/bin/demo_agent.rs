#![allow(clippy::print_stdout, clippy::unwrap_used)]

//! demo-agent: End-to-end KAVACH agent workflow (evaluate-only).
//!
//! Uses temporary files, databases, and local servers only.
//! No public internet access, no destructive real commands.
//! Execution enforcement is proven by existing KAVACH integration tests.
//!
//! Shows:
//!   1. Allowed project-file evaluate → Permitted
//!   2. Denied .env evaluate → Denied (no secret leak)
//!   3. Approval-required file deletion (approve + consume)
//!   4. Allowed harmless command evaluate → Permitted
//!   5. Denied dangerous command evaluate → Denied
//!   6. Allowed local HTTP evaluate → Permitted
//!   7. Blocked SSRF destination evaluate → Denied
//!   8. Response secret redaction
//!   9. Single-use approval replay rejection
//!  10. Successful audit-chain verification

use std::time::Duration;

use kavach_approval::ApprovalActor;
use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::{
    CommandResource, NetworkHost, NetworkPort, NetworkResource, NetworkScheme, Resource,
};
use kavach_core::subject::TrustLevel;
use kavach_policy::{DefaultEffect, Effect, Policy, Rule, RuleConditions};
use kavach_redaction::{CompositeRedactor, Redactor};
use kavach_runtime::config::RuntimeConfig;
use kavach_runtime::outcome::RuntimeOutcome;
use kavach_runtime::runtime::RuntimeBuilder;

fn main() {
    let mut pass = 0u32;
    let total = 10u32;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║        KAVACH End-to-End Demo Agent                        ║");
    println!("║        Zero-Trust Runtime Enforcement                       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Setup temp workspace
    let ws_root = std::env::temp_dir().join("kavach-demo-e2e");
    let _ = std::fs::remove_dir_all(&ws_root);
    std::fs::create_dir_all(&ws_root).expect("create workspace");
    std::fs::write(ws_root.join("report.txt"), b"demo data for approval test\n")
        .expect("write report.txt");

    let audit_path = ws_root.join("audit.db").to_string_lossy().to_string();
    let approval_path = ws_root.join("approvals.db").to_string_lossy().to_string();

    let policy = Policy {
        id: PolicyId::new("demo-e2e").unwrap(),
        name: "Demo E2E Policy".into(),
        description: "Comprehensive demo policy".into(),
        default_effect: DefaultEffect::Deny,
        rules: vec![
            Rule {
                id: RuleId::new("allow-src-read").unwrap(),
                description: "Allow reading project source".into(),
                effect: Effect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["src/**".into()]),
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("deny-env").unwrap(),
                description: "Block secret files".into(),
                effect: Effect::Deny,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["**/.env".into(), "**/.env.*".into()]),
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
            Rule {
                id: RuleId::new("allow-echo").unwrap(),
                description: "Allow echo".into(),
                effect: Effect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec!["echo".into(), "cmd.exe".into()]),
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("deny-shutdown").unwrap(),
                description: "Block shutdown/rm".into(),
                effect: Effect::Deny,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec![
                        "rm".into(),
                        "del".into(),
                        "shutdown".into(),
                        "format".into(),
                    ]),
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("allow-localhost").unwrap(),
                description: "Allow localhost HTTP".into(),
                effect: Effect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_schemes: Some(vec!["http".into()]),
                    network_hosts: Some(vec!["127.0.0.1".into(), "localhost".into()]),
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("deny-metadata").unwrap(),
                description: "Block SSRF targets".into(),
                effect: Effect::Deny,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_hosts: Some(vec![
                        "169.254.169.254".into(),
                        "metadata.google.internal".into(),
                    ]),
                    ..Default::default()
                },
            },
        ],
    };

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

    // SCENARIO 1: Allowed project-file read
    {
        println!("─── Scenario 1: Allowed project-file read ──────────────");
        let req = make_req(
            "e2e-1",
            Operation::FileRead {
                max_bytes: Some(4096),
            },
            Resource::file("src/app.rs").unwrap(),
        );
        match runtime.evaluate(&req).unwrap() {
            RuntimeOutcome::Permitted(_) => {
                pass += 1;
                println!("    PASS 1/10: src/app.rs Permitted");
            }
            other => {
                println!("    FAIL 1/10: expected Permitted, got {:?}", other);
                ok = false;
            }
        }
    }

    // SCENARIO 2: Denied .env read (verify sanitized summary)
    {
        println!("─── Scenario 2: Denied .env read ────────────────────────");
        let req = make_req(
            "e2e-2",
            Operation::FileRead {
                max_bytes: Some(4096),
            },
            Resource::file(".env").unwrap(),
        );
        match runtime.evaluate(&req).unwrap() {
            RuntimeOutcome::Denied {
                reason_code,
                sanitized_summary,
                ..
            } => {
                println!("    Denied ({:?})", reason_code);
                println!("    Sanitized: {}", sanitized_summary);
                let leak =
                    sanitized_summary.contains("sk-test") || sanitized_summary.contains("abc123");
                if !leak {
                    pass += 1;
                    println!("    PASS 2/10: .env read Denied (no leak)");
                } else {
                    println!("    FAIL 2/10: leaked secrets");
                    ok = false;
                }
            }
            other => {
                println!("    FAIL 2/10: expected Denied, got {:?}", other);
                ok = false;
            }
        }
    }

    // SCENARIO 3: Approval-required file deletion + approve + consume
    {
        println!("─── Scenario 3: Approval-required file deletion ─────────");
        let req = make_req(
            "e2e-3",
            Operation::FileDelete,
            Resource::file("data/report.txt").unwrap(),
        );
        if let RuntimeOutcome::ApprovalRequired { approval_id, .. } =
            runtime.evaluate(&req).unwrap()
        {
            println!("    ApprovalRequired (id={})", approval_id);
            let actor = ApprovalActor::new("demo-admin").unwrap();
            let token = runtime.approve(&approval_id, &actor).expect("approve");
            println!("    Approval granted");
            // Reuse the SAME request (same digest needed for consume)
            if runtime.consume_approval(&req, &approval_id, &token).is_ok() {
                pass += 1;
                println!("    PASS 3/10: Approval flow completed");
            } else {
                println!("    FAIL 3/10: consume failed");
                ok = false;
            }
        } else {
            println!("    FAIL 3/10: expected ApprovalRequired");
            ok = false;
        }
    }

    // SCENARIO 4: Allowed harmless command
    {
        println!("─── Scenario 4: Allowed harmless command ────────────────");
        let (exe, args): (&str, Vec<&str>) = if cfg!(target_os = "windows") {
            ("cmd.exe", vec!["/C", "echo", "hello"])
        } else {
            ("echo", vec!["hello"])
        };
        let cmd_res =
            CommandResource::new(exe, args.iter().map(|s| s.to_string()).collect()).unwrap();
        let req = make_req(
            "e2e-4",
            Operation::CommandExecute,
            Resource::Command(cmd_res),
        );
        match runtime.evaluate(&req).unwrap() {
            RuntimeOutcome::Permitted(_) => {
                pass += 1;
                println!("    PASS 4/10: echo Permitted");
            }
            other => {
                println!("    FAIL 4/10: expected Permitted, got {:?}", other);
                ok = false;
            }
        }
    }

    // SCENARIO 5: Denied dangerous command
    {
        println!("─── Scenario 5: Denied dangerous command ────────────────");
        let cmd_res = CommandResource::new("shutdown", vec![]).unwrap();
        let req = make_req(
            "e2e-5",
            Operation::CommandExecute,
            Resource::Command(cmd_res),
        );
        match runtime.evaluate(&req).unwrap() {
            RuntimeOutcome::Denied { reason_code, .. } => {
                pass += 1;
                println!("    PASS 5/10: shutdown Denied ({:?})", reason_code);
            }
            other => {
                println!("    FAIL 5/10: expected Denied, got {:?}", other);
                ok = false;
            }
        }
    }

    // SCENARIO 6: Allowed local HTTP
    {
        println!("─── Scenario 6: Allowed local HTTP ──────────────────────");
        let net_res = NetworkResource::new(
            NetworkScheme::new("http").unwrap(),
            NetworkHost::new("127.0.0.1").unwrap(),
            Some(NetworkPort::new(8080)),
            "/demo",
        )
        .unwrap();
        let req = make_req(
            "e2e-6",
            Operation::NetworkRequest,
            Resource::NetworkEndpoint(net_res),
        );
        match runtime.evaluate(&req).unwrap() {
            RuntimeOutcome::Permitted(_) => {
                pass += 1;
                println!("    PASS 6/10: localhost HTTP Permitted");
            }
            other => {
                println!("    FAIL 6/10: expected Permitted, got {:?}", other);
                ok = false;
            }
        }
    }

    // SCENARIO 7: Blocked SSRF destination
    {
        println!("─── Scenario 7: Blocked SSRF destination ────────────────");
        let net_res = NetworkResource::new(
            NetworkScheme::new("http").unwrap(),
            NetworkHost::new("169.254.169.254").unwrap(),
            None,
            "/latest/meta-data/",
        )
        .unwrap();
        let req = make_req(
            "e2e-7",
            Operation::NetworkRequest,
            Resource::NetworkEndpoint(net_res),
        );
        match runtime.evaluate(&req).unwrap() {
            RuntimeOutcome::Denied { reason_code, .. } => {
                pass += 1;
                println!("    PASS 7/10: SSRF blocked ({:?})", reason_code);
            }
            other => {
                println!("    FAIL 7/10: expected Denied, got {:?}", other);
                ok = false;
            }
        }
    }

    // SCENARIO 8: Response secret redaction
    {
        println!("─── Scenario 8: Response secret redaction ───────────────");
        let redactor = CompositeRedactor::builder()
            .with_bearer(true)
            .with_assignments(true)
            .build();
        let response = r#"HTTP/1.1 200 OK
Content-Type: application/json
Authorization: Bearer sk-secret-test-abc

{"status":"ok","user":"admin","data":"API_KEY = a1b2c3d4e5f6"}"#;
        let redacted = redactor.redact_text(response).expect("redact");
        let s = &redacted.redacted;
        let has_redacted = s.contains("[REDACTED");
        let leak = s.contains("sk-secret-test-abc") || s.contains("a1b2c3d4e5f6");
        let preserved = s.contains("admin");
        println!("    Redacted: {}", s);
        if has_redacted && !leak && preserved {
            pass += 1;
            println!("    PASS 8/10: Secrets redacted, data preserved");
        } else {
            if !has_redacted {
                println!("    FAIL: no redaction markers");
            }
            if leak {
                println!("    FAIL: secrets leaked");
            }
            if !preserved {
                println!("    FAIL: non-secret data lost");
            }
            ok = false;
        }
    }

    // SCENARIO 9: Single-use approval replay rejection
    {
        println!("─── Scenario 9: Single-use approval replay ──────────────");
        let req = make_req(
            "e2e-9",
            Operation::FileDelete,
            Resource::file("data/report.txt").unwrap(),
        );
        if let RuntimeOutcome::ApprovalRequired { approval_id, .. } =
            runtime.evaluate(&req).unwrap()
        {
            println!("    ApprovalRequired");
            let actor = ApprovalActor::new("demo-admin").unwrap();
            let token = runtime.approve(&approval_id, &actor).expect("approve");
            // First consume
            let ok1 = runtime.consume_approval(&req, &approval_id, &token).is_ok();
            // Second consume with SAME request (digest must match)
            let ok2 = runtime.consume_approval(&req, &approval_id, &token).is_ok();
            if ok1 && !ok2 {
                pass += 1;
                println!("    PASS 9/10: First use OK, replay rejected");
            } else {
                println!("    FAIL 9/10: first={}, replay={}", ok1, ok2);
                ok = false;
            }
        } else {
            println!("    FAIL 9/10: expected ApprovalRequired");
            ok = false;
        }
    }

    // SCENARIO 10: Audit-chain verification
    {
        println!("─── Scenario 10: Audit-chain verification ───────────────");
        let store = runtime.audit_store();
        match store.verify_full() {
            Ok(report) if report.chain_valid => {
                pass += 1;
                println!(
                    "    PASS 10/10: Chain valid ({} events)",
                    report.event_count
                );
            }
            Ok(_report) => {
                println!("    FAIL 10/10: chain INVALID");
                ok = false;
            }
            Err(e) => {
                println!("    FAIL 10/10: verify error: {:?}", e);
                ok = false;
            }
        }
    }

    let _ = std::fs::remove_dir_all(&ws_root);

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    if ok && pass == total {
        println!(
            "║           ALL {}/{} DEMO SCENARIOS PASSED              ║",
            pass, total
        );
        println!("╚══════════════════════════════════════════════════════════════╝");
        std::process::exit(0);
    } else {
        println!(
            "║           DEMO FAILED ({}/{})                           ║",
            pass, total
        );
        println!("╚══════════════════════════════════════════════════════════════╝");
        std::process::exit(1);
    }
}

fn make_req(id: &str, op: Operation, resource: Resource) -> ToolRequest {
    ToolRequest::new(
        RequestId::new(id).unwrap(),
        AgentSubjectBuilder::new(
            AgentId::new("demo-agent").unwrap(),
            SessionId::new("demo-sess").unwrap(),
        )
        .trust_level(TrustLevel::Standard)
        .build(),
        op,
        resource,
        RequestContext::new(None, None, None, None, false).unwrap(),
    )
}
