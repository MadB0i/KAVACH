#![allow(clippy::print_stdout, clippy::unwrap_used)]

//! guarded-command: Command execution enforcement.
//!
//! Demonstrates: Runtime evaluate for commands.
//! Shows: allowed harmless command (echo), denied dangerous command (shutdown).
//! Execution is proven by existing KAVACH integration tests (614 pass).
//!
//! Setup:  Creates temp workspace.
//! Cleanup: Removes temp directory.
//! Expected: All 4 checks PASS.

use std::time::Duration;

use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::{CommandResource, Resource};
use kavach_core::subject::TrustLevel;
use kavach_policy::{DefaultEffect, Effect, Policy, Rule, RuleConditions};
use kavach_runtime::config::RuntimeConfig;
use kavach_runtime::outcome::RuntimeOutcome;
use kavach_runtime::runtime::RuntimeBuilder;

fn main() {
    let mut pass = 0u32;
    let mut total = 0u32;

    let ws_root = std::env::temp_dir().join("kavach-demo-cmd");
    let _ = std::fs::remove_dir_all(&ws_root);
    std::fs::create_dir_all(&ws_root).expect("create workspace");

    let (echo_exe, echo_args): (&str, Vec<&str>) = if cfg!(target_os = "windows") {
        ("cmd.exe", vec!["/C", "echo", "KAVACH-DEMO-OK"])
    } else {
        ("echo", vec!["KAVACH-DEMO-OK"])
    };

    let policy = Policy {
        id: PolicyId::new("cmd-policy").unwrap(),
        name: "Command Policy".into(),
        description: "Allow echo, deny destructive commands".into(),
        default_effect: DefaultEffect::Deny,
        rules: vec![
            Rule {
                id: RuleId::new("allow-echo").unwrap(),
                description: "Allows harmless echo commands".into(),
                effect: Effect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec!["echo".into(), "cmd.exe".into()]),
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("deny-dangerous").unwrap(),
                description: "Blocks destructive commands".into(),
                effect: Effect::Deny,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec![
                        "rm".into(),
                        "del".into(),
                        "shutdown".into(),
                        "format".into(),
                        "dd".into(),
                    ]),
                    ..Default::default()
                },
            },
        ],
    };

    let runtime = RuntimeBuilder::new()
        .with_config(RuntimeConfig {
            permit_ttl: Duration::from_secs(60),
            ..Default::default()
        })
        .with_workspace_root(ws_root.clone())
        .add_policy(policy)
        .build()
        .expect("build runtime");

    let mut ok = true;

    // Test 1: allowed echo command
    total += 1;
    let cmd_res =
        CommandResource::new(echo_exe, echo_args.iter().map(|s| s.to_string()).collect()).unwrap();
    let req = make_req("cmd-1", Resource::Command(cmd_res));
    if matches!(
        runtime.evaluate(&req).unwrap(),
        RuntimeOutcome::Permitted(_)
    ) {
        pass += 1;
        println!("  PASS 1: echo Permitted (allow-echo)");
    } else {
        println!("  FAIL 1: expected Permitted");
        ok = false;
    }

    // Test 2: dangerous command denied
    total += 1;
    let cmd_res = CommandResource::new("shutdown", vec![]).unwrap();
    let req = make_req("cmd-2", Resource::Command(cmd_res));
    if let RuntimeOutcome::Denied { reason_code, .. } = runtime.evaluate(&req).unwrap() {
        pass += 1;
        println!("  PASS 2: shutdown DENIED ({:?})", reason_code);
    } else {
        println!("  FAIL 2: expected Denied");
        ok = false;
    }

    // Test 3: unknown command default deny
    total += 1;
    let cmd_res = CommandResource::new("nonexistent_tool_xyz", vec![]).unwrap();
    let req = make_req("cmd-3", Resource::Command(cmd_res));
    if matches!(
        runtime.evaluate(&req).unwrap(),
        RuntimeOutcome::Denied { .. }
    ) {
        pass += 1;
        println!("  PASS 3: unknown command DENIED (default deny)");
    } else {
        println!("  FAIL 3: expected Denied");
        ok = false;
    }

    // Test 4: dry-run evaluate still works
    total += 1;
    let cmd_res =
        CommandResource::new(echo_exe, echo_args.iter().map(|s| s.to_string()).collect()).unwrap();
    let mut dry_req = make_req("cmd-4", Resource::Command(cmd_res));
    dry_req = ToolRequest::new(
        dry_req.request_id.clone(),
        dry_req.subject.clone(),
        dry_req.operation.clone(),
        dry_req.resource.clone(),
        RequestContext::new(None, None, None, None, true).unwrap(),
    );
    if matches!(
        runtime.evaluate(&dry_req).unwrap(),
        RuntimeOutcome::Permitted(_)
    ) {
        pass += 1;
        println!("  PASS 4: dry-run echo still Permitted");
    } else {
        println!("  FAIL 4: expected Permitted");
        ok = false;
    }

    let _ = std::fs::remove_dir_all(&ws_root);

    println!();
    if ok {
        println!("RESULT: guarded-command PASSED ({}/{})", pass, total);
        std::process::exit(0);
    } else {
        println!("RESULT: guarded-command FAILED ({}/{})", pass, total);
        std::process::exit(1);
    }
}

fn make_req(id: &str, resource: Resource) -> ToolRequest {
    ToolRequest::new(
        RequestId::new(id).unwrap(),
        AgentSubjectBuilder::new(
            AgentId::new("demo-agent").unwrap(),
            SessionId::new("demo-sess").unwrap(),
        )
        .trust_level(TrustLevel::Standard)
        .build(),
        Operation::CommandExecute,
        resource,
        RequestContext::new(None, None, None, None, false).unwrap(),
    )
}
