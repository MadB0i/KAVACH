#![allow(clippy::print_stdout, clippy::unwrap_used)]

//! basic-policy: Policy evaluation without a runtime.
//!
//! Demonstrates: PolicyEngine construction, policy evaluation with
//! allow/deny/approval-required outcomes, rule matching via glob patterns.
//!
//! Setup:  None (pure logic, no filesystem).
//! Cleanup: None.
//! Expected: All 6 checks PASS.

use kavach_core::decision::DecisionEffect;
use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use kavach_policy::engine::PolicyEngine;
use kavach_policy::{DefaultEffect, Effect, Policy, Rule, RuleConditions};

fn main() {
    let mut pass = 0u32;
    let mut total = 0u32;

    // Build policy
    let policy = Policy {
        id: PolicyId::new("demo-policy").unwrap(),
        name: "Demo Policy".into(),
        description: "Example policy for demonstration".into(),
        default_effect: DefaultEffect::Deny,
        rules: vec![
            Rule {
                id: RuleId::new("allow-src-read").unwrap(),
                description: "Allow reading project source files".into(),
                effect: Effect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["src/**".into()]),
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("deny-env").unwrap(),
                description: "Never allow reading .env files".into(),
                effect: Effect::Deny,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["**/.env".into(), "**/.env.*".into()]),
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("require-approval-delete").unwrap(),
                description: "File deletion requires human approval".into(),
                effect: Effect::RequireApproval,
                conditions: RuleConditions {
                    operations: vec!["file_delete".into()],
                    ..Default::default()
                },
            },
        ],
    };

    let engine = PolicyEngine::new(vec![policy]).expect("valid policy");
    let mut ok = true;

    // Test 1: allowed source file read
    total += 1;
    let req = make_req(
        Operation::FileRead {
            max_bytes: Some(4096),
        },
        Resource::file("src/main.rs").unwrap(),
    );
    let d = engine.evaluate(&req);
    if d.effect == DecisionEffect::Allow {
        pass += 1;
        println!("  PASS 1: src/main.rs read ALLOWED (allow-src-read)");
    } else {
        println!("  FAIL 1: got {:?}", d.effect);
        ok = false;
    }

    // Test 2: denied .env read
    total += 1;
    let req = make_req(
        Operation::FileRead {
            max_bytes: Some(4096),
        },
        Resource::file(".env").unwrap(),
    );
    let d = engine.evaluate(&req);
    if d.effect == DecisionEffect::Deny {
        pass += 1;
        println!("  PASS 2: .env read DENIED (deny-env)");
    } else {
        println!("  FAIL 2: got {:?}", d.effect);
        ok = false;
    }

    // Test 3: denied .env.production read
    total += 1;
    let req = make_req(
        Operation::FileRead {
            max_bytes: Some(4096),
        },
        Resource::file(".env.production").unwrap(),
    );
    let d = engine.evaluate(&req);
    if d.effect == DecisionEffect::Deny {
        pass += 1;
        println!("  PASS 3: .env.production DENIED (deny-env glob)");
    } else {
        println!("  FAIL 3: got {:?}", d.effect);
        ok = false;
    }

    // Test 4: non-matching path hits default deny
    total += 1;
    let req = make_req(
        Operation::FileRead {
            max_bytes: Some(4096),
        },
        Resource::file("target/debug/binary").unwrap(),
    );
    let d = engine.evaluate(&req);
    if d.effect == DecisionEffect::Deny {
        pass += 1;
        println!("  PASS 4: target/debug/binary DENIED (default deny)");
    } else {
        println!("  FAIL 4: got {:?}", d.effect);
        ok = false;
    }

    // Test 5: file delete requires approval
    total += 1;
    let req = make_req(Operation::FileDelete, Resource::file("test.txt").unwrap());
    let d = engine.evaluate(&req);
    if d.effect == DecisionEffect::RequireApproval {
        pass += 1;
        println!("  PASS 5: file delete REQUIRES APPROVAL");
    } else {
        println!("  FAIL 5: got {:?}", d.effect);
        ok = false;
    }

    // Test 6: command execution default deny
    total += 1;
    let cmd_res =
        kavach_core::resource::CommandResource::new("echo", vec!["hello".into()]).unwrap();
    let req = make_req(Operation::CommandExecute, Resource::Command(cmd_res));
    let d = engine.evaluate(&req);
    if d.effect == DecisionEffect::Deny {
        pass += 1;
        println!("  PASS 6: echo hello DENIED (no explicit allow for commands)");
    } else {
        println!("  FAIL 6: got {:?}", d.effect);
        ok = false;
    }

    println!();
    if ok {
        println!("RESULT: basic-policy PASSED ({}/{})", pass, total);
        std::process::exit(0);
    } else {
        println!("RESULT: basic-policy FAILED ({}/{})", pass, total);
        std::process::exit(1);
    }
}

fn make_req(operation: Operation, resource: Resource) -> ToolRequest {
    ToolRequest::new(
        RequestId::new("demo-req").unwrap(),
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
