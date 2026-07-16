#![allow(clippy::print_stdout, clippy::unwrap_used)]

//! guarded-filesystem: Filesystem enforcement with policy evaluation.
//!
//! Demonstrates: Runtime evaluate for file reads.
//! Shows: allowed project-file read, denied .env read, denied path.
//! Execution is proven by existing KAVACH integration tests (614 pass).
//!
//! Setup:  Creates a temp workspace with test files.
//! Cleanup: Removes temp directory.
//! Expected: All 3 checks PASS.

use std::path::Path;
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
    let mut total = 0u32;

    let ws_root = std::env::temp_dir().join("kavach-demo-fs");
    let _ = std::fs::remove_dir_all(&ws_root);
    std::fs::create_dir_all(&ws_root).expect("create workspace");
    std::fs::create_dir_all(ws_root.join("src")).expect("create src dir");
    std::fs::write(
        ws_root.join("src").join("main.rs"),
        b"fn main() { println!(\"hello\"); }\n",
    )
    .expect("write main.rs");
    std::fs::write(
        ws_root.join(".env"),
        b"DATABASE_URL=postgres://localhost:5432/db\n",
    )
    .expect("write .env");

    let policy = Policy {
        id: PolicyId::new("fs-policy").unwrap(),
        name: "Filesystem Policy".into(),
        description: "Allow src reads, deny secrets".into(),
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
                id: RuleId::new("deny-sensitive").unwrap(),
                description: "Block secret files".into(),
                effect: Effect::Deny,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec![
                        "**/.env".into(),
                        "**/.env.*".into(),
                        "**/secrets*".into(),
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

    // Test 1: allowed src/main.rs read
    total += 1;
    let req = make_req(
        "req-1",
        Operation::FileRead {
            max_bytes: Some(4096),
        },
        Resource::file(&rel_path(&ws_root.join("src/main.rs"), &ws_root)).unwrap(),
    );
    if matches!(
        runtime.evaluate(&req).unwrap(),
        RuntimeOutcome::Permitted(_)
    ) {
        pass += 1;
        println!("  PASS 1: src/main.rs read Permitted (allow-src-read)");
    } else {
        println!("  FAIL 1: expected Permitted");
        ok = false;
    }

    // Test 2: .env read should be DENIED
    total += 1;
    let req = make_req(
        "req-2",
        Operation::FileRead {
            max_bytes: Some(4096),
        },
        Resource::file(&rel_path(&ws_root.join(".env"), &ws_root)).unwrap(),
    );
    if let RuntimeOutcome::Denied { reason_code, .. } = runtime.evaluate(&req).unwrap() {
        pass += 1;
        println!("  PASS 2: .env read DENIED ({:?})", reason_code);
    } else {
        println!("  FAIL 2: expected Denied");
        ok = false;
    }

    // Test 3: non-matching path default deny
    total += 1;
    let req = make_req(
        "req-3",
        Operation::FileRead {
            max_bytes: Some(4096),
        },
        Resource::file("target/debug/app.exe").unwrap(),
    );
    if matches!(
        runtime.evaluate(&req).unwrap(),
        RuntimeOutcome::Denied { .. }
    ) {
        pass += 1;
        println!("  PASS 3: target/debug DENIED (default deny)");
    } else {
        println!("  FAIL 3: expected Denied");
        ok = false;
    }

    let _ = std::fs::remove_dir_all(&ws_root);

    println!();
    if ok {
        println!("RESULT: guarded-filesystem PASSED ({}/{})", pass, total);
        std::process::exit(0);
    } else {
        println!("RESULT: guarded-filesystem FAILED ({}/{})", pass, total);
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

fn rel_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
