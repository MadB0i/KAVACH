#![allow(clippy::unwrap_used, clippy::print_stdout, missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use kavach_policy::{DefaultEffect, Effect, Policy, Rule, RuleConditions};
use kavach_runtime::config::RuntimeConfig;
use kavach_runtime::outcome::RuntimeOutcome;
use kavach_runtime::runtime::RuntimeBuilder;
use std::time::Duration;

fn bench_approval_lookup(c: &mut Criterion) {
    let ws = std::env::temp_dir().join("kavach-bench-approval");
    let _ = std::fs::create_dir_all(&ws);
    let audit_path = ws.join("audit.db").to_string_lossy().to_string();
    let approval_path = ws.join("approvals.db").to_string_lossy().to_string();
    let policy = Policy {
        id: PolicyId::new("bench-pol").unwrap(),
        name: "bench".into(),
        description: String::new(),
        default_effect: DefaultEffect::Deny,
        rules: vec![Rule {
            id: RuleId::new("require-approval").unwrap(),
            description: String::new(),
            effect: Effect::RequireApproval,
            conditions: RuleConditions {
                operations: vec!["file_delete".into()],
                ..Default::default()
            },
        }],
    };
    let runtime = RuntimeBuilder::new()
        .with_config(RuntimeConfig {
            permit_ttl: Duration::from_secs(300),
            ..Default::default()
        })
        .with_workspace_root(ws.clone())
        .add_policy(policy)
        .with_audit_db(audit_path)
        .with_approval_db(approval_path)
        .build()
        .unwrap();
    let req = ToolRequest::new(
        RequestId::new("bench-req").unwrap(),
        AgentSubjectBuilder::new(
            AgentId::new("bench-agent").unwrap(),
            SessionId::new("bench-sess").unwrap(),
        )
        .trust_level(TrustLevel::Standard)
        .build(),
        Operation::FileDelete,
        Resource::file("bench-file.txt").unwrap(),
        RequestContext::new(None, None, None, None, false).unwrap(),
    );
    let outcome = runtime.evaluate(&req).unwrap();
    let _aid = match &outcome {
        RuntimeOutcome::ApprovalRequired { approval_id, .. } => approval_id.clone(),
        _ => panic!("expected ApprovalRequired"),
    };
    c.bench_function("list_pending", |b| {
        b.iter(|| {
            let _ = black_box(runtime.broker().list_pending(None));
        })
    });
    c.bench_function("evaluate_delete", |b| {
        b.iter(|| {
            let _ = black_box(runtime.evaluate(black_box(&req)));
        })
    });
}

criterion_group!(benches, bench_approval_lookup);
criterion_main!(benches);
