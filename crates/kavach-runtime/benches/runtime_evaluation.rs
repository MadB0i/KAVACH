#![allow(clippy::unwrap_used, clippy::print_stdout, missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use kavach_policy::{DefaultEffect, Effect, Policy, Rule, RuleConditions};
use kavach_runtime::config::RuntimeConfig;
use kavach_runtime::runtime::{KavachRuntime, RuntimeBuilder};
use std::sync::Arc;
use std::time::Duration;

fn build_runtime() -> KavachRuntime {
    let policy = Policy {
        id: PolicyId::new("bench-pol").unwrap(),
        name: "bench".into(),
        description: String::new(),
        default_effect: DefaultEffect::Deny,
        rules: vec![Rule {
            id: RuleId::new("allow-read").unwrap(),
            description: String::new(),
            effect: Effect::Allow,
            conditions: RuleConditions {
                operations: vec!["file_read".into()],
                ..Default::default()
            },
        }],
    };
    let ws = std::env::temp_dir().join("kavach-bench-runtime");
    let _ = std::fs::create_dir_all(&ws);
    RuntimeBuilder::new()
        .with_config(RuntimeConfig {
            permit_ttl: Duration::from_secs(300),
            ..Default::default()
        })
        .with_workspace_root(ws)
        .add_policy(policy)
        .build()
        .unwrap()
}

fn bench_runtime_evaluation(c: &mut Criterion) {
    let runtime = Arc::new(build_runtime());
    let req = ToolRequest::new(
        RequestId::new("bench-req").unwrap(),
        AgentSubjectBuilder::new(
            AgentId::new("bench-agent").unwrap(),
            SessionId::new("bench-sess").unwrap(),
        )
        .trust_level(TrustLevel::Standard)
        .build(),
        Operation::FileRead { max_bytes: None },
        Resource::file("/workspace/data/file.txt").unwrap(),
        RequestContext::new(None, None, None, None, false).unwrap(),
    );
    c.bench_function("runtime_evaluate", |b| {
        b.iter(|| {
            let _ = black_box(runtime.evaluate(black_box(&req)).unwrap());
        });
    });
}

criterion_group!(benches, bench_runtime_evaluation);
criterion_main!(benches);
