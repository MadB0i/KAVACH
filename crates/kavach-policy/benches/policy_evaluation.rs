#![allow(clippy::unwrap_used, clippy::print_stdout, missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use kavach_policy::engine::PolicyEngine;
use kavach_policy::{DefaultEffect, Effect, Policy, Rule, RuleConditions};

fn build_policy(rule_count: usize) -> Policy {
    let mut rules = Vec::with_capacity(rule_count);
    for i in 0..rule_count {
        rules.push(Rule {
            id: RuleId::new(format!("rule-{}", i)).unwrap(),
            description: String::new(),
            effect: if i % 3 == 0 {
                Effect::Allow
            } else if i % 3 == 1 {
                Effect::Deny
            } else {
                Effect::RequireApproval
            },
            conditions: RuleConditions {
                operations: if i % 2 == 0 {
                    vec!["file_read".into()]
                } else {
                    vec!["command_execute".into()]
                },
                path_globs: Some(vec![format!("/path/{}/*", i)]),
                ..Default::default()
            },
        });
    }
    Policy {
        id: PolicyId::new("bench-pol").unwrap(),
        name: "bench".into(),
        description: String::new(),
        default_effect: DefaultEffect::Deny,
        rules,
    }
}

fn make_request() -> ToolRequest {
    ToolRequest::new(
        RequestId::new("bench-req").unwrap(),
        AgentSubjectBuilder::new(
            AgentId::new("bench-agent").unwrap(),
            SessionId::new("bench-sess").unwrap(),
        )
        .trust_level(TrustLevel::Standard)
        .build(),
        Operation::FileRead { max_bytes: None },
        Resource::file("/path/5/data.txt").unwrap(),
        RequestContext::new(None, None, None, None, false).unwrap(),
    )
}

fn bench_policy_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_evaluation");
    for &rules in &[1usize, 10, 50, 100] {
        let policy = build_policy(rules);
        let engine = PolicyEngine::new(vec![policy]).unwrap();
        let req = make_request();
        group.bench_function(format!("{}_rules", rules), |b| {
            b.iter(|| engine.evaluate(black_box(&req)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_policy_evaluation);
criterion_main!(benches);
