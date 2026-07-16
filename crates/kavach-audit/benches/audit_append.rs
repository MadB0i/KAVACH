#![allow(clippy::unwrap_used, clippy::print_stdout, missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_audit::AuditStoreBuilder;
use kavach_audit::event::{AuditAppendInput, AuditEventCategory};
use std::collections::BTreeMap;

fn setup_store(count: u64) -> kavach_audit::AuditStore {
    let store = AuditStoreBuilder::new().open_in_memory().unwrap();
    for i in 0..count {
        store
            .append(AuditAppendInput {
                category: AuditEventCategory::DecisionAllow,
                request_id: Some(format!("bench-{}", i)),
                agent_id: None,
                operation: Some("bench".into()),
                resource_kind: None,
                resource_summary: Some(format!("benchmark event {}", i)),
                decision: Some("allow".into()),
                reason_code: None,
                matched_rule_ids: vec![],
                metadata: BTreeMap::new(),
            })
            .unwrap();
    }
    store
}

fn bench_audit(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit");
    group.bench_function("append_single", |b| {
        let store = AuditStoreBuilder::new().open_in_memory().unwrap();
        let input = AuditAppendInput {
            category: AuditEventCategory::DecisionAllow,
            request_id: Some("bench-req".into()),
            agent_id: None,
            operation: Some("file_read".into()),
            resource_kind: None,
            resource_summary: Some("benchmark".into()),
            decision: Some("allow".into()),
            reason_code: None,
            matched_rule_ids: vec![],
            metadata: BTreeMap::new(),
        };
        b.iter(|| store.append(black_box(input.clone())));
    });
    group.bench_function("batch_10_appends", |b| {
        b.iter(|| {
            let store = AuditStoreBuilder::new().open_in_memory().unwrap();
            for i in 0..10 {
                store
                    .append(AuditAppendInput {
                        category: if i % 2 == 0 {
                            AuditEventCategory::DecisionAllow
                        } else {
                            AuditEventCategory::DecisionDeny
                        },
                        request_id: Some(format!("req-{}", i)),
                        agent_id: None,
                        operation: Some("test".into()),
                        resource_kind: None,
                        resource_summary: Some(format!("event {}", i)),
                        decision: Some("allow".into()),
                        reason_code: None,
                        matched_rule_ids: vec![],
                        metadata: BTreeMap::new(),
                    })
                    .unwrap();
            }
        });
    });
    group.bench_function("verify_10_events", |b| {
        let store = setup_store(10);
        b.iter(|| store.verify_full());
    });
    group.bench_function("verify_100_events", |b| {
        let store = setup_store(100);
        b.iter(|| store.verify_full());
    });
    group.finish();
}

criterion_group!(benches, bench_audit);
criterion_main!(benches);
