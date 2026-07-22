#![no_main]

use std::collections::BTreeMap;

use kavach_audit::{AuditAppendInput, AuditEventCategory};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let fields = data
        .split(|byte| *byte == 0)
        .map(|field| String::from_utf8_lossy(field).into_owned())
        .collect::<Vec<_>>();
    let value = |index: usize| fields.get(index).cloned();

    let matched_rule_ids = fields.iter().skip(8).step_by(2).cloned().collect();
    let metadata = fields
        .iter()
        .skip(9)
        .step_by(2)
        .cloned()
        .zip(fields.iter().skip(10).step_by(2).cloned())
        .collect::<BTreeMap<_, _>>();

    let input = AuditAppendInput {
        category: AuditEventCategory::SecurityWarning,
        request_id: value(0),
        agent_id: value(1),
        operation: value(2),
        resource_kind: value(3),
        resource_summary: value(4),
        decision: value(5),
        reason_code: value(6),
        matched_rule_ids,
        metadata,
    };

    let _ = input.validate();
});
