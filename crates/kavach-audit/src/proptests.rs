#![allow(clippy::unwrap_used, unused_imports)]

use crate::AuditStoreBuilder;
use crate::canonical::encode_canonical;
use crate::event::{AuditAppendInput, AuditEventCategory, CanonicalEventFields};
use proptest::prelude::*;
use std::collections::BTreeMap;

proptest! {
    #[test]
    fn canonical_encoding_is_deterministic(
        category in 0u8..7u8,
        req_id in "[a-f0-9-]{1,36}",
        summary in ".{0,50}",
    ) {
        let cat_str = match category % 7 {
            0 => "RequestReceived",
            1 => "DecisionAllow",
            2 => "DecisionDeny",
            3 => "ApprovalRequested",
            4 => "ApprovalApproved",
            5 => "ExecutionStarted",
            _ => "ExecutionSucceeded",
        };

        let fields = CanonicalEventFields {
            schema_version: 1,
            sequence: 1,
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            category: cat_str.to_string(),
            request_id: Some(req_id.clone()),
            agent_id: None,
            operation: Some("test".into()),
            resource_kind: None,
            resource_summary: Some(summary.clone()),
            decision: Some("allow".into()),
            reason_code: None,
            matched_rule_ids: vec![],
            metadata: BTreeMap::new(),
        };

        let enc1 = encode_canonical(&fields);
        let enc2 = encode_canonical(&fields);
        assert_eq!(enc1, enc2, "canonical encoding must be deterministic");
    }

    #[test]
    fn audit_store_append_and_verify(count in 1usize..10usize) {
        let store = AuditStoreBuilder::new().open_in_memory().unwrap();
        for i in 0..count {
            let cat = if i % 2 == 0 { AuditEventCategory::DecisionAllow } else { AuditEventCategory::DecisionDeny };
            store.append(AuditAppendInput {
                category: cat,
                request_id: Some(format!("req-{}", i)),
                agent_id: None,
                operation: Some("test".into()),
                resource_kind: None,
                resource_summary: Some(format!("test event {}", i)),
                decision: if i % 2 == 0 { Some("allow".into()) } else { Some("deny".into()) },
                reason_code: None,
                matched_rule_ids: vec![],
                metadata: BTreeMap::new(),
            }).unwrap();
        }
        let report = store.verify_full().unwrap();
        assert!(report.chain_valid, "chain must be valid after {} appends", count);
        assert_eq!(report.event_count, count as u64);
    }
}
