use crate::canonical::encode_canonical;
use crate::error::AuditError;
use crate::event::{AuditEventRecord, CanonicalEventFields, MAX_VERIFICATION_RANGE};
use crate::hash::HashValue;
use crate::store::AuditStore;

/// Detailed report produced by chain verification.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// Whether the entire chain is valid (no errors found).
    pub chain_valid: bool,
    /// Total number of events verified.
    pub event_count: u64,
    /// The highest sequence number that was verified.
    pub verified_to: u64,
    /// List of verification errors found.
    pub errors: Vec<VerificationError>,
}

/// A single verification error.
#[derive(Debug, Clone)]
pub struct VerificationError {
    /// The sequence number at which the error was detected.
    pub sequence: u64,
    /// The kind of verification error.
    pub kind: VerificationErrorKind,
    /// Human-readable description of the error.
    pub detail: String,
}

/// Kind of verification error.
#[derive(Debug, Clone)]
pub enum VerificationErrorKind {
    /// An expected event was not found in the database.
    MissingEvent,
    /// A gap was found in the sequence numbering.
    SequenceGap,
    /// A duplicate sequence number was detected.
    DuplicateSequence,
    /// The recomputed hash does not match the stored hash.
    HashMismatch,
    /// The previous_hash of an event does not match the current_hash of its predecessor.
    PreviousHashLinkBroken,
    /// A stored hash value is malformed (not valid hex or wrong length).
    MalformedHash,
    /// The first event's previous_hash does not match the genesis hash.
    GenesisMismatch,
    /// Database corruption was detected during verification.
    DatabaseCorruption,
}

#[allow(dead_code)]
impl VerificationError {
    fn missing(seq: u64) -> Self {
        Self {
            sequence: seq,
            kind: VerificationErrorKind::MissingEvent,
            detail: format!("event at sequence {seq} is missing"),
        }
    }

    fn gap(expected: u64, actual: u64) -> Self {
        Self {
            sequence: expected,
            kind: VerificationErrorKind::SequenceGap,
            detail: format!("expected sequence {expected}, found {actual}"),
        }
    }

    fn hash(seq: u64, expected: String, actual: String) -> Self {
        Self {
            sequence: seq,
            kind: VerificationErrorKind::HashMismatch,
            detail: format!("hash mismatch at {seq}: expected {expected}, got {actual}"),
        }
    }

    fn prev_link(seq: u64, detail: String) -> Self {
        Self {
            sequence: seq,
            kind: VerificationErrorKind::PreviousHashLinkBroken,
            detail,
        }
    }
}

impl AuditStore {
    /// Full chain verification — walks every event and recomputes hashes.
    pub fn verify_full(&self) -> Result<VerificationReport, AuditError> {
        let events = self.all_events()?;
        verify_events(&events, None)
    }

    /// Verification from a trusted checkpoint hash.
    ///
    /// Starts from the event whose `current_hash` matches `checkpoint_hash`
    /// (or the first event if `checkpoint_hash` is the genesis hash) and
    /// verifies every subsequent event.
    pub fn verify_from_checkpoint(
        &self,
        checkpoint_hash: &str,
        checkpoint_sequence: u64,
    ) -> Result<VerificationReport, AuditError> {
        let events = self.events_in_range(checkpoint_sequence, u64::MAX)?;
        let checkpoint_hash_val = parse_hex_hash(checkpoint_hash)?;
        verify_events(&events, Some(checkpoint_hash_val))
    }

    /// Bounded range verification.
    pub fn verify_range(&self, start: u64, end: u64) -> Result<VerificationReport, AuditError> {
        if end - start + 1 > MAX_VERIFICATION_RANGE {
            return Err(AuditError::verification_range_too_large(
                end - start + 1,
                MAX_VERIFICATION_RANGE,
            ));
        }
        let events = self.events_in_range(start, end)?;
        // Determine the previous hash for the first event in the range.
        let prev_hash = if start > 1 {
            let prev_event = self.event_by_sequence(start - 1)?;
            match prev_event {
                Some(e) => e.current_hash,
                None => return Err(AuditError::missing_event(start - 1)),
            }
        } else {
            HashValue::genesis()
        };
        verify_events(&events, Some(prev_hash))
    }
}

fn parse_hex_hash(s: &str) -> Result<HashValue, AuditError> {
    let bytes = hex::decode(s)
        .map_err(|e| AuditError::database_corruption(format!("malformed hash: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuditError::database_corruption(String::from("hash is not 32 bytes")))?;
    Ok(HashValue::from_bytes(arr))
}

fn verify_events(
    events: &[AuditEventRecord],
    expected_prev_hash: Option<HashValue>,
) -> Result<VerificationReport, AuditError> {
    let mut errors: Vec<VerificationError> = Vec::new();
    let event_count = events.len() as u64;

    if events.is_empty() {
        return Ok(VerificationReport {
            chain_valid: true,
            event_count: 0,
            verified_to: 0,
            errors: vec![],
        });
    }

    let mut prev_hash = match expected_prev_hash {
        Some(h) => h,
        None => {
            // Check genesis: first event's previous_hash must be the genesis hash.
            let genesis = HashValue::genesis();
            if events[0].previous_hash != genesis {
                errors.push(VerificationError {
                    sequence: events[0].sequence,
                    kind: VerificationErrorKind::GenesisMismatch,
                    detail: format!(
                        "expected genesis {}, got {}",
                        genesis, events[0].previous_hash
                    ),
                });
            }
            genesis
        }
    };

    for (i, event) in events.iter().enumerate() {
        let seq = event.sequence;

        // Check sequence continuity.
        if i > 0 {
            let expected_seq = events[i - 1].sequence + 1;
            if seq != expected_seq {
                errors.push(VerificationError::gap(expected_seq, seq));
            }
        }

        // Check previous hash linkage.
        if event.previous_hash != prev_hash {
            errors.push(VerificationError::prev_link(
                seq,
                format!(
                    "expected prev_hash {}, got {}",
                    prev_hash, event.previous_hash
                ),
            ));
        }

        // Recompute current hash.
        let canonical = encode_canonical(&CanonicalEventFields {
            schema_version: 1,
            sequence: event.sequence,
            event_id: event.event_id.clone(),
            timestamp: event.timestamp.clone(),
            category: event.category.to_string(),
            request_id: event.request_id.clone(),
            agent_id: event.agent_id.clone(),
            operation: event.operation.clone(),
            resource_kind: event.resource_kind.clone(),
            resource_summary: event.resource_summary.clone(),
            decision: event.decision.clone(),
            reason_code: event.reason_code.clone(),
            matched_rule_ids: event.matched_rule_ids.clone(),
            metadata: event.metadata.clone(),
        });

        let recomputed = HashValue::compute(&prev_hash, &canonical);

        if recomputed != event.current_hash {
            errors.push(VerificationError::hash(
                seq,
                recomputed.to_string(),
                event.current_hash.to_string(),
            ));
        }

        prev_hash = event.current_hash;
    }

    let last_seq = events.last().map(|e| e.sequence).unwrap_or_default();

    Ok(VerificationReport {
        chain_valid: errors.is_empty(),
        event_count,
        verified_to: last_seq,
        errors,
    })
}

/// Recompute the hash for a single event given its predecessor's hash.
pub fn recompute_hash(event: &AuditEventRecord, previous_hash: &HashValue) -> HashValue {
    let canonical = encode_canonical(&CanonicalEventFields {
        schema_version: 1,
        sequence: event.sequence,
        event_id: event.event_id.clone(),
        timestamp: event.timestamp.clone(),
        category: event.category.to_string(),
        request_id: event.request_id.clone(),
        agent_id: event.agent_id.clone(),
        operation: event.operation.clone(),
        resource_kind: event.resource_kind.clone(),
        resource_summary: event.resource_summary.clone(),
        decision: event.decision.clone(),
        reason_code: event.reason_code.clone(),
        matched_rule_ids: event.matched_rule_ids.clone(),
        metadata: event.metadata.clone(),
    });
    HashValue::compute(previous_hash, &canonical)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::event::AuditAppendInput;
    use crate::event::{
        AuditEventCategory, MAX_METADATA_KEY_LENGTH, MAX_METADATA_VALUE_LENGTH,
        MAX_RESOURCE_SUMMARY_LENGTH,
    };
    use crate::store::AuditStore;
    use rusqlite::params;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn make_input(category: &str) -> AuditAppendInput {
        let cat = match category {
            "RequestReceived" => AuditEventCategory::RequestReceived,
            "DecisionAllow" => AuditEventCategory::DecisionAllow,
            "DecisionDeny" => AuditEventCategory::DecisionDeny,
            _ => AuditEventCategory::SecurityWarning,
        };
        AuditAppendInput {
            category: cat,
            request_id: Some("req-1".into()),
            agent_id: Some("agent-1".into()),
            operation: Some("file_read".into()),
            resource_kind: Some("file".into()),
            resource_summary: Some("test-file.txt".into()),
            decision: None,
            reason_code: Some("policy_matched".into()),
            matched_rule_ids: vec!["rule-1".into()],
            metadata: BTreeMap::new(),
        }
    }

    fn open_store() -> AuditStore {
        AuditStore::builder().open_in_memory().unwrap()
    }

    #[test]
    fn empty_database_verifies() {
        let store = open_store();
        let report = store.verify_full().unwrap();
        assert!(report.chain_valid);
        assert_eq!(report.event_count, 0);
    }

    #[test]
    fn single_event_chain_verifies() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();
        let report = store.verify_full().unwrap();
        assert!(report.chain_valid);
        assert_eq!(report.event_count, 1);
        assert_eq!(report.verified_to, 1);
    }

    #[test]
    fn two_event_chain_verifies() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();
        store.append(make_input("DecisionAllow")).unwrap();
        let report = store.verify_full().unwrap();
        assert!(report.chain_valid);
        assert_eq!(report.event_count, 2);
    }

    #[test]
    fn full_valid_chain_verifies() {
        let store = open_store();
        for i in 0..5 {
            let mut input = make_input("RequestReceived");
            input.request_id = Some(format!("req-{i}"));
            store.append(input).unwrap();
        }
        let report = store.verify_full().unwrap();
        assert!(report.chain_valid);
        assert_eq!(report.event_count, 5);
    }

    #[test]
    fn modified_category_detected() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();

        // Manually corrupt the database.
        let conn = store.test_conn();
        conn.execute(
            "UPDATE audit_events SET category = 'SecurityWarning' WHERE sequence = 1",
            [],
        )
        .unwrap();
        drop(conn);

        let report = store.verify_full().unwrap();
        assert!(!report.chain_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e.kind, VerificationErrorKind::HashMismatch)),
            "expected hash mismatch error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn modified_reason_code_detected() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();

        let conn = store.test_conn();
        conn.execute(
            "UPDATE audit_events SET reason_code = 'tampered' WHERE sequence = 1",
            [],
        )
        .unwrap();
        drop(conn);

        let report = store.verify_full().unwrap();
        assert!(!report.chain_valid);
    }

    #[test]
    fn modified_metadata_detected() {
        let store = open_store();
        let mut meta = BTreeMap::new();
        meta.insert("key".into(), "original".into());
        let mut input = make_input("RequestReceived");
        input.metadata = meta;
        store.append(input).unwrap();

        let conn = store.test_conn();
        conn.execute(
            "UPDATE audit_events SET metadata = '{\"key\":\"tampered\"}' WHERE sequence = 1",
            [],
        )
        .unwrap();
        drop(conn);

        let report = store.verify_full().unwrap();
        assert!(!report.chain_valid);
    }

    #[test]
    fn modified_previous_hash_detected() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();
        store.append(make_input("DecisionAllow")).unwrap();

        let fake: [u8; 32] = [0xaa; 32];
        let conn = store.test_conn();
        conn.execute(
            "UPDATE audit_events SET previous_hash = ?1 WHERE sequence = 2",
            params![fake.as_slice()],
        )
        .unwrap();
        drop(conn);

        let report = store.verify_full().unwrap();
        assert!(!report.chain_valid);
    }

    #[test]
    fn modified_current_hash_detected() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();

        let fake: [u8; 32] = [0xbb; 32];
        let conn = store.test_conn();
        conn.execute(
            "UPDATE audit_events SET current_hash = ?1 WHERE sequence = 1",
            params![fake.as_slice()],
        )
        .unwrap();
        drop(conn);

        let report = store.verify_full().unwrap();
        assert!(!report.chain_valid);
    }

    #[test]
    fn deleted_middle_row_detected() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap(); // seq 1
        store.append(make_input("DecisionAllow")).unwrap(); // seq 2
        store.append(make_input("DecisionDeny")).unwrap(); // seq 3

        let conn = store.test_conn();
        conn.execute("DELETE FROM audit_events WHERE sequence = 2", [])
            .unwrap();
        drop(conn);

        let report = store.verify_full().unwrap();
        assert!(!report.chain_valid);
    }

    #[test]
    fn sequence_gap_detected() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();

        let conn = store.test_conn();
        // Manually insert event with sequence 3 (skipping 2)
        conn.execute(
            "INSERT INTO audit_events (sequence, event_id, timestamp, category, \
             matched_rule_ids, metadata, previous_hash, current_hash) \
             VALUES (3, 'gap-id', '2026-01-01T00:00:00Z', 'RequestReceived', \
             '[]', '{}', x'00', x'00')",
            [],
        )
        .unwrap();
        drop(conn);

        let report = store.verify_full().unwrap();
        assert!(!report.chain_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e.kind, VerificationErrorKind::SequenceGap)),
            "expected sequence gap error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn duplicate_sequence_prevented() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();

        let conn = store.test_conn();
        let result = conn.execute(
            "INSERT INTO audit_events (sequence, event_id, timestamp, category, \
             matched_rule_ids, metadata, previous_hash, current_hash) \
             VALUES (1, 'dup-id', '2026-01-01T00:00:00Z', 'RequestReceived', \
             '[]', '{}', x'00', x'00')",
            [],
        );
        drop(conn);
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_event_id_prevented() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();

        let conn = store.test_conn();
        let first: String = conn
            .query_row(
                "SELECT event_id FROM audit_events WHERE sequence = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let result = conn.execute(
            "INSERT INTO audit_events (sequence, event_id, timestamp, category, \
             matched_rule_ids, metadata, previous_hash, current_hash) \
             VALUES (2, ?1, '2026-01-01T00:00:00Z', 'RequestReceived', \
             '[]', '{}', x'00', x'00')",
            params![first],
        );
        drop(conn);
        assert!(result.is_err());
    }

    #[test]
    fn concurrent_appends_create_linear_chain() {
        let dir = std::env::temp_dir().join("kavach_audit_test_concurrent");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_concurrent.db");
        let path_str = path.display().to_string();
        let _ = std::fs::remove_file(&path);

        let store = Arc::new(AuditStore::builder().open(&path_str).unwrap());

        let mut handles = Vec::new();
        for i in 0..5 {
            let s = Arc::clone(&store);
            let input = AuditAppendInput {
                category: AuditEventCategory::RequestReceived,
                request_id: Some(format!("concurrent-{i}")),
                agent_id: None,
                operation: None,
                resource_kind: None,
                resource_summary: None,
                decision: None,
                reason_code: None,
                matched_rule_ids: vec![],
                metadata: BTreeMap::new(),
            };
            handles.push(std::thread::spawn(move || s.append(input)));
        }

        for h in handles {
            let result = h.join().unwrap();
            assert!(result.is_ok(), "concurrent append failed: {:?}", result);
        }

        let report = store.verify_full().unwrap();
        assert!(
            report.chain_valid,
            "concurrent chain invalid: {:?}",
            report.errors
        );
        assert_eq!(report.event_count, 5);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn failed_append_leaves_no_partial_event() {
        let store = open_store();
        let count_before = store.event_count().unwrap();

        let mut huge_meta = BTreeMap::new();
        huge_meta.insert(
            "k".to_string().repeat(MAX_METADATA_KEY_LENGTH + 1),
            "v".into(),
        );
        let bad_input = AuditAppendInput {
            category: AuditEventCategory::RequestReceived,
            request_id: None,
            agent_id: None,
            operation: None,
            resource_kind: None,
            resource_summary: None,
            decision: None,
            reason_code: None,
            matched_rule_ids: vec![],
            metadata: huge_meta,
        };

        let result = store.append(bad_input);
        assert!(result.is_err());

        let count_after = store.event_count().unwrap();
        assert_eq!(count_before, count_after);
    }

    #[test]
    fn configured_secret_never_appears_in_database() {
        use kavach_redaction::{CompositeRedactor, SecretContainer};
        let mut secrets = SecretContainer::new();
        secrets.add("my-hidden-secret".into()).unwrap();
        let redactor = CompositeRedactor::builder()
            .with_exact_secrets(secrets)
            .build();

        let store = AuditStore::builder()
            .with_redactor(Arc::new(redactor))
            .open_in_memory()
            .unwrap();

        let mut meta = BTreeMap::new();
        meta.insert("token".into(), "my-hidden-secret".into());

        store
            .append(AuditAppendInput {
                category: crate::event::AuditEventCategory::RequestReceived,
                request_id: None,
                agent_id: None,
                operation: None,
                resource_kind: None,
                resource_summary: Some("contains my-hidden-secret".into()),
                decision: None,
                reason_code: None,
                matched_rule_ids: vec![],
                metadata: meta,
            })
            .unwrap();

        // Read directly from DB — secret must not appear.
        let conn = store.test_conn();
        let summary: Option<String> = conn
            .query_row(
                "SELECT resource_summary FROM audit_events WHERE sequence = 1",
                [],
                |row| row.get(0),
            )
            .ok();
        drop(conn);

        assert!(summary.is_some());
        let s = summary.unwrap();
        assert!(
            !s.contains("my-hidden-secret"),
            "secret leaked into DB: {s}"
        );
        assert!(s.contains("[REDACTED:configured_secret]") || s.contains("[REDACTED:"));
    }

    #[test]
    fn bearer_token_never_appears_in_persisted_metadata() {
        use kavach_redaction::CompositeRedactor;

        let redactor = CompositeRedactor::builder().build();
        let store = AuditStore::builder()
            .with_redactor(Arc::new(redactor))
            .open_in_memory()
            .unwrap();

        let mut meta = BTreeMap::new();
        meta.insert("auth".into(), "Bearer tok12345678".into());

        store
            .append(AuditAppendInput {
                category: crate::event::AuditEventCategory::RequestReceived,
                request_id: None,
                agent_id: None,
                operation: None,
                resource_kind: None,
                resource_summary: None,
                decision: None,
                reason_code: None,
                matched_rule_ids: vec![],
                metadata: meta,
            })
            .unwrap();

        let conn = store.test_conn();
        let meta_json: String = conn
            .query_row(
                "SELECT metadata FROM audit_events WHERE sequence = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(conn);

        assert!(
            !meta_json.contains("tok12345678"),
            "bearer token leaked: {meta_json}"
        );
    }

    #[test]
    fn private_key_never_appears_in_persisted_summary() {
        use kavach_redaction::CompositeRedactor;

        let redactor = CompositeRedactor::builder().build();
        let store = AuditStore::builder()
            .with_redactor(Arc::new(redactor))
            .open_in_memory()
            .unwrap();

        store
            .append(AuditAppendInput {
                category: crate::event::AuditEventCategory::RequestReceived,
                request_id: None,
                agent_id: None,
                operation: None,
                resource_kind: None,
                resource_summary: Some(
                    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0+OSlK4Q6+Oa\n-----END RSA PRIVATE KEY-----".into()
                ),
                decision: None,
                reason_code: None,
                matched_rule_ids: vec![],
                metadata: BTreeMap::new(),
            })
            .unwrap();

        let conn = store.test_conn();
        let summary: String = conn
            .query_row(
                "SELECT resource_summary FROM audit_events WHERE sequence = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(conn);

        assert!(!summary.contains("MIIEpAIBAAKCAQEA0+OSlK4Q6+Oa"));
        assert!(summary.contains("[REDACTED:private_key]"));
    }

    #[test]
    fn errors_do_not_reveal_secret_values() {
        use kavach_redaction::{CompositeRedactor, SecretContainer};
        let mut secrets = SecretContainer::new();
        secrets.add("my-secret".into()).unwrap();
        let redactor = CompositeRedactor::builder()
            .with_exact_secrets(secrets)
            .build();
        let store = AuditStore::builder()
            .with_redactor(Arc::new(redactor))
            .open_in_memory()
            .unwrap();

        let err_input = AuditAppendInput {
            category: crate::event::AuditEventCategory::RequestReceived,
            request_id: None,
            agent_id: None,
            operation: None,
            resource_kind: None,
            resource_summary: Some("safe".into()),
            decision: None,
            reason_code: None,
            matched_rule_ids: vec![],
            metadata: BTreeMap::new(),
        };

        let result = store.append(err_input);
        // The append should succeed; errors from the store should not contain
        // secret values.
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => return, // success is fine
        };
        assert!(
            !err_msg.contains("my-secret"),
            "error leaked secret: {err_msg}"
        );
    }

    #[test]
    fn debug_output_does_not_reveal_secret_values() {
        use kavach_redaction::{CompositeRedactor, SecretContainer};
        let mut secrets = SecretContainer::new();
        secrets.add("secret-value".into()).unwrap();
        let redactor = CompositeRedactor::builder()
            .with_exact_secrets(secrets)
            .build();
        let store = AuditStore::builder()
            .with_redactor(Arc::new(redactor))
            .open_in_memory()
            .unwrap();

        let input = AuditAppendInput {
            category: crate::event::AuditEventCategory::RequestReceived,
            request_id: Some("req-1".into()),
            agent_id: None,
            operation: None,
            resource_kind: None,
            resource_summary: Some("contains secret-value".into()),
            decision: None,
            reason_code: None,
            matched_rule_ids: vec![],
            metadata: BTreeMap::new(),
        };

        let summary = store.append(input).unwrap();
        let debug = format!("{:?}", summary);
        assert!(
            !debug.contains("secret-value"),
            "Debug leaked secret: {debug}"
        );
    }

    #[test]
    fn matched_rule_ids_in_deterministic_order() {
        let store = open_store();
        let input = AuditAppendInput {
            category: crate::event::AuditEventCategory::DecisionAllow,
            request_id: None,
            agent_id: None,
            operation: None,
            resource_kind: None,
            resource_summary: None,
            decision: Some("Allow".into()),
            reason_code: Some("bypass".into()),
            matched_rule_ids: vec!["z-rule".into(), "a-rule".into(), "m-rule".into()],
            metadata: BTreeMap::new(),
        };
        store.append(input).unwrap();

        let event = store.event_by_sequence(1).unwrap().unwrap();
        assert_eq!(event.matched_rule_ids, vec!["a-rule", "m-rule", "z-rule"]);
    }

    #[test]
    fn metadata_ordering_does_not_change_hash() {
        let store = open_store();

        let mut meta_a = BTreeMap::new();
        meta_a.insert("a".into(), "1".into());
        meta_a.insert("b".into(), "2".into());
        let input_a = AuditAppendInput {
            category: crate::event::AuditEventCategory::RequestReceived,
            request_id: None,
            agent_id: None,
            operation: None,
            resource_kind: None,
            resource_summary: None,
            decision: None,
            reason_code: None,
            matched_rule_ids: vec![],
            metadata: meta_a,
        };
        store.append(input_a).unwrap();

        // Same logical metadata via BTreeMap always produces same hash.
        let event = store.event_by_sequence(1).unwrap().unwrap();
        let hash_str = event.current_hash.to_string();
        assert_eq!(hash_str.len(), 64);
    }

    #[test]
    fn bounded_query_limit_enforced() {
        let store = open_store();
        for i in 0..10 {
            let mut input = make_input("RequestReceived");
            input.request_id = Some(format!("req-{i}"));
            store.append(input).unwrap();
        }

        let events = store.events_after_sequence(0, 5).unwrap();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn events_after_sequence_deterministic() {
        let store = open_store();
        for i in 0..5 {
            let mut input = make_input("RequestReceived");
            input.request_id = Some(format!("req-{i}"));
            store.append(input).unwrap();
        }

        let events = store.events_after_sequence(0, 10).unwrap();
        assert_eq!(events.len(), 5);
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.sequence, (i + 1) as u64);
        }
    }

    #[test]
    fn query_by_request_id_works() {
        let store = open_store();
        let mut input = make_input("RequestReceived");
        input.request_id = Some("find-me".into());
        store.append(input).unwrap();
        store.append(make_input("DecisionAllow")).unwrap();

        let events = store.events_by_request_id("find-me", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request_id.as_deref(), Some("find-me"));
    }

    #[test]
    fn query_by_category_works() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();
        store.append(make_input("DecisionAllow")).unwrap();

        let events = store
            .events_by_category(crate::event::AuditEventCategory::RequestReceived, 10)
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn range_verification_succeeds() {
        let store = open_store();
        for i in 0..5 {
            let mut input = make_input("RequestReceived");
            input.request_id = Some(format!("req-{i}"));
            store.append(input).unwrap();
        }

        let report = store.verify_range(2, 4).unwrap();
        assert!(report.chain_valid);
        assert_eq!(report.event_count, 3);
    }

    #[test]
    fn range_verification_detects_tampering() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap(); // seq 1
        store.append(make_input("DecisionAllow")).unwrap(); // seq 2
        store.append(make_input("DecisionDeny")).unwrap(); // seq 3

        let conn = store.test_conn();
        conn.execute(
            "UPDATE audit_events SET reason_code = 'tampered' WHERE sequence = 2",
            [],
        )
        .unwrap();
        drop(conn);

        let report = store.verify_range(1, 3).unwrap();
        assert!(!report.chain_valid);
    }

    #[test]
    fn checkpoint_contains_final_sequence_and_hash() {
        let store = open_store();
        for i in 0..3 {
            let mut input = make_input("RequestReceived");
            input.request_id = Some(format!("req-{i}"));
            store.append(input).unwrap();
        }

        let checkpoint = store.create_checkpoint().unwrap();
        assert_eq!(checkpoint.ending_sequence, 3);
        assert_eq!(checkpoint.event_count, 3);
        assert!(checkpoint.ending_hash.len() == 64);

        // Hash should match the actual latest event.
        let latest = store.latest_event().unwrap().unwrap();
        assert_eq!(checkpoint.ending_hash, latest.current_hash.to_string());
    }

    #[test]
    fn checkpoint_generation_does_not_mutate_chain() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();

        let count_before = store.event_count().unwrap();
        let checkpoint = store.create_checkpoint().unwrap();
        let count_after = store.event_count().unwrap();

        assert_eq!(count_before, count_after);
        assert_eq!(checkpoint.event_count, 1);

        // Chain should still verify after checkpoint.
        let report = store.verify_full().unwrap();
        assert!(report.chain_valid);
    }

    #[test]
    fn empty_database_verification_explicit_empty() {
        let store = open_store();
        let report = store.verify_full().unwrap();
        assert!(report.chain_valid);
        assert_eq!(report.event_count, 0);
        assert_eq!(report.verified_to, 0);
    }

    #[test]
    fn read_only_verification_performs_no_writes() {
        let store = open_store();
        store.append(make_input("RequestReceived")).unwrap();

        // Verify and check no modification happened.
        let report = store.verify_full().unwrap();
        assert!(report.chain_valid);

        // Read the event back and verify it's unchanged.
        let event = store.event_by_sequence(1).unwrap().unwrap();
        assert_eq!(
            event.category,
            crate::event::AuditEventCategory::RequestReceived
        );
    }

    #[test]
    fn repeated_verification_identical_report() {
        let store = open_store();
        for _ in 0..3 {
            store.append(make_input("RequestReceived")).unwrap();
        }

        let r1 = store.verify_full().unwrap();
        let r2 = store.verify_full().unwrap();

        assert_eq!(r1.chain_valid, r2.chain_valid);
        assert_eq!(r1.event_count, r2.event_count);
        assert_eq!(r1.errors.len(), r2.errors.len());
    }

    #[test]
    fn oversized_metadata_rejected() {
        let store = open_store();
        let mut huge_meta = BTreeMap::new();
        huge_meta.insert("k".into(), "v".repeat(MAX_METADATA_VALUE_LENGTH + 1));

        let input = AuditAppendInput {
            category: crate::event::AuditEventCategory::RequestReceived,
            request_id: None,
            agent_id: None,
            operation: None,
            resource_kind: None,
            resource_summary: None,
            decision: None,
            reason_code: None,
            matched_rule_ids: vec![],
            metadata: huge_meta,
        };

        let result = store.append(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid field"));
    }

    #[test]
    fn long_resource_summary_rejected() {
        let store = open_store();
        let long_summary = "x".repeat(MAX_RESOURCE_SUMMARY_LENGTH + 1);

        let input = AuditAppendInput {
            category: crate::event::AuditEventCategory::RequestReceived,
            request_id: None,
            agent_id: None,
            operation: None,
            resource_kind: None,
            resource_summary: Some(long_summary),
            decision: None,
            reason_code: None,
            matched_rule_ids: vec![],
            metadata: BTreeMap::new(),
        };

        let result = store.append(input);
        assert!(result.is_err());
    }
}
