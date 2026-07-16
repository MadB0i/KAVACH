use crate::event::CanonicalEventFields;

/// Produces the deterministic canonical byte representation of an event.
///
/// Field order is explicit and fixed.  Maps are written in key-sorted order.
/// Optional fields that are `None` are omitted.  Empty arrays are written as
/// `[]`.  The hash fields are *not* included — the canonical bytes are what
/// gets hashed together with the previous hash to produce the current hash.
///
/// Format (one field per line, no trailing whitespace):
///
/// ```text
/// schema_version: 1
/// sequence: 1
/// event_id: <uuid>
/// timestamp: 2026-07-16T12:00:00Z
/// category: RequestReceived
/// request_id: <value>       (omitted if None)
/// agent_id: <value>
/// ...
/// matched_rule_ids: ["id1","id2"]
/// metadata:
///   key1: <value>
///   key2: <value>
/// ```
pub(crate) fn encode_canonical(fields: &CanonicalEventFields) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    write_fmt(
        &mut buf,
        "schema_version",
        &fields.schema_version.to_string(),
    );
    write_fmt(&mut buf, "sequence", &fields.sequence.to_string());
    write_fmt(&mut buf, "event_id", &fields.event_id);
    write_fmt(&mut buf, "timestamp", &fields.timestamp);
    write_fmt(&mut buf, "category", &fields.category);

    write_opt(&mut buf, "request_id", &fields.request_id);
    write_opt(&mut buf, "agent_id", &fields.agent_id);
    write_opt(&mut buf, "operation", &fields.operation);
    write_opt(&mut buf, "resource_kind", &fields.resource_kind);
    write_opt(&mut buf, "resource_summary", &fields.resource_summary);
    write_opt(&mut buf, "decision", &fields.decision);
    write_opt(&mut buf, "reason_code", &fields.reason_code);

    write_array(&mut buf, "matched_rule_ids", &fields.matched_rule_ids);
    write_map(&mut buf, "metadata", &fields.metadata);

    buf
}

fn write_fmt(buf: &mut Vec<u8>, key: &str, value: &str) {
    buf.extend_from_slice(key.as_bytes());
    buf.push(b':');
    buf.push(b' ');
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'\n');
}

fn write_opt(buf: &mut Vec<u8>, key: &str, value: &Option<String>) {
    if let Some(v) = value {
        write_fmt(buf, key, v);
    }
}

fn write_array(buf: &mut Vec<u8>, key: &str, values: &[String]) {
    buf.extend_from_slice(key.as_bytes());
    buf.extend_from_slice(b": [");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        buf.push(b'"');
        buf.extend_from_slice(v.as_bytes());
        buf.push(b'"');
    }
    buf.push(b']');
    buf.push(b'\n');
}

fn write_map(buf: &mut Vec<u8>, key: &str, map: &std::collections::BTreeMap<String, String>) {
    buf.extend_from_slice(key.as_bytes());
    buf.extend_from_slice(b":\n");
    for (k, v) in map.iter() {
        buf.extend_from_slice(b"  ");
        buf.extend_from_slice(k.as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(v.as_bytes());
        buf.push(b'\n');
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn canonical_empty_event() {
        let fields = CanonicalEventFields {
            schema_version: 1,
            sequence: 1,
            event_id: "id-1".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            category: "RequestReceived".into(),
            request_id: None,
            agent_id: None,
            operation: None,
            resource_kind: None,
            resource_summary: None,
            decision: None,
            reason_code: None,
            matched_rule_ids: vec![],
            metadata: BTreeMap::new(),
        };
        let bytes = encode_canonical(&fields);
        let text = String::from_utf8(bytes).expect("valid utf-8");
        assert!(text.contains("schema_version: 1"));
        assert!(text.contains("sequence: 1"));
        assert!(text.contains("event_id: id-1"));
        assert!(text.contains("matched_rule_ids: []"));
        assert!(!text.contains("request_id:"));
    }

    #[test]
    fn canonical_deterministic() {
        let mut metadata = BTreeMap::new();
        metadata.insert("b-key".into(), "b-val".into());
        metadata.insert("a-key".into(), "a-val".into());

        let fields = CanonicalEventFields {
            schema_version: 1,
            sequence: 42,
            event_id: "evt-42".into(),
            timestamp: "2026-07-16T12:00:00Z".into(),
            category: "DecisionAllow".into(),
            request_id: Some("req-1".into()),
            agent_id: Some("agent-99".into()),
            operation: Some("file_read".into()),
            resource_kind: Some("file".into()),
            resource_summary: Some("[REDACTED]".into()),
            decision: Some("Allow".into()),
            reason_code: Some("policy_matched".into()),
            matched_rule_ids: vec!["rule-b".into(), "rule-a".into()],
            metadata,
        };

        let a = encode_canonical(&fields);
        let b = encode_canonical(&fields);
        assert_eq!(a, b);
    }

    #[test]
    fn metadata_order_is_deterministic() {
        let mut metadata = BTreeMap::new();
        metadata.insert("z".into(), "1".into());
        metadata.insert("a".into(), "2".into());

        let fields = CanonicalEventFields {
            schema_version: 1,
            sequence: 1,
            event_id: "id".into(),
            timestamp: "t".into(),
            category: "Test".into(),
            request_id: None,
            agent_id: None,
            operation: None,
            resource_kind: None,
            resource_summary: None,
            decision: None,
            reason_code: None,
            matched_rule_ids: vec![],
            metadata,
        };

        let bytes = encode_canonical(&fields);
        let text = String::from_utf8(bytes).expect("valid utf-8");

        let a_pos = text.find("a: 2").expect("a: 2 must be present");
        let z_pos = text.find("z: 1").expect("z: 1 must be present");
        assert!(a_pos < z_pos, "metadata keys must appear in sorted order");
    }
}
