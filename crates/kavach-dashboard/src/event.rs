//! Normalized decision-event shape shared by the SSE feed, history API and
//! dashboard UI. Two sources map into it: CLI JSONL feed lines (full
//! decisions with traces) and SQLite audit records (no trace).

/// One dashboard event, newest-first ordered by `at_secs`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeedEvent {
    /// Event origin: `"cli"` (decision feed) or `"audit"` (SQLite log).
    pub source: String,
    /// Normalized effect: `Allow`, `Deny` or `RequireApproval`.
    pub effect: String,
    /// Machine-readable reason code, if any.
    pub reason: String,
    /// Human-readable explanation.
    pub explanation: String,
    /// Matched rule IDs.
    pub matched_rule_ids: Vec<String>,
    /// Request ID, if any.
    pub request_id: String,
    /// Unix seconds used for newest-first ordering.
    pub at_secs: u64,
    /// Short human title: `echo 'x' '>' f` or a file path.
    pub title: String,
    /// Executable for filtering, when the resource is a command.
    pub executable: Option<String>,
    /// Trace payload (baseline / failed conditions), when present.
    pub trace: Option<serde_json::Value>,
}

impl FeedEvent {
    /// Case-insensitive substring match across the filterable fields.
    pub fn matches_query(&self, q: &str) -> bool {
        let q = q.to_lowercase();
        self.title.to_lowercase().contains(&q)
            || self.explanation.to_lowercase().contains(&q)
            || self.effect.to_lowercase().contains(&q)
            || self.request_id.to_lowercase().contains(&q)
            || self
                .matched_rule_ids
                .iter()
                .any(|id| id.to_lowercase().contains(&q))
    }
}

/// Parse one CLI JSONL feed line (written by `kavach policy check/explain
/// --feed-log`) into a [`FeedEvent`]. Returns `None` for blank/garbled lines.
pub fn feed_event_from_cli_line(line: &str) -> Option<FeedEvent> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let resource = value.get("resource").cloned().unwrap_or_default();
    let (title, executable) = resource_title(&resource);
    Some(FeedEvent {
        source: "cli".to_string(),
        effect: normalize_effect(
            value
                .get("effect")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
        ),

        reason: value
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        explanation: value
            .get("explanation")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        matched_rule_ids: value
            .get("matched_rule_ids")
            .and_then(|v| {
                v.as_array().map(|items| {
                    items
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
            })
            .unwrap_or_default(),
        request_id: value
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        at_secs: value
            .get("evaluated_at_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        title,
        executable,
        trace: value.get("trace").cloned().filter(|t| !t.is_null()),
    })
}

/// Map one SQLite audit record into a [`FeedEvent`] (no trace available).
pub fn feed_event_from_audit(record: &kavach_audit::AuditEventRecord) -> FeedEvent {
    let summary = record.resource_summary.clone().unwrap_or_default();
    let title = if summary.is_empty() {
        record.operation.clone().unwrap_or_default()
    } else {
        summary
    };
    FeedEvent {
        source: "audit".to_string(),
        effect: normalize_effect(record.decision.as_deref().unwrap_or_default()),
        reason: record.reason_code.clone().unwrap_or_default(),
        explanation: format!(
            "{} {}",
            record.category,
            record.resource_summary.clone().unwrap_or_default()
        )
        .trim()
        .to_string(),
        matched_rule_ids: record.matched_rule_ids.clone(),
        request_id: record.request_id.clone().unwrap_or_default(),
        at_secs: parse_audit_timestamp(&record.timestamp),
        title,
        executable: None,
        trace: None,
    }
}

/// Normalize effect spellings (`Allow`, `allow`, `DecisionAllow`, …) to the
/// canonical `Allow` / `Deny` / `RequireApproval` labels.
fn normalize_effect(text: &str) -> String {
    let lower = text.to_lowercase();
    if lower.contains("deny") || lower.contains("denied") {
        "Deny".to_string()
    } else if lower.contains("approv") || lower.contains("ask") {
        "RequireApproval".to_string()
    } else if lower.contains("allow") {
        "Allow".to_string()
    } else if text.is_empty() {
        "Unknown".to_string()
    } else {
        text.to_string()
    }
}

fn resource_title(resource: &serde_json::Value) -> (String, Option<String>) {
    let kind = resource
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    match kind {
        "command" => {
            let exe = resource
                .get("executable")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let args: Vec<String> = resource
                .get("arguments")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(quote_word)
                        .collect()
                })
                .unwrap_or_default();
            let mut title = exe.to_string();
            if !args.is_empty() {
                title.push(' ');
                title.push_str(&args.join(" "));
            }
            (title, Some(exe.to_string()))
        }
        _ => {
            let path = resource
                .get("path")
                .or_else(|| resource.get("identifier"))
                .or_else(|| resource.get("host"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            (format!("{kind} {path}"), None)
        }
    }
}

fn quote_word(word: &str) -> String {
    if word.is_empty()
        || word.bytes().any(|b| {
            b.is_ascii_whitespace()
                || matches!(
                    b,
                    b'\''
                        | b'"'
                        | b'$'
                        | b'`'
                        | b'|'
                        | b';'
                        | b'&'
                        | b'('
                        | b')'
                        | b'<'
                        | b'>'
                        | b'\\'
                )
        })
    {
        format!("'{}'", word.replace('\'', "'\\''"))
    } else {
        word.to_string()
    }
}

fn parse_audit_timestamp(timestamp: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt.timestamp().max(0) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_cli_feed_line() {
        let line = serde_json::json!({
            "source": "cli",
            "effect": "Deny",
            "reason": "KavachDenyExplicitRule",
            "explanation": "denied by built-in baseline",
            "matched_rule_ids": ["baseline-shell-hazard"],
            "request_id": "req-1",
            "evaluated_at_secs": 1700000000u64,
            "resource": {"kind": "command", "executable": "echo",
                         "arguments": ["x", ">", "f"]},
            "trace": {"baseline_triggered": "shell hazards",
                      "failed_conditions": []},
        })
        .to_string();
        let event = feed_event_from_cli_line(&line).unwrap();
        assert_eq!(event.effect, "Deny");
        assert_eq!(event.title, "echo x '>' f");
        assert_eq!(event.executable.as_deref(), Some("echo"));
        assert!(event.trace.is_some());
        assert!(event.matches_query("SHELL-hazard"));
        assert!(!event.matches_query("kubectl"));
    }

    #[test]
    fn rejects_blank_and_garbled_lines() {
        assert!(feed_event_from_cli_line("").is_none());
        assert!(feed_event_from_cli_line("   ").is_none());
        assert!(feed_event_from_cli_line("{not json").is_none());
    }

    #[test]
    fn maps_audit_record_to_event() {
        use kavach_audit::{AuditAppendInput, AuditEventCategory};
        use std::collections::BTreeMap;
        let store = kavach_audit::AuditStore::builder()
            .open_in_memory()
            .unwrap();
        store
            .append(AuditAppendInput {
                category: AuditEventCategory::DecisionDeny,
                request_id: Some("req-9".to_string()),
                agent_id: Some("agent-1".to_string()),
                operation: Some("command_execute".to_string()),
                resource_kind: Some("command".to_string()),
                resource_summary: Some("echo hello".to_string()),
                decision: Some("Deny".to_string()),
                reason_code: Some("KavachDenyExplicitRule".to_string()),
                matched_rule_ids: vec!["deny-x".to_string()],
                metadata: BTreeMap::new(),
            })
            .unwrap();
        let records = store.events_after_sequence(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        let event = feed_event_from_audit(&records[0]);
        assert_eq!(event.source, "audit");
        assert_eq!(event.effect, "Deny");
        assert_eq!(event.title, "echo hello");
        assert_eq!(event.request_id, "req-9");
        assert!(event.trace.is_none());
        assert!(event.matches_query("deny-x"));
    }
}
