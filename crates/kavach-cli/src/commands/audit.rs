use std::path::Path;

use kavach_audit::AuditStore;

use crate::error::CliError;
use crate::exit::ExitCode;
use crate::output::{CliOutput, OutputMode};

fn open_audit(path: &str) -> Result<AuditStore, CliError> {
    let db_path = Path::new(path);
    if !db_path.is_file() {
        return Err(CliError::new(
            ExitCode::InvalidInput,
            format!("database file not found: {path}"),
        ));
    }
    AuditStore::builder().open(path).map_err(|e| {
        CliError::new(
            ExitCode::AuditError,
            format!("failed to open audit database: {e}"),
        )
    })
}

pub fn verify(path: &str, mode: OutputMode) -> Result<(), CliError> {
    let store = open_audit(path)?;

    let report = store
        .verify_full()
        .map_err(|e| CliError::new(ExitCode::AuditError, format!("verification failed: {e}")))?;

    let error_details: Vec<serde_json::Value> = report
        .errors
        .iter()
        .map(|e| {
            serde_json::json!({
                "sequence": e.sequence,
                "kind": format!("{:?}", e.kind),
                "detail": e.detail,
            })
        })
        .collect();

    let chain_status = store.chain_status().ok().map(|cs| {
        serde_json::json!({
            "event_count": cs.event_count,
            "latest_sequence": cs.latest_sequence,
            "genesis_hash": cs.genesis_hash,
        })
    });

    let output = CliOutput::with_data(serde_json::json!({
        "chain_valid": report.chain_valid,
        "event_count": report.event_count,
        "verified_to": report.verified_to,
        "errors": error_details,
        "chain_status": chain_status,
    }));
    output.render(mode);

    if !report.chain_valid {
        return Err(CliError::new(
            ExitCode::AuditError,
            format!(
                "audit chain verification failed with {} error(s)",
                report.errors.len()
            ),
        ));
    }
    Ok(())
}

pub fn list(path: &str, mode: OutputMode) -> Result<(), CliError> {
    let store = open_audit(path)?;

    let count = store
        .event_count()
        .map_err(|e| CliError::new(ExitCode::AuditError, format!("failed to count events: {e}")))?;

    if count == 0 {
        let output = CliOutput::with_message("no audit events found");
        output.render(mode);
        return Ok(());
    }

    let limit = std::cmp::min(count, 100);
    let events = store
        .events_after_sequence(0, limit)
        .map_err(|e| CliError::new(ExitCode::AuditError, format!("failed to list events: {e}")))?;

    let event_list: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "sequence": e.sequence,
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "category": format!("{:?}", e.category),
                "request_id": e.request_id,
                "agent_id": e.agent_id,
                "operation": e.operation,
                "decision": e.decision,
            })
        })
        .collect();

    let output = CliOutput::with_data(serde_json::json!({
        "total_events": count,
        "events": event_list,
    }));
    output.render(mode);
    Ok(())
}
