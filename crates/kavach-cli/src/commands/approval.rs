use std::path::Path;
use std::sync::Arc;

use kavach_approval::{ApprovalActor, ApprovalStoreConfig, RealClock, open_approval_broker};
use kavach_core::ids::ApprovalId;

use crate::error::CliError;
use crate::exit::ExitCode;
use crate::output::{CliOutput, OutputMode};

struct ApprovalContext {
    broker: Arc<dyn kavach_approval::ApprovalBroker>,
}

fn resolve_db_paths(config_path: Option<&str>) -> Result<(String, String), CliError> {
    if let Some(cfg_path) = config_path {
        let cfg = kavach_config::load_config(cfg_path).map_err(|e| {
            let msg = match &e {
                kavach_config::ConfigError::Io(inner) => format!("I/O error: {inner}"),
                kavach_config::ConfigError::Parse(detail) => format!("parse error: {detail}"),
                kavach_config::ConfigError::Validation(detail) => {
                    format!("validation error: {detail}")
                }
                kavach_config::ConfigError::Env(detail) => format!("environment error: {detail}"),
            };
            CliError::new(ExitCode::InvalidInput, msg)
        })?;
        let audit_db = cfg.audit.database.to_string_lossy().to_string();
        let approval_db = {
            let dir = Path::new(&audit_db).parent().unwrap_or(Path::new("./data"));
            dir.join("approvals.db").to_string_lossy().to_string()
        };
        Ok((audit_db, approval_db))
    } else {
        let default_audit = "./data/kavach-audit.db".to_string();
        let default_approval = "./data/approvals.db".to_string();

        let (audit_db, approval_db) = if Path::new(&default_audit).is_file() {
            (default_audit, default_approval)
        } else {
            return Err(CliError::new(
                ExitCode::InvalidInput,
                "no config file provided and no default audit database found at ./data/kavach-audit.db. \
                 Use --config to specify a config file.",
            ));
        };
        Ok((audit_db, approval_db))
    }
}

fn open_context(config_path: Option<&str>) -> Result<ApprovalContext, CliError> {
    let (audit_db, approval_db) = resolve_db_paths(config_path)?;

    let audit_store = kavach_audit::AuditStore::builder()
        .open(&audit_db)
        .map_err(|e| {
            CliError::new(
                ExitCode::Unavailable,
                format!("failed to open audit database: {e}"),
            )
        })?;

    let config = ApprovalStoreConfig {
        db_path: Some(approval_db.clone()),
    };
    let broker = open_approval_broker(&approval_db, config, audit_store, Box::new(RealClock))
        .map_err(|e| {
            CliError::new(
                ExitCode::Unavailable,
                format!("failed to open approval broker: {e}"),
            )
        })?;

    Ok(ApprovalContext { broker })
}

pub fn list(config_path: Option<&str>, mode: OutputMode) -> Result<(), CliError> {
    let ctx = open_context(config_path)?;

    let records = ctx.broker.list_pending(None).map_err(|e| {
        CliError::new(
            ExitCode::Unavailable,
            format!("failed to list approvals: {e}"),
        )
    })?;

    if records.is_empty() {
        let output = CliOutput::with_message("no pending approvals");
        output.render(mode);
        return Ok(());
    }

    let approval_list: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "approval_id": r.approval_id.to_string(),
                "request_id": r.request_id,
                "summary": r.summary,
                "operation": r.operation,
                "resource_kind": r.resource_kind,
                "state": format!("{:?}", r.state),
                "created_at": r.created_at.to_rfc3339(),
                "expires_at": r.expires_at.to_rfc3339(),
            })
        })
        .collect();

    let output = CliOutput::with_data(serde_json::json!({
        "count": records.len(),
        "approvals": approval_list,
    }));
    output.render(mode);
    Ok(())
}

pub fn approve(id: &str, config_path: Option<&str>, mode: OutputMode) -> Result<(), CliError> {
    let approval_id = ApprovalId::new(id)
        .map_err(|e| CliError::new(ExitCode::InvalidInput, format!("invalid approval ID: {e}")))?;
    let ctx = open_context(config_path)?;

    let actor = ApprovalActor::new("kavach-cli")
        .map_err(|e| CliError::new(ExitCode::InvalidInput, format!("invalid actor: {e}")))?;

    let token = ctx.broker.approve(&approval_id, &actor).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found") {
            CliError::new(ExitCode::InvalidInput, format!("approval not found: {id}"))
        } else {
            CliError::new(ExitCode::InternalError, format!("approval failed: {msg}"))
        }
    })?;

    let token_hash_hex = hex::encode(token.hash());
    let output = CliOutput::with_message(format!(
        "approval {id} approved; token hash: {token_hash_hex}"
    ));
    output.render(mode);
    Ok(())
}

pub fn deny(id: &str, config_path: Option<&str>, mode: OutputMode) -> Result<(), CliError> {
    let approval_id = ApprovalId::new(id)
        .map_err(|e| CliError::new(ExitCode::InvalidInput, format!("invalid approval ID: {e}")))?;
    let ctx = open_context(config_path)?;

    let actor = ApprovalActor::new("kavach-cli")
        .map_err(|e| CliError::new(ExitCode::InvalidInput, format!("invalid actor: {e}")))?;

    ctx.broker.deny(&approval_id, &actor, None).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found") {
            CliError::new(ExitCode::InvalidInput, format!("approval not found: {id}"))
        } else {
            CliError::new(ExitCode::InternalError, format!("deny failed: {msg}"))
        }
    })?;

    let output = CliOutput::with_message(format!("approval {id} denied"));
    output.render(mode);
    Ok(())
}
