use std::sync::Arc;
use std::thread;

use kavach_mcp::proxy::{McpProxy, McpProxyConfig, run_proxy};
use kavach_mcp::transport::McpTransport;

use crate::error::CliError;
use crate::exit::ExitCode;
use crate::output::OutputMode;

/// Run the MCP adapter: connects to the configured MCP server and proxies
/// tool calls through the KAVACH security runtime.
pub async fn run(config_path: &str, mode: OutputMode) -> Result<(), CliError> {
    let cfg = kavach_config::load_config(config_path).map_err(|e| {
        let msg = match &e {
            kavach_config::ConfigError::Io(inner) => format!("I/O error: {inner}"),
            kavach_config::ConfigError::Parse(detail) => format!("parse error: {detail}"),
            kavach_config::ConfigError::Validation(detail) => format!("validation error: {detail}"),
            kavach_config::ConfigError::Env(detail) => format!("environment error: {detail}"),
        };
        CliError::new(ExitCode::InvalidInput, msg)
    })?;

    let mut runtime_builder = kavach_runtime::runtime::RuntimeBuilder::new()
        .with_config(kavach_runtime::config::RuntimeConfig {
            audit_fail_closed: cfg.security.fail_closed,
            redaction_enabled: cfg.redaction.enabled,
            ..Default::default()
        })
        .with_workspace_root(cfg.security.workspace_root.clone())
        .with_audit_db(cfg.audit.database.to_string_lossy().to_string())
        .with_approval_db(cfg.approval.database.to_string_lossy().to_string())
        .with_approval_config(kavach_approval::ApprovalStoreConfig {
            default_ttl_seconds: cfg.approval.default_ttl_seconds,
            max_pending: cfg.approval.max_pending,
        });

    for policy_path in &cfg.policy.files {
        let policy = kavach_policy::load_policy_from_file(policy_path).map_err(|e| {
            let msg = format!("failed to load policy {}: {e}", policy_path.display());
            CliError::new(ExitCode::PolicyError, msg)
        })?;
        runtime_builder = runtime_builder.add_policy(policy);
    }

    let runtime = runtime_builder.build().map_err(|e| {
        CliError::new(
            ExitCode::InternalError,
            format!("runtime build failed: {e}"),
        )
    })?;

    if cfg.audit.verify_on_startup {
        let report = runtime.audit_store().verify_full().map_err(|e| {
            CliError::new(
                ExitCode::AuditError,
                format!("audit verification failed at startup: {e}"),
            )
        })?;
        if !report.chain_valid {
            return Err(CliError::new(
                ExitCode::AuditError,
                "audit verification failed at startup: chain is invalid",
            ));
        }
    }

    let runtime = Arc::new(runtime);

    let proxy_config = McpProxyConfig {
        server_command: "mcp-server".into(),
        ..Default::default()
    };

    let message = "starting KAVACH MCP adapter on stdio";
    crate::output::CliOutput::with_message(message).render(mode);

    let handle = thread::spawn(move || -> Result<(), String> {
        let mut proxy = McpProxy::spawn(proxy_config, runtime)?;
        let mut client_transport =
            McpTransport::new(Box::new(std::io::stdin()), Box::new(std::io::stdout()));
        run_proxy(&mut proxy, &mut client_transport)
    });

    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(CliError::new(ExitCode::InternalError, e)),
        Err(_) => Err(CliError::new(
            ExitCode::InternalError,
            "MCP proxy thread panicked",
        )),
    }
}
