use std::time::Duration;

use kavach_gateway::state::GatewayConfig as GwConfig;

use crate::error::CliError;
use crate::exit::ExitCode;
use crate::output::OutputMode;

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

    // Load policies.
    let mut policies = Vec::new();
    for policy_path in &cfg.policy.files {
        let policy = kavach_policy::load_policy_from_file(policy_path).map_err(|e| {
            let msg = format!("failed to load policy {}: {e}", policy_path.display());
            CliError::new(ExitCode::PolicyError, msg)
        })?;
        policies.push(policy);
    }

    // Build runtime.
    let mut runtime = kavach_runtime::runtime::RuntimeBuilder::new()
        .with_config(kavach_runtime::config::RuntimeConfig {
            permit_ttl: Duration::from_secs(cfg.server.request_timeout_seconds),
            ..Default::default()
        })
        .with_workspace_root(cfg.security.workspace_root.clone())
        .with_audit_db(cfg.audit.database.to_string_lossy().to_string())
        .build()
        .map_err(|e| {
            CliError::new(
                ExitCode::InternalError,
                format!("runtime build failed: {e}"),
            )
        })?;

    for policy in policies {
        let _ = runtime.reload_policies(vec![policy]);
    }

    // Build gateway config.
    let gw_config = GwConfig {
        bind: cfg.server.bind.clone(),
        request_body_limit: cfg.server.request_body_limit as usize,
        request_timeout: Duration::from_secs(cfg.server.request_timeout_seconds),
        ..Default::default()
    };

    let message = format!("starting KAVACH gateway on {}", cfg.server.bind);
    let output = crate::output::CliOutput::with_message(message);
    output.render(mode);

    // Start gateway (blocks until shutdown).
    kavach_gateway::GatewayBuilder::new()
        .with_runtime(runtime)
        .with_config(gw_config)
        .start()
        .await
        .map_err(|e| CliError::new(ExitCode::InternalError, format!("gateway error: {e}")))?;

    Ok(())
}
