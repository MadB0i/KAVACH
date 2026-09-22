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

    // Validate authentication before opening databases, loading runtime state,
    // or printing a startup message. Invalid credentials must not leave local
    // side effects or make the process appear to have started.
    let gateway_token = std::env::var("KAVACH_GATEWAY_TOKEN").map_err(|_| {
        CliError::new(
            ExitCode::InvalidInput,
            "KAVACH_GATEWAY_TOKEN must contain a 64-character hexadecimal token",
        )
    })?;
    if gateway_token.len() != 64 || !gateway_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::new(
            ExitCode::InvalidInput,
            "KAVACH_GATEWAY_TOKEN must contain a 64-character hexadecimal token",
        ));
    }

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

    for policy in policies {
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

    // Build gateway config.
    let gw_config = GwConfig {
        bind: cfg.server.bind.clone(),
        request_body_limit: usize::try_from(cfg.server.request_body_limit).map_err(|_| {
            CliError::new(
                ExitCode::InvalidInput,
                "server.request_body_limit does not fit this platform",
            )
        })?,
        request_timeout: Duration::from_secs(cfg.server.request_timeout_seconds),
        allow_non_loopback: cfg.server.allow_non_loopback,
        ..Default::default()
    };

    let message = format!("starting KAVACH gateway on {}", cfg.server.bind);
    let output = crate::output::CliOutput::with_message(message);
    output.render(mode);

    // Start gateway (blocks until shutdown).
    kavach_gateway::GatewayBuilder::new()
        .with_runtime(runtime)
        .with_auth_token_hex(Some(gateway_token))
        .with_config(gw_config)
        .start()
        .await
        .map_err(|e| CliError::new(ExitCode::InternalError, format!("gateway error: {e}")))?;

    Ok(())
}
