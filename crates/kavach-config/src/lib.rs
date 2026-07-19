//! Layered configuration for the KAVACH security runtime.
//!
//! # Precedence
//!
//! Environment variables (`KAVACH_*`) > TOML file > built-in secure defaults.
//!
//! # Security
//!
//! - `fail_closed = false` is rejected at parse time.
//! - Non-loopback binding without explicit authentication configuration is rejected.
//! - All unknown TOML fields are rejected via `#[serde(deny_unknown_fields)]`.

use std::path::{Path, PathBuf};

/// Errors that can arise during configuration loading or validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// I/O error reading the configuration file.
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    /// TOML parse error (syntax or unknown field).
    #[error("failed to parse config TOML: {0}")]
    Parse(String),
    /// Semantic validation error (invalid values).
    #[error("config validation failed: {0}")]
    Validation(String),
    /// Environment variable override error.
    #[error("invalid environment variable: {0}")]
    Env(String),
}

/// Top-level KAVACH configuration.
#[derive(Debug, Clone)]
pub struct KavachConfig {
    /// HTTP server configuration.
    pub server: ServerConfig,
    /// Security posture configuration.
    pub security: SecurityConfig,
    /// Policy loading configuration.
    pub policy: PolicyConfig,
    /// Audit chain configuration.
    pub audit: AuditConfig,
    /// Approval broker configuration.
    pub approval: ApprovalConfig,
    /// Secret redaction configuration.
    pub redaction: RedactionConfig,
    /// Logging configuration.
    pub logging: LoggingConfig,
}

/// HTTP server configuration for the local gateway.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind on (loopback by default).
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Allow binding to non-loopback interfaces.
    #[serde(default = "default_false")]
    pub allow_non_loopback: bool,
    /// Maximum HTTP request body size in bytes.
    #[serde(default = "default_request_body_limit")]
    pub request_body_limit: u64,
    /// Request timeout in seconds.
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
}

/// Security posture configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Root directory for filesystem operations.
    #[serde(default = "default_workspace_root")]
    pub workspace_root: PathBuf,
    /// Whether to fail closed on errors (must be true).
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    /// Whether destructive operations require human approval.
    #[serde(default = "default_true")]
    pub approval_required_for_destructive_operations: bool,
}

/// Policy loading configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Paths to policy TOML files loaded at startup.
    #[serde(default = "default_policy_files")]
    pub files: Vec<PathBuf>,
}

/// Audit chain configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Path to the SQLite audit database.
    #[serde(default = "default_audit_database")]
    pub database: PathBuf,
    /// Whether to verify the audit chain on startup.
    #[serde(default = "default_true")]
    pub verify_on_startup: bool,
    /// Maximum events before rotation.
    #[serde(default = "default_rotation_max")]
    pub rotation_max_events: u64,
}

/// Approval broker configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    /// Path to the SQLite approval database.
    #[serde(default = "default_approval_database")]
    pub database: PathBuf,
    /// Default time-to-live for approval requests (seconds).
    #[serde(default = "default_ttl")]
    pub default_ttl_seconds: u64,
    /// Maximum number of pending approvals.
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
}

/// Secret redaction configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionConfig {
    /// Whether secret redaction is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Logging configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format (pretty or json).
    #[serde(default = "default_log_format")]
    pub format: String,
}

// ---- Secure defaults ----

fn default_bind() -> String {
    "127.0.0.1:7421".into()
}

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_request_body_limit() -> u64 {
    1_048_576
}

fn default_request_timeout_seconds() -> u64 {
    30
}

fn default_workspace_root() -> PathBuf {
    PathBuf::from(".")
}

fn default_policy_files() -> Vec<PathBuf> {
    vec![PathBuf::from("./config/default-policy.toml")]
}

fn default_audit_database() -> PathBuf {
    PathBuf::from("./data/kavach-audit.db")
}

fn default_rotation_max() -> u64 {
    100_000
}

fn default_ttl() -> u64 {
    300
}

fn default_approval_database() -> PathBuf {
    PathBuf::from("./data/kavach-approvals.db")
}

fn default_max_pending() -> usize {
    1000
}

fn default_log_level() -> String {
    "info".into()
}

fn default_log_format() -> String {
    "pretty".into()
}

// ---- TOML document ----

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlConfig {
    #[serde(default)]
    server: TomlServer,
    #[serde(default)]
    security: TomlSecurity,
    #[serde(default)]
    policy: TomlPolicy,
    #[serde(default)]
    audit: TomlAudit,
    #[serde(default)]
    approval: TomlApproval,
    #[serde(default)]
    redaction: TomlRedaction,
    #[serde(default)]
    logging: TomlLogging,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlServer {
    bind: Option<String>,
    allow_non_loopback: Option<bool>,
    request_body_limit: Option<u64>,
    request_timeout_seconds: Option<u64>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlSecurity {
    workspace_root: Option<String>,
    fail_closed: Option<bool>,
    approval_required_for_destructive_operations: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlPolicy {
    files: Option<Vec<String>>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlAudit {
    database: Option<String>,
    verify_on_startup: Option<bool>,
    rotation_max_events: Option<u64>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlApproval {
    database: Option<String>,
    default_ttl_seconds: Option<u64>,
    max_pending: Option<u64>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRedaction {
    enabled: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlLogging {
    level: Option<String>,
    format: Option<String>,
}

// ---- Environment variable prefix ----

const ENV_PREFIX: &str = "KAVACH_";

fn env_override_bool(current: bool, var: &str) -> Result<bool, ConfigError> {
    match std::env::var(var) {
        Ok(val) => match val.to_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            other => Err(ConfigError::Env(format!("invalid bool for {var}: {other}"))),
        },
        Err(std::env::VarError::NotPresent) => Ok(current),
        Err(e) => Err(ConfigError::Env(format!("{var}: {e}"))),
    }
}

fn env_override_string(current: String, var: &str) -> Result<String, ConfigError> {
    match std::env::var(var) {
        Ok(val) => Ok(val),
        Err(std::env::VarError::NotPresent) => Ok(current),
        Err(e) => Err(ConfigError::Env(format!("{var}: {e}"))),
    }
}

fn env_override_u64(current: u64, var: &str) -> Result<u64, ConfigError> {
    match std::env::var(var) {
        Ok(val) => val
            .parse::<u64>()
            .map_err(|e| ConfigError::Env(format!("{var}: {e}"))),
        Err(std::env::VarError::NotPresent) => Ok(current),
        Err(e) => Err(ConfigError::Env(format!("{var}: {e}"))),
    }
}

fn env_override_usize(current: usize, var: &str) -> Result<usize, ConfigError> {
    match std::env::var(var) {
        Ok(val) => val
            .parse::<usize>()
            .map_err(|e| ConfigError::Env(format!("{var}: {e}"))),
        Err(std::env::VarError::NotPresent) => Ok(current),
        Err(e) => Err(ConfigError::Env(format!("{var}: {e}"))),
    }
}

fn env_override_pathbuf(current: PathBuf, var: &str) -> Result<PathBuf, ConfigError> {
    match std::env::var(var) {
        Ok(val) => Ok(PathBuf::from(val)),
        Err(std::env::VarError::NotPresent) => Ok(current),
        Err(e) => Err(ConfigError::Env(format!("{var}: {e}"))),
    }
}

// ---- Loading functions ----

impl Default for KavachConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind: default_bind(),
                allow_non_loopback: false,
                request_body_limit: default_request_body_limit(),
                request_timeout_seconds: default_request_timeout_seconds(),
            },
            security: SecurityConfig {
                workspace_root: default_workspace_root(),
                fail_closed: true,
                approval_required_for_destructive_operations: true,
            },
            policy: PolicyConfig {
                files: default_policy_files(),
            },
            audit: AuditConfig {
                database: default_audit_database(),
                verify_on_startup: true,
                rotation_max_events: default_rotation_max(),
            },
            approval: ApprovalConfig {
                database: default_approval_database(),
                default_ttl_seconds: default_ttl(),
                max_pending: default_max_pending(),
            },
            redaction: RedactionConfig { enabled: true },
            logging: LoggingConfig {
                level: default_log_level(),
                format: default_log_format(),
            },
        }
    }
}

fn merge_option<T>(opt: Option<T>, default: T) -> T {
    opt.unwrap_or(default)
}

/// Load configuration from a TOML file, then apply environment variable overrides.
pub fn load_config(path: impl AsRef<Path>) -> Result<KavachConfig, ConfigError> {
    let contents = std::fs::read_to_string(path.as_ref()).map_err(ConfigError::Io)?;
    let toml_cfg: TomlConfig =
        toml::from_str(&contents).map_err(|e| ConfigError::Parse(e.to_string()))?;

    let mut cfg = KavachConfig::default();

    // Server
    cfg.server.bind = merge_option(toml_cfg.server.bind, cfg.server.bind);
    cfg.server.allow_non_loopback = merge_option(
        toml_cfg.server.allow_non_loopback,
        cfg.server.allow_non_loopback,
    );
    cfg.server.request_body_limit = merge_option(
        toml_cfg.server.request_body_limit,
        cfg.server.request_body_limit,
    );
    cfg.server.request_timeout_seconds = merge_option(
        toml_cfg.server.request_timeout_seconds,
        cfg.server.request_timeout_seconds,
    );

    // Security
    cfg.security.workspace_root = merge_option(
        toml_cfg.security.workspace_root.map(PathBuf::from),
        cfg.security.workspace_root,
    );
    cfg.security.fail_closed =
        merge_option(toml_cfg.security.fail_closed, cfg.security.fail_closed);
    cfg.security.approval_required_for_destructive_operations = merge_option(
        toml_cfg
            .security
            .approval_required_for_destructive_operations,
        cfg.security.approval_required_for_destructive_operations,
    );

    // Policy
    cfg.policy.files = merge_option(
        toml_cfg
            .policy
            .files
            .map(|v| v.into_iter().map(PathBuf::from).collect()),
        cfg.policy.files,
    );

    // Audit
    cfg.audit.database = merge_option(
        toml_cfg.audit.database.map(PathBuf::from),
        cfg.audit.database,
    );
    cfg.audit.verify_on_startup = merge_option(
        toml_cfg.audit.verify_on_startup,
        cfg.audit.verify_on_startup,
    );
    cfg.audit.rotation_max_events = merge_option(
        toml_cfg.audit.rotation_max_events,
        cfg.audit.rotation_max_events,
    );

    // Approval
    cfg.approval.database = merge_option(
        toml_cfg.approval.database.map(PathBuf::from),
        cfg.approval.database,
    );
    cfg.approval.default_ttl_seconds = merge_option(
        toml_cfg.approval.default_ttl_seconds,
        cfg.approval.default_ttl_seconds,
    );
    cfg.approval.max_pending = merge_option(
        toml_cfg.approval.max_pending.map(|v| v as usize),
        cfg.approval.max_pending,
    );

    // Redaction
    cfg.redaction.enabled = merge_option(toml_cfg.redaction.enabled, cfg.redaction.enabled);

    // Logging
    cfg.logging.level = merge_option(toml_cfg.logging.level, cfg.logging.level);
    cfg.logging.format = merge_option(toml_cfg.logging.format, cfg.logging.format);

    // Apply environment variable overrides
    cfg = apply_env_overrides(cfg)?;

    validate(&cfg)?;

    Ok(cfg)
}

fn apply_env_overrides(mut cfg: KavachConfig) -> Result<KavachConfig, ConfigError> {
    cfg.server.bind = env_override_string(cfg.server.bind, &format!("{ENV_PREFIX}SERVER_BIND"))?;
    cfg.server.allow_non_loopback = env_override_bool(
        cfg.server.allow_non_loopback,
        &format!("{ENV_PREFIX}SERVER_ALLOW_NON_LOOPBACK"),
    )?;
    cfg.server.request_body_limit = env_override_u64(
        cfg.server.request_body_limit,
        &format!("{ENV_PREFIX}SERVER_REQUEST_BODY_LIMIT"),
    )?;
    cfg.server.request_timeout_seconds = env_override_u64(
        cfg.server.request_timeout_seconds,
        &format!("{ENV_PREFIX}SERVER_REQUEST_TIMEOUT"),
    )?;

    cfg.security.workspace_root = env_override_pathbuf(
        cfg.security.workspace_root,
        &format!("{ENV_PREFIX}SECURITY_WORKSPACE_ROOT"),
    )?;
    cfg.security.fail_closed = env_override_bool(
        cfg.security.fail_closed,
        &format!("{ENV_PREFIX}SECURITY_FAIL_CLOSED"),
    )?;

    cfg.audit.database =
        env_override_pathbuf(cfg.audit.database, &format!("{ENV_PREFIX}AUDIT_DATABASE"))?;
    cfg.audit.verify_on_startup = env_override_bool(
        cfg.audit.verify_on_startup,
        &format!("{ENV_PREFIX}AUDIT_VERIFY_ON_STARTUP"),
    )?;

    cfg.approval.default_ttl_seconds = env_override_u64(
        cfg.approval.default_ttl_seconds,
        &format!("{ENV_PREFIX}APPROVAL_DEFAULT_TTL"),
    )?;
    cfg.approval.database = env_override_pathbuf(
        cfg.approval.database,
        &format!("{ENV_PREFIX}APPROVAL_DATABASE"),
    )?;
    cfg.approval.max_pending = env_override_usize(
        cfg.approval.max_pending,
        &format!("{ENV_PREFIX}APPROVAL_MAX_PENDING"),
    )?;

    cfg.redaction.enabled = env_override_bool(
        cfg.redaction.enabled,
        &format!("{ENV_PREFIX}REDACTION_ENABLED"),
    )?;

    cfg.logging.level =
        env_override_string(cfg.logging.level, &format!("{ENV_PREFIX}LOGGING_LEVEL"))?;
    cfg.logging.format =
        env_override_string(cfg.logging.format, &format!("{ENV_PREFIX}LOGGING_FORMAT"))?;

    Ok(cfg)
}

fn validate(cfg: &KavachConfig) -> Result<(), ConfigError> {
    if !cfg.security.fail_closed {
        return Err(ConfigError::Validation(
            "security.fail_closed must be true; disabling fail-closed is rejected".into(),
        ));
    }

    if !cfg.redaction.enabled {
        return Err(ConfigError::Validation(
            "redaction.enabled must be true for the gateway".into(),
        ));
    }

    if cfg.server.allow_non_loopback {
        return Err(ConfigError::Validation(
            "server.allow_non_loopback requires explicit authentication configuration (not yet supported)".into(),
        ));
    }

    if cfg.server.bind.is_empty() {
        return Err(ConfigError::Validation(
            "server.bind must not be empty".into(),
        ));
    }

    if cfg.server.request_body_limit == 0 {
        return Err(ConfigError::Validation(
            "server.request_body_limit must be greater than 0".into(),
        ));
    }

    if cfg.server.request_timeout_seconds == 0 {
        return Err(ConfigError::Validation(
            "server.request_timeout_seconds must be greater than 0".into(),
        ));
    }

    if cfg.approval.default_ttl_seconds == 0 {
        return Err(ConfigError::Validation(
            "approval.default_ttl_seconds must be greater than 0".into(),
        ));
    }

    if cfg.approval.database.as_os_str().is_empty() {
        return Err(ConfigError::Validation(
            "approval.database must not be empty".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn write_temp_config(filename: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("kavach_config_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(filename);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn defaults_are_secure() {
        let cfg = KavachConfig::default();
        assert!(cfg.security.fail_closed);
        assert!(!cfg.server.allow_non_loopback);
        assert!(cfg.redaction.enabled);
        assert!(cfg.audit.verify_on_startup);
        assert_eq!(cfg.server.bind, "127.0.0.1:7421");
        assert_eq!(cfg.logging.level, "info");
    }

    #[test]
    fn load_minimal_toml_config() {
        let toml = r#"
[server]
bind = "127.0.0.1:9090"
"#;
        let p = write_temp_config("minimal.toml", toml);
        let cfg = load_config(&p).unwrap();
        assert_eq!(cfg.server.bind, "127.0.0.1:9090");
        assert!(cfg.security.fail_closed);
    }

    #[test]
    fn load_full_toml_config() {
        let toml = r#"
[server]
bind = "127.0.0.1:7421"
request_timeout_seconds = 60

[security]
workspace_root = "/home/user/project"
fail_closed = true

[policy]
files = ["./config/policy-a.toml", "./config/policy-b.toml"]

[audit]
database = "./data/audit.db"
rotation_max_events = 50000

[approval]
database = "./data/approvals.db"
default_ttl_seconds = 600
max_pending = 500

[redaction]
enabled = true

[logging]
level = "debug"
format = "json"
"#;
        let p = write_temp_config("full.toml", toml);
        let cfg = load_config(&p).unwrap();
        assert_eq!(cfg.server.bind, "127.0.0.1:7421");
        assert_eq!(cfg.server.request_timeout_seconds, 60);
        assert_eq!(
            cfg.security.workspace_root,
            PathBuf::from("/home/user/project")
        );
        assert_eq!(cfg.policy.files.len(), 2);
        assert_eq!(cfg.audit.database, PathBuf::from("./data/audit.db"));
        assert_eq!(cfg.audit.rotation_max_events, 50000);
        assert_eq!(cfg.approval.default_ttl_seconds, 600);
        assert_eq!(cfg.approval.database, PathBuf::from("./data/approvals.db"));
        assert_eq!(cfg.approval.max_pending, 500);
        assert_eq!(cfg.logging.level, "debug");
        assert_eq!(cfg.logging.format, "json");
    }

    #[test]
    fn fail_closed_false_is_rejected() {
        let toml = r#"
[security]
fail_closed = false
"#;
        let p = write_temp_config("fail-closed.toml", toml);
        let err = load_config(&p).unwrap_err();
        assert!(
            err.to_string().contains("fail_closed"),
            "expected fail_closed error, got: {err}"
        );
    }

    #[test]
    fn allow_non_loopback_rejected() {
        let toml = r#"
[server]
allow_non_loopback = true
"#;
        let p = write_temp_config("non-loopback.toml", toml);
        let err = load_config(&p).unwrap_err();
        assert!(
            err.to_string().contains("allow_non_loopback"),
            "expected allow_non_loopback error, got: {err}"
        );
    }

    #[test]
    fn empty_bind_rejected() {
        let toml = r#"
[server]
bind = ""
"#;
        let p = write_temp_config("empty-bind.toml", toml);
        let err = load_config(&p).unwrap_err();
        assert!(
            err.to_string().contains("bind"),
            "expected bind error, got: {err}"
        );
    }

    #[test]
    fn zero_request_body_limit_rejected() {
        let toml = r#"
[server]
request_body_limit = 0
"#;
        let p = write_temp_config("zero-body.toml", toml);
        let err = load_config(&p).unwrap_err();
        assert!(
            err.to_string().contains("request_body_limit"),
            "expected body limit error, got: {err}"
        );
    }

    #[test]
    fn zero_ttl_rejected() {
        let toml = r#"
[approval]
default_ttl_seconds = 0
"#;
        let p = write_temp_config("zero-ttl.toml", toml);
        let err = load_config(&p).unwrap_err();
        assert!(
            err.to_string().contains("default_ttl_seconds"),
            "expected ttl error, got: {err}"
        );
    }

    #[test]
    fn unknown_field_rejected() {
        let toml = r#"
[server]
bind = "127.0.0.1:9090"
unknown_key = "bad"
"#;
        let p = write_temp_config("unknown.toml", toml);
        match load_config(&p) {
            Err(ConfigError::Parse(_)) => {}
            other => panic!("expected Parse error for unknown field, got {:?}", other),
        }
    }

    #[test]
    fn invalid_toml_rejected() {
        let p = write_temp_config("invalid.toml", "this is not toml {{{");
        match load_config(&p) {
            Err(ConfigError::Parse(_)) => {}
            other => panic!("expected Parse error, got {:?}", other),
        }
    }

    #[test]
    fn file_not_found() {
        match load_config("/nonexistent/path/config.toml") {
            Err(ConfigError::Io(_)) => {}
            other => panic!("expected Io error, got {:?}", other),
        }
    }
}
