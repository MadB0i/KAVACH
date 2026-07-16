use std::time::Duration;

/// Configuration for the KAVACH runtime.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Duration before an [`ExecutionPermit`](kavach_core::permit::ExecutionPermit) expires.
    pub permit_ttl: Duration,
    /// Whether the runtime fails closed when a required audit event cannot be
    /// written. When `true`, any audit failure causes the current operation to
    /// fail with [`RuntimeError::AuditFailure`](crate::error::RuntimeError::AuditFailure).
    pub audit_fail_closed: bool,
    /// Whether output redaction is enabled for execution results.
    pub redaction_enabled: bool,
    /// Maximum length of a sanitised summary string.
    pub max_sanitized_summary_length: usize,
    /// When `true`, the runtime never executes side effects.
    pub dry_run: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            permit_ttl: Duration::from_secs(300),
            audit_fail_closed: true,
            redaction_enabled: true,
            max_sanitized_summary_length: 4096,
            dry_run: false,
        }
    }
}
