use kavach_core::permit::PermitScope;

/// Errors that can arise from runtime operations.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The request failed validation.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Policy evaluation failed.
    #[error("policy evaluation failed: {0}")]
    PolicyFailure(String),
    /// The request was denied.
    #[error("request denied: {reason}")]
    Denied {
        /// Human-readable reason.
        reason: String,
    },
    /// An approval operation failed.
    #[error("approval failure: {0}")]
    ApprovalFailure(String),
    /// An audit operation failed.
    #[error("audit failure: {0}")]
    AuditFailure(String),
    /// Redaction failed.
    #[error("redaction failure: {0}")]
    RedactionFailure(String),
    /// A permit operation failed.
    #[error("permit failure: {0}")]
    PermitFailure(String),
    /// The permit's scope is insufficient for the requested operation.
    #[error("permit scope mismatch: expected {expected:?}, got {actual:?}")]
    PermitScopeMismatch {
        /// The scope required by the operation.
        expected: PermitScope,
        /// The scope on the presented permit.
        actual: PermitScope,
    },
    /// No adapter is registered for the operation.
    #[error("missing adapter for operation: {0}")]
    MissingAdapter(String),
    /// The operation is not supported by any adapter.
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),
    /// Filesystem enforcement failed.
    #[error("filesystem enforcement failed: {0}")]
    FilesystemFailure(String),
    /// Command enforcement failed.
    #[error("command enforcement failed: {0}")]
    CommandFailure(String),
    /// Network enforcement failed.
    #[error("network enforcement failed: {0}")]
    NetworkFailure(String),
    /// The execution input was invalid for the operation.
    #[error("invalid execution input: {0}")]
    InvalidExecutionInput(String),
    /// Execution was attempted in dry-run mode.
    #[error("dry run execution rejected: cannot execute in dry-run mode")]
    DryRunExecutionRejected,
    /// The runtime configuration is invalid.
    #[error("configuration failure: {0}")]
    ConfigurationFailure(String),
    /// An internal consistency check failed.
    #[error("internal consistency failure: {0}")]
    InternalConsistencyFailure(String),
}
