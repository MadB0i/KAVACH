use std::fmt;

/// Errors that can arise from approval broker operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalError {
    /// Specific kind of error.
    pub kind: ApprovalErrorKind,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ApprovalErrorKind::InvalidRequest(d) => write!(f, "invalid request: {d}"),
            ApprovalErrorKind::InvalidConfiguration(d) => write!(f, "invalid configuration: {d}"),
            ApprovalErrorKind::InvalidActor(d) => write!(f, "invalid actor: {d}"),
            ApprovalErrorKind::InvalidReason(d) => write!(f, "invalid reason: {d}"),
            ApprovalErrorKind::SummaryTooLarge(s) => {
                write!(f, "summary too large: {s} bytes exceeds maximum")
            }
            ApprovalErrorKind::DatabaseOpen(d) => write!(f, "database open failure: {d}"),
            ApprovalErrorKind::MigrationFailure(d) => write!(f, "migration failure: {d}"),
            ApprovalErrorKind::DatabaseCorruption(d) => write!(f, "database corruption: {d}"),
            ApprovalErrorKind::ApprovalNotFound => write!(f, "approval not found"),
            ApprovalErrorKind::DuplicateActiveApproval => {
                write!(f, "duplicate active approval for request")
            }
            ApprovalErrorKind::PendingLimitReached => {
                write!(f, "maximum pending approvals reached")
            }
            ApprovalErrorKind::InvalidStateTransition { from, to } => {
                write!(f, "invalid state transition: {from} -> {to}")
            }
            ApprovalErrorKind::AlreadyApproved => write!(f, "approval already approved"),
            ApprovalErrorKind::AlreadyDenied => write!(f, "approval already denied"),
            ApprovalErrorKind::Cancelled => write!(f, "approval was cancelled"),
            ApprovalErrorKind::Expired => write!(f, "approval has expired"),
            ApprovalErrorKind::InvalidToken => write!(f, "invalid approval token"),
            ApprovalErrorKind::TokenBindingMismatch => {
                write!(f, "token binding does not match this approval")
            }
            ApprovalErrorKind::TokenAlreadyConsumed => {
                write!(f, "token has already been consumed")
            }
            ApprovalErrorKind::RequestDigestMismatch => {
                write!(f, "request digest does not match")
            }
            ApprovalErrorKind::TransactionFailure(d) => write!(f, "transaction failure: {d}"),
            ApprovalErrorKind::AuditFailure(d) => write!(f, "audit event append failed: {d}"),
            ApprovalErrorKind::RedactionFailure(d) => write!(f, "redaction failure: {d}"),
            ApprovalErrorKind::QueryLimitExceeded => write!(f, "query limit exceeded"),
        }
    }
}

/// Categorised reason for an approval error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalErrorKind {
    /// The tool request was invalid.
    InvalidRequest(String),
    /// The broker configuration was invalid.
    InvalidConfiguration(String),
    /// The actor ID was invalid.
    InvalidActor(String),
    /// The denial reason was invalid.
    InvalidReason(String),
    /// The approval summary exceeded the maximum size.
    SummaryTooLarge(usize),
    /// Could not open the SQLite database.
    DatabaseOpen(String),
    /// Schema migration failed.
    MigrationFailure(String),
    /// The database appears corrupted.
    DatabaseCorruption(String),
    /// The approval was not found.
    ApprovalNotFound,
    /// An active approval already exists for this request digest.
    DuplicateActiveApproval,
    /// The maximum number of pending approvals has been reached.
    PendingLimitReached,
    /// The requested state transition is not allowed.
    InvalidStateTransition {
        /// Current state.
        from: String,
        /// Desired state.
        to: String,
    },
    /// The approval was already approved.
    AlreadyApproved,
    /// The approval was already denied.
    AlreadyDenied,
    /// The approval was cancelled.
    Cancelled,
    /// The approval has expired.
    Expired,
    /// The presented token is invalid.
    InvalidToken,
    /// The token does not bind to this approval.
    TokenBindingMismatch,
    /// The token has already been consumed.
    TokenAlreadyConsumed,
    /// The request digest does not match the approval binding.
    RequestDigestMismatch,
    /// A transaction could not be completed.
    TransactionFailure(String),
    /// Appending an audit event failed.
    AuditFailure(String),
    /// Secret redaction failed.
    RedactionFailure(String),
    /// Query limit was exceeded.
    QueryLimitExceeded,
}

impl ApprovalError {
    /// Creates an error for an invalid request.
    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::InvalidRequest(detail.into()),
        }
    }

    /// Creates an error for invalid configuration.
    pub fn invalid_configuration(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::InvalidConfiguration(detail.into()),
        }
    }

    /// Creates an error for an invalid actor.
    pub fn invalid_actor(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::InvalidActor(detail.into()),
        }
    }

    /// Creates an error for an invalid denial reason.
    pub fn invalid_reason(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::InvalidReason(detail.into()),
        }
    }

    /// Creates an error when the summary exceeds size limits.
    pub fn summary_too_large(size: usize) -> Self {
        Self {
            kind: ApprovalErrorKind::SummaryTooLarge(size),
        }
    }

    /// Creates an error for database open failures.
    pub fn database_open(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::DatabaseOpen(detail.into()),
        }
    }

    /// Creates an error for migration failures.
    pub fn migration_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::MigrationFailure(detail.into()),
        }
    }

    /// Creates an error for database corruption.
    pub fn database_corruption(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::DatabaseCorruption(detail.into()),
        }
    }

    /// Creates an error for approval not found.
    pub fn not_found() -> Self {
        Self {
            kind: ApprovalErrorKind::ApprovalNotFound,
        }
    }

    /// Creates an error for duplicate active approval.
    pub fn duplicate_active() -> Self {
        Self {
            kind: ApprovalErrorKind::DuplicateActiveApproval,
        }
    }

    /// Creates an error for pending limit reached.
    pub fn pending_limit() -> Self {
        Self {
            kind: ApprovalErrorKind::PendingLimitReached,
        }
    }

    /// Creates an error for invalid state transition.
    pub fn invalid_transition(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::InvalidStateTransition {
                from: from.into(),
                to: to.into(),
            },
        }
    }

    /// Creates an error for an invalid token.
    pub fn invalid_token() -> Self {
        Self {
            kind: ApprovalErrorKind::InvalidToken,
        }
    }

    /// Creates an error for token binding mismatch.
    pub fn token_binding() -> Self {
        Self {
            kind: ApprovalErrorKind::TokenBindingMismatch,
        }
    }

    /// Creates an error for request digest mismatch.
    pub fn digest_mismatch() -> Self {
        Self {
            kind: ApprovalErrorKind::RequestDigestMismatch,
        }
    }

    /// Creates an error for transaction failures.
    pub fn transaction_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::TransactionFailure(detail.into()),
        }
    }

    /// Creates an error for audit append failures.
    pub fn audit_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::AuditFailure(detail.into()),
        }
    }

    /// Creates an error for redaction failures.
    pub fn redaction_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: ApprovalErrorKind::RedactionFailure(detail.into()),
        }
    }
}

impl std::error::Error for ApprovalError {}
