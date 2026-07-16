use std::fmt;

use kavach_core::decision::ReasonCode;
use kavach_core::ids::{ApprovalId, RequestId, RuleId};
use kavach_core::permit::{ExecutionPermit, PermitScope};

/// Outcome of a runtime [`evaluate`](crate::runtime::KavachRuntime::evaluate) call.
#[derive(Debug, Clone)]
pub enum RuntimeOutcome {
    /// The request is denied. Never contains an execution permit.
    Denied {
        /// The original request ID.
        request_id: RequestId,
        /// Stable machine-readable reason code.
        reason_code: ReasonCode,
        /// Sorted matched rule IDs that caused the denial.
        matched_rule_ids: Vec<RuleId>,
        /// Sanitised summary safe for logging.
        sanitized_summary: String,
        /// Audit event sequence number.
        audit_event_id: u64,
    },
    /// The request requires human approval before execution.
    ApprovalRequired {
        /// The original request ID.
        request_id: RequestId,
        /// The approval ID to track the pending approval.
        approval_id: ApprovalId,
        /// Sanitised summary safe for logging.
        sanitized_summary: String,
        /// Audit event sequence number.
        audit_event_id: u64,
    },
    /// The request is permitted. Contains a request-bound execution permit.
    Permitted(PermittedOutcome),
}

/// A permit paired with its secret.
///
/// The secret is required at execution time but must **never** be logged or
/// serialised.  This wrapper ensures the secret is only accessible through an
/// explicit method call that consumes the struct.
#[derive(Clone)]
pub struct PermittedOutcome {
    /// The execution permit (safe to log — no secret).
    pub permit: ExecutionPermit,
    /// The raw 256-bit permit secret.
    permit_secret: [u8; 32],
}

impl fmt::Debug for PermittedOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PermittedOutcome")
            .field("permit", &self.permit)
            .field("permit_secret", &"<redacted>")
            .finish()
    }
}

impl PermittedOutcome {
    /// Create a new permitted outcome.
    pub fn new(permit: ExecutionPermit, secret: [u8; 32]) -> Self {
        Self {
            permit,
            permit_secret: secret,
        }
    }

    /// Consume this outcome and return the raw permit secret for execution.
    pub fn into_secret(self) -> [u8; 32] {
        self.permit_secret
    }

    /// Borrow the permit secret.
    pub fn secret(&self) -> &[u8; 32] {
        &self.permit_secret
    }

    /// The original request ID.
    pub fn request_id(&self) -> &RequestId {
        &self.permit.request_id
    }

    /// The scope of the permit.
    pub fn scope(&self) -> PermitScope {
        self.permit.scope
    }

    /// The matched rule IDs.
    pub fn matched_rule_ids(&self) -> &[RuleId] {
        &self.permit.matched_rule_ids
    }

    /// The request digest this permit is bound to.
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.permit.request_digest
    }
}

/// Input data for execution, dispatched by operation.
pub enum ExecutionInput<'a> {
    /// No input data needed (read-only or input-less operations).
    None,
    /// Filesystem write payload.
    FilesystemWrite(&'a [u8]),
    /// Command execution parameters.
    Command(kavach_enforcement::command::CommandInput),
    /// Network request parameters.
    Network(kavach_enforcement::network::NetworkInput),
}

/// Result of an executed operation.
#[derive(Debug, Clone)]
pub enum ExecutionResult {
    /// Filesystem operation result.
    Filesystem(kavach_enforcement::FilesystemOutcome),
    /// Command execution result.
    Command(kavach_enforcement::command::CommandOutcome),
    /// Network request result.
    Network(kavach_enforcement::network::NetworkOutcome),
}

impl ExecutionResult {
    /// Redact any secret-bearing content in this result, returning a new
    /// sanitised copy (or the same result if no redaction applies).
    pub fn redacted(
        &self,
        redactor: &dyn kavach_redaction::Redactor,
    ) -> Result<Self, kavach_redaction::RedactionError> {
        match self {
            ExecutionResult::Filesystem(outcome) => {
                Ok(ExecutionResult::Filesystem(outcome.clone()))
            }
            ExecutionResult::Command(outcome) => {
                let stdout_str = String::from_utf8_lossy(&outcome.stdout);
                let stderr_str = String::from_utf8_lossy(&outcome.stderr);
                let redacted_stdout = redactor.redact_text(&stdout_str)?;
                let redacted_stderr = redactor.redact_text(&stderr_str)?;
                Ok(ExecutionResult::Command(
                    kavach_enforcement::command::CommandOutcome {
                        stdout: redacted_stdout.redacted.into_bytes(),
                        stderr: redacted_stderr.redacted.into_bytes(),
                        ..outcome.clone()
                    },
                ))
            }
            ExecutionResult::Network(outcome) => {
                let body_str = String::from_utf8_lossy(&outcome.body);
                let redacted_body = redactor.redact_text(&body_str)?;
                let mut headers = outcome.headers.clone();
                for (name, value) in &mut headers {
                    let lower = name.to_lowercase();
                    if lower == "authorization"
                        || lower == "set-cookie"
                        || lower == "proxy-authenticate"
                        || lower == "www-authenticate"
                    {
                        *value = "[REDACTED]".to_string();
                    } else {
                        let r = redactor.redact_text(value)?;
                        *value = r.redacted;
                    }
                }
                Ok(ExecutionResult::Network(
                    kavach_enforcement::network::NetworkOutcome {
                        body: redacted_body.redacted.into_bytes(),
                        headers,
                        ..outcome.clone()
                    },
                ))
            }
        }
    }
}
