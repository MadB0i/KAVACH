use std::fmt;

use chrono::{DateTime, Utc};

use kavach_core::ids::ApprovalId;

/// Maximum TTL for an approval in seconds.
pub const MAX_APPROVAL_TTL_SECONDS: u64 = 86_400;

/// Default TTL for an approval in seconds (1 hour).
pub const DEFAULT_APPROVAL_TTL_SECONDS: u64 = 3_600;

/// Maximum number of pending approvals allowed per broker.
pub const MAX_PENDING_APPROVALS: usize = 10_000;

/// Default maximum number of pending approvals.
pub const DEFAULT_MAX_PENDING_APPROVALS: usize = 1_000;

/// Maximum length of an approval summary.
pub const MAX_APPROVAL_SUMMARY_LENGTH: usize = 4_096;

/// Maximum length of an actor ID string.
pub const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum length of a denial reason.
pub const MAX_DENIAL_REASON_LENGTH: usize = 1_024;

/// Maximum number of records returned by a single query.
pub const MAX_QUERY_LIMIT: u64 = 1_000;

/// Configuration for the SQLite approval store.
#[derive(Debug, Clone, Default)]
pub struct ApprovalStoreConfig {
    /// Path to the SQLite database file.
    pub db_path: Option<String>,
}

/// The current state of an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    /// Approval created, awaiting human decision.
    Pending,
    /// Human approved, token issued.
    Approved,
    /// Human denied.
    Denied,
    /// Approval TTL expired before a decision.
    Expired,
    /// Token was consumed to execute the operation.
    Consumed,
    /// Approval was cancelled before a decision.
    Cancelled,
}

impl fmt::Display for ApprovalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalState::Pending => f.write_str("pending"),
            ApprovalState::Approved => f.write_str("approved"),
            ApprovalState::Denied => f.write_str("denied"),
            ApprovalState::Expired => f.write_str("expired"),
            ApprovalState::Consumed => f.write_str("consumed"),
            ApprovalState::Cancelled => f.write_str("cancelled"),
        }
    }
}

/// Identifies the human actor who made an approval decision.
#[derive(Debug, Clone)]
pub struct ApprovalActor {
    id: String,
}

impl ApprovalActor {
    /// Creates a new actor with the given ID, validating length.
    pub fn new(id: impl Into<String>) -> Result<Self, crate::error::ApprovalError> {
        let s = id.into();
        if s.is_empty() {
            return Err(crate::error::ApprovalError::invalid_actor(
                "actor id must not be empty",
            ));
        }
        if s.len() > MAX_ACTOR_ID_LENGTH {
            return Err(crate::error::ApprovalError::invalid_actor(format!(
                "actor id length {} exceeds maximum {MAX_ACTOR_ID_LENGTH}",
                s.len()
            )));
        }
        Ok(Self { id: s })
    }

    /// Returns the actor ID string.
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for ApprovalActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)
    }
}

/// Input for requesting a new approval.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// The request that triggered the approval requirement.
    pub request: kavach_core::request::ToolRequest,
    /// Matched rule IDs that triggered the approval requirement.
    pub matched_rule_ids: Vec<String>,
    /// Pre-redacted display summary of the request.
    pub summary: String,
}

/// Output of a successful approval creation.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    /// Unique approval ID.
    pub approval_id: ApprovalId,
    /// The request ID from the original tool request.
    pub request_id: String,
    /// SHA-256 digest of the request.
    pub request_digest: [u8; 32],
    /// Sanitized summary of what was requested.
    pub summary: String,
    /// Requested operation.
    pub operation: String,
    /// Resource kind.
    pub resource_kind: String,
    /// Sorted matched rule IDs.
    pub matched_rule_ids: Vec<String>,
    /// When the approval was created.
    pub created_at: DateTime<Utc>,
    /// When the approval expires.
    pub expires_at: DateTime<Utc>,
    /// Current state (always Pending when returned from request_approval).
    pub state: ApprovalState,
}

/// A fully populated approval record, including decision details.
#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    /// Unique approval ID.
    pub approval_id: ApprovalId,
    /// The request ID from the original tool request.
    pub request_id: String,
    /// SHA-256 digest of the request.
    pub request_digest: [u8; 32],
    /// Sanitized summary of what was requested.
    pub summary: String,
    /// Requested operation.
    pub operation: String,
    /// Resource kind.
    pub resource_kind: String,
    /// Sorted matched rule IDs.
    pub matched_rule_ids: Vec<String>,
    /// When the approval was created.
    pub created_at: DateTime<Utc>,
    /// When the approval expires.
    pub expires_at: DateTime<Utc>,
    /// Current state.
    pub state: ApprovalState,
    /// Actor who approved or denied (if applicable).
    pub actor: Option<ApprovalActor>,
    /// Denial reason (if denied).
    pub denial_reason: Option<String>,
    /// When the decision was made (approve/deny/cancel).
    pub decision_at: Option<DateTime<Utc>>,
    /// When the token was consumed (if consumed).
    pub consumed_at: Option<DateTime<Utc>>,
    /// Audit event sequence reference, if available.
    pub audit_sequence: Option<u64>,
}

/// Output of a successful token consumption.
#[derive(Debug, Clone)]
pub struct ConsumedApproval {
    /// Unique approval ID.
    pub approval_id: ApprovalId,
    /// SHA-256 digest of the original request.
    pub request_digest: [u8; 32],
    /// Matched rule IDs that triggered the approval.
    pub matched_rule_ids: Vec<String>,
    /// When the token was consumed.
    pub consumed_at: DateTime<Utc>,
    /// Audit event sequence reference, if available.
    pub audit_sequence: Option<u64>,
}

/// Internal database row representation (not public).
#[derive(Debug, Clone)]
pub(crate) struct ApprovalRow {
    pub approval_id: String,
    pub request_id: String,
    pub request_digest_hex: String,
    pub summary: String,
    pub operation: String,
    pub resource_kind: String,
    pub matched_rule_ids: String,
    pub created_at: String,
    pub expires_at: String,
    pub state: String,
    pub token_hash: Option<String>,
    pub actor_id: Option<String>,
    pub denial_reason: Option<String>,
    pub decision_at: Option<String>,
    pub consumed_at: Option<String>,
    pub audit_sequence: Option<u64>,
}
