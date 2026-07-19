use std::collections::BTreeMap;
use std::fmt;

use crate::error::AuditError;
use crate::hash::HashValue;

/// Current schema version for audit events.
pub const SCHEMA_VERSION: u16 = 1;

// ── Size limits ──────────────────────────────────────────────────────────────

/// Maximum number of metadata entries per event.
pub const MAX_METADATA_ENTRIES: usize = 64;

/// Maximum byte length of a metadata key.
pub const MAX_METADATA_KEY_LENGTH: usize = 128;

/// Maximum byte length of a metadata value.
pub const MAX_METADATA_VALUE_LENGTH: usize = 1024;

/// Maximum byte length of a resource summary.
pub const MAX_RESOURCE_SUMMARY_LENGTH: usize = 2048;

/// Maximum byte length of a reason code.
pub const MAX_REASON_CODE_LENGTH: usize = 128;

/// Maximum number of matched rule IDs per event.
pub const MAX_MATCHED_RULE_IDS: usize = 64;

/// Maximum number of events returned by a single query.
pub const MAX_EVENT_QUERY_COUNT: u64 = 1000;

/// Maximum number of events in a verification range.
pub const MAX_VERIFICATION_RANGE: u64 = 100_000;

/// Maximum database busy timeout in milliseconds.
pub const MAX_DATABASE_BUSY_TIMEOUT: u64 = 60_000;

// ── Event category ───────────────────────────────────────────────────────────

/// Typed category for an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditEventCategory {
    /// A request was received by the policy engine.
    RequestReceived,
    /// A request was rejected before processing.
    RequestRejected,
    /// The policy engine decided to allow an action.
    DecisionAllow,
    /// The policy engine decided to deny an action.
    DecisionDeny,
    /// An approval was requested for a pending action.
    ApprovalRequested,
    /// An approval was granted.
    ApprovalApproved,
    /// An approval was denied.
    ApprovalDenied,
    /// An approval request expired without a decision.
    ApprovalExpired,
    /// An approved one-time token was consumed and exchanged for a permit.
    ApprovalConsumed,
    /// Execution of an approved action started.
    ExecutionStarted,
    /// Execution of an action completed successfully.
    ExecutionSucceeded,
    /// Execution of an action failed.
    ExecutionFailed,
    /// A policy was loaded successfully.
    PolicyLoaded,
    /// A policy was rejected due to an error.
    PolicyRejected,
    /// An audit chain verification event.
    AuditVerification,
    /// A security warning was generated.
    SecurityWarning,
}

impl fmt::Display for AuditEventCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            AuditEventCategory::RequestReceived => "RequestReceived",
            AuditEventCategory::RequestRejected => "RequestRejected",
            AuditEventCategory::DecisionAllow => "DecisionAllow",
            AuditEventCategory::DecisionDeny => "DecisionDeny",
            AuditEventCategory::ApprovalRequested => "ApprovalRequested",
            AuditEventCategory::ApprovalApproved => "ApprovalApproved",
            AuditEventCategory::ApprovalDenied => "ApprovalDenied",
            AuditEventCategory::ApprovalExpired => "ApprovalExpired",
            AuditEventCategory::ApprovalConsumed => "ApprovalConsumed",
            AuditEventCategory::ExecutionStarted => "ExecutionStarted",
            AuditEventCategory::ExecutionSucceeded => "ExecutionSucceeded",
            AuditEventCategory::ExecutionFailed => "ExecutionFailed",
            AuditEventCategory::PolicyLoaded => "PolicyLoaded",
            AuditEventCategory::PolicyRejected => "PolicyRejected",
            AuditEventCategory::AuditVerification => "AuditVerification",
            AuditEventCategory::SecurityWarning => "SecurityWarning",
        };
        f.write_str(s)
    }
}

// ── Append input (caller provides this) ──────────────────────────────────────

/// Input to append a new audit event.
///
/// The store auto-generates `schema_version`, `sequence`, `event_id`,
/// `timestamp`, and hashes.
#[derive(Debug, Clone)]
pub struct AuditAppendInput {
    /// Category of the audit event.
    pub category: AuditEventCategory,
    /// Unique identifier for the request that triggered this event.
    pub request_id: Option<String>,
    /// Identifier of the agent that performed the action.
    pub agent_id: Option<String>,
    /// The operation being audited (e.g. "file_read").
    pub operation: Option<String>,
    /// The type of resource being accessed (e.g. "file", "database").
    pub resource_kind: Option<String>,
    /// A human-readable summary of the resource (redacted before persistence).
    pub resource_summary: Option<String>,
    /// The policy decision (e.g. "Allow", "Deny").
    pub decision: Option<String>,
    /// Machine-readable code explaining the policy decision.
    pub reason_code: Option<String>,
    /// List of policy rule IDs that matched for this event.
    pub matched_rule_ids: Vec<String>,
    /// Arbitrary key-value metadata attached to the event.
    pub metadata: BTreeMap<String, String>,
}

// ── Persisted event record (returned from queries) ───────────────────────────

/// A complete audit event record returned by the store.
#[derive(Debug, Clone)]
pub struct AuditEventRecord {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Unique UUID assigned at append time.
    pub event_id: String,
    /// ISO-8601 timestamp when the event was appended.
    pub timestamp: String,
    /// Category of the audit event.
    pub category: AuditEventCategory,
    /// Unique identifier for the request that triggered this event.
    pub request_id: Option<String>,
    /// Identifier of the agent that performed the action.
    pub agent_id: Option<String>,
    /// The operation being audited.
    pub operation: Option<String>,
    /// The type of resource being accessed.
    pub resource_kind: Option<String>,
    /// A summary of the resource (redacted if configured).
    pub resource_summary: Option<String>,
    /// The policy decision.
    pub decision: Option<String>,
    /// Machine-readable policy decision code.
    pub reason_code: Option<String>,
    /// List of policy rule IDs that matched.
    pub matched_rule_ids: Vec<String>,
    /// Key-value metadata attached to the event.
    pub metadata: BTreeMap<String, String>,
    /// Hash of the previous event (or genesis for the first event).
    pub previous_hash: HashValue,
    /// Hash of this event's canonical bytes chained with the previous hash.
    pub current_hash: HashValue,
}

// ── Validation ───────────────────────────────────────────────────────────────

impl AuditAppendInput {
    /// Validates the input against configured size limits.
    ///
    /// Returns `Ok(())` if all fields are within limits, or an
    /// [`crate::error::AuditErrorKind::InvalidField`] describing the first violation.
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.metadata.len() > MAX_METADATA_ENTRIES {
            return Err(AuditError::invalid_field(format!(
                "metadata entries {} exceeds maximum {MAX_METADATA_ENTRIES}",
                self.metadata.len()
            )));
        }
        for (k, v) in &self.metadata {
            if k.len() > MAX_METADATA_KEY_LENGTH {
                return Err(AuditError::invalid_field(format!(
                    "metadata key length {} exceeds maximum {MAX_METADATA_KEY_LENGTH}",
                    k.len()
                )));
            }
            if v.len() > MAX_METADATA_VALUE_LENGTH {
                return Err(AuditError::invalid_field(format!(
                    "metadata value length {} exceeds maximum {MAX_METADATA_VALUE_LENGTH}",
                    v.len()
                )));
            }
        }
        if let Some(ref summary) = self.resource_summary {
            if summary.len() > MAX_RESOURCE_SUMMARY_LENGTH {
                return Err(AuditError::invalid_field(format!(
                    "resource summary length {} exceeds maximum {MAX_RESOURCE_SUMMARY_LENGTH}",
                    summary.len()
                )));
            }
        }
        if let Some(ref code) = self.reason_code {
            if code.len() > MAX_REASON_CODE_LENGTH {
                return Err(AuditError::invalid_field(format!(
                    "reason code length {} exceeds maximum {MAX_REASON_CODE_LENGTH}",
                    code.len()
                )));
            }
        }
        if self.matched_rule_ids.len() > MAX_MATCHED_RULE_IDS {
            return Err(AuditError::invalid_field(format!(
                "matched rule IDs {} exceeds maximum {MAX_MATCHED_RULE_IDS}",
                self.matched_rule_ids.len()
            )));
        }
        if self.matched_rule_ids.iter().any(|s| s.is_empty()) {
            return Err(AuditError::invalid_field(
                "matched rule ID must not be empty",
            ));
        }
        Ok(())
    }
}

// ── Canonical fields (intermediate representation for hashing) ────────────────

/// Ordered set of fields extracted from an event for canonical encoding.
pub(crate) struct CanonicalEventFields {
    pub schema_version: u16,
    pub sequence: u64,
    pub event_id: String,
    pub timestamp: String,
    pub category: String,
    pub request_id: Option<String>,
    pub agent_id: Option<String>,
    pub operation: Option<String>,
    pub resource_kind: Option<String>,
    pub resource_summary: Option<String>,
    pub decision: Option<String>,
    pub reason_code: Option<String>,
    pub matched_rule_ids: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}
