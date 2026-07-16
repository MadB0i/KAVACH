use crate::event::AuditEventCategory;

/// A sanitised summary returned after a successful append.
#[derive(Debug, Clone)]
pub struct PersistedEventSummary {
    /// Assigned sequence number.
    pub sequence: u64,
    /// Auto-generated event UUID.
    pub event_id: String,
    /// ISO-8601 timestamp of the append.
    pub timestamp: String,
    /// Event category.
    pub category: AuditEventCategory,
    /// Hex-encoded hash of the previous event.
    pub previous_hash: String,
    /// Hex-encoded hash of this event.
    pub current_hash: String,
}

/// Current chain status.
#[derive(Debug, Clone)]
pub struct ChainStatus {
    /// Total number of events in the chain.
    pub event_count: u64,
    /// Sequence number of the most recent event, if any.
    pub latest_sequence: Option<u64>,
    /// Hex-encoded hash of the most recent event, if any.
    pub latest_hash: Option<String>,
    /// Hex-encoded genesis hash of the chain.
    pub genesis_hash: String,
    /// Whether the chain is structurally valid (no hash mismatches detected during last operation).
    pub is_valid: bool,
}
