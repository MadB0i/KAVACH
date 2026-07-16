//! Tamper-evident audit events with SHA-256 hash chaining and SQLite persistence.
//!
//! This crate provides an append-only audit log where every event is linked to
//! its predecessor via a SHA-256 hash.  Textual fields are redacted through
//! [`kavach_redaction`] before persistence so secret values never appear in
//! the database.
//!
//! # Architecture
//!
//! - [`AuditStore`] — SQLite-backed append-only store
//! - [`HashValue`] — validated 32-byte SHA-256 hash
//! - [`AuditEventCategory`] — typed event categories
//! - [`VerificationReport`] — chain verification result
//!
//! # Canonical encoding
//!
//! Each event is serialised to a deterministic byte representation
//! (`field: value\n`) with explicit field ordering and sorted metadata keys.
//! The hash of an event is `SHA-256(prev_hash || canonical_bytes)`.
//! The first event's `previous_hash` is the genesis hash
//! `SHA-256("kavach-audit-genesis-v1")`.
//!
//! # SQLite
//!
//! The store uses WAL journal mode, foreign keys enabled, and a configurable
//! busy timeout.  Appends use `BEGIN IMMEDIATE` transactions to prevent
//! concurrent writers from creating forked chains.

/// Canonical byte encoding for hash chaining.
pub mod canonical;
/// Checkpoint creation for trusted verification starting points.
pub mod checkpoint;
/// Error types for audit-chain operations.
pub mod error;
/// Event types, categories, and validation.
pub mod event;
/// SHA-256 hash value type and computation.
pub mod hash;
/// Query result types returned from the store.
pub mod query;
/// SQLite-backed audit event store with append and query operations.
pub mod store;
/// Chain verification and tamper detection.
pub mod verification;

pub use checkpoint::Checkpoint;
pub use error::{AuditError, AuditErrorKind};
pub use event::{
    AuditAppendInput, AuditEventCategory, AuditEventRecord, MAX_DATABASE_BUSY_TIMEOUT,
    MAX_EVENT_QUERY_COUNT, MAX_MATCHED_RULE_IDS, MAX_METADATA_ENTRIES, MAX_METADATA_KEY_LENGTH,
    MAX_METADATA_VALUE_LENGTH, MAX_REASON_CODE_LENGTH, MAX_RESOURCE_SUMMARY_LENGTH,
    MAX_VERIFICATION_RANGE, SCHEMA_VERSION,
};
pub use hash::HashValue;
pub use query::{ChainStatus, PersistedEventSummary};
pub use store::{AuditStore, AuditStoreBuilder};
pub use verification::{VerificationError, VerificationErrorKind, VerificationReport};

#[cfg(test)]
mod proptests;
