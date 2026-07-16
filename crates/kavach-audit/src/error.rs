use std::fmt;

/// Error returned by audit-chain operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditError {
    /// Specific kind of error.
    pub kind: AuditErrorKind,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            AuditErrorKind::InvalidEvent(detail) => write!(f, "invalid audit event: {detail}"),
            AuditErrorKind::InvalidField(detail) => write!(f, "invalid field: {detail}"),
            AuditErrorKind::InputTooLarge { bytes, max } => {
                write!(f, "input too large: {bytes} bytes exceeds maximum {max}")
            }
            AuditErrorKind::RedactionFailure(detail) => {
                write!(f, "redaction failure: {detail}")
            }
            AuditErrorKind::DatabaseOpen(detail) => write!(f, "database open failure: {detail}"),
            AuditErrorKind::MigrationFailure(detail) => {
                write!(f, "migration failure: {detail}")
            }
            AuditErrorKind::DatabaseCorruption(detail) => {
                write!(f, "database corruption: {detail}")
            }
            AuditErrorKind::TransactionFailure(detail) => {
                write!(f, "transaction failure: {detail}")
            }
            AuditErrorKind::AppendFailure(detail) => write!(f, "append failure: {detail}"),
            AuditErrorKind::SequenceConflict { expected, actual } => {
                write!(f, "sequence conflict: expected {expected}, got {actual}")
            }
            AuditErrorKind::HashMismatch {
                sequence,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "hash mismatch at sequence {sequence}: expected {expected}, got {actual}"
                )
            }
            AuditErrorKind::BrokenChain(detail) => write!(f, "broken chain: {detail}"),
            AuditErrorKind::MissingEvent(sequence) => {
                write!(f, "missing event at sequence {sequence}")
            }
            AuditErrorKind::VerificationRangeTooLarge { requested, max } => {
                write!(
                    f,
                    "verification range too large: {requested} exceeds maximum {max}"
                )
            }
            AuditErrorKind::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported schema version: {version}")
            }
            AuditErrorKind::SerializationFailure(detail) => {
                write!(f, "serialization failure: {detail}")
            }
        }
    }
}

/// Categorised reason for an audit error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditErrorKind {
    /// The event structure was invalid.
    InvalidEvent(String),
    /// A specific field value was invalid.
    InvalidField(String),
    /// Input data exceeded a size limit.
    InputTooLarge {
        /// Number of bytes provided.
        bytes: usize,
        /// Maximum allowed bytes.
        max: usize,
    },
    /// Secret redaction failed.
    RedactionFailure(String),
    /// Could not open the SQLite database.
    DatabaseOpen(String),
    /// Schema migration failed.
    MigrationFailure(String),
    /// The database appears corrupted.
    DatabaseCorruption(String),
    /// A transaction could not be started or committed.
    TransactionFailure(String),
    /// Appending an event failed.
    AppendFailure(String),
    /// Sequence number conflict detected.
    SequenceConflict {
        /// Expected sequence number.
        expected: u64,
        /// Actual sequence number found.
        actual: u64,
    },
    /// Hash mismatch during verification.
    HashMismatch {
        /// Sequence number where the mismatch occurred.
        sequence: u64,
        /// Expected (recomputed) hash.
        expected: String,
        /// Actual hash stored in the database.
        actual: String,
    },
    /// Hash chain continuity broken.
    BrokenChain(String),
    /// Referenced event not found.
    MissingEvent(u64),
    /// Verification range exceeds maximum allowed.
    VerificationRangeTooLarge {
        /// Number of events requested.
        requested: u64,
        /// Maximum allowed events.
        max: u64,
    },
    /// Database schema version is not supported.
    UnsupportedSchemaVersion(u64),
    /// Failed to serialize or deserialize event data.
    SerializationFailure(String),
}

impl AuditError {
    /// Creates an error for an invalid event structure.
    pub fn invalid_event(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::InvalidEvent(detail.into()),
        }
    }

    /// Creates an error for an invalid field value.
    pub fn invalid_field(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::InvalidField(detail.into()),
        }
    }

    /// Creates an error when input exceeds a size limit.
    pub fn input_too_large(bytes: usize, max: usize) -> Self {
        Self {
            kind: AuditErrorKind::InputTooLarge { bytes, max },
        }
    }

    /// Creates an error when secret redaction fails.
    pub fn redaction_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::RedactionFailure(detail.into()),
        }
    }

    /// Creates an error when opening the database fails.
    pub fn database_open(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::DatabaseOpen(detail.into()),
        }
    }

    /// Creates an error when a schema migration fails.
    pub fn migration_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::MigrationFailure(detail.into()),
        }
    }

    /// Creates an error when database corruption is detected.
    pub fn database_corruption(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::DatabaseCorruption(detail.into()),
        }
    }

    /// Creates an error when a transaction cannot complete.
    pub fn transaction_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::TransactionFailure(detail.into()),
        }
    }

    /// Creates an error when appending an event fails.
    pub fn append_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::AppendFailure(detail.into()),
        }
    }

    /// Creates an error for a sequence number conflict.
    pub fn sequence_conflict(expected: u64, actual: u64) -> Self {
        Self {
            kind: AuditErrorKind::SequenceConflict { expected, actual },
        }
    }

    /// Creates an error when a recomputed hash does not match the stored hash.
    pub fn hash_mismatch(sequence: u64, expected: String, actual: String) -> Self {
        Self {
            kind: AuditErrorKind::HashMismatch {
                sequence,
                expected,
                actual,
            },
        }
    }

    /// Creates an error when the hash chain is broken.
    pub fn broken_chain(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::BrokenChain(detail.into()),
        }
    }

    /// Creates an error for a missing event.
    pub fn missing_event(sequence: u64) -> Self {
        Self {
            kind: AuditErrorKind::MissingEvent(sequence),
        }
    }

    /// Creates an error when a verification range exceeds the maximum.
    pub fn verification_range_too_large(requested: u64, max: u64) -> Self {
        Self {
            kind: AuditErrorKind::VerificationRangeTooLarge { requested, max },
        }
    }

    /// Creates an error for an unsupported database schema version.
    pub fn unsupported_schema_version(version: u64) -> Self {
        Self {
            kind: AuditErrorKind::UnsupportedSchemaVersion(version),
        }
    }

    /// Creates an error when serialization or deserialization fails.
    pub fn serialization_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: AuditErrorKind::SerializationFailure(detail.into()),
        }
    }
}

impl std::error::Error for AuditError {}
