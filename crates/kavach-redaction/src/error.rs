use std::fmt;

/// Error returned by redaction operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionError {
    /// Specific kind of error.
    pub kind: RedactionErrorKind,
}

impl fmt::Display for RedactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            RedactionErrorKind::InputTooLarge { bytes, max } => {
                write!(f, "input too large: {bytes} bytes exceeds maximum {max}")
            }
            RedactionErrorKind::InvalidConfiguration(detail) => {
                write!(f, "invalid redaction configuration: {detail}")
            }
            RedactionErrorKind::EmptyConfiguredSecret => {
                write!(f, "configured secret must not be empty")
            }
            RedactionErrorKind::TooManyConfiguredSecrets { count, max } => {
                write!(
                    f,
                    "too many configured secrets: {count} exceeds maximum {max}"
                )
            }
            RedactionErrorKind::ConfiguredSecretTooLong { length, max } => {
                write!(
                    f,
                    "configured secret too long: {length} bytes exceeds maximum {max}"
                )
            }
            RedactionErrorKind::InvalidSensitiveKey(detail) => {
                write!(f, "invalid sensitive key pattern: {detail}")
            }
            RedactionErrorKind::UnsupportedBinaryInput => {
                write!(f, "unsupported binary input: not valid UTF-8")
            }
            RedactionErrorKind::InternalPatternFailure(detail) => {
                write!(f, "internal pattern failure: {detail}")
            }
        }
    }
}

/// Categorised reason for a redaction error.
///
/// Each variant carries the data needed to produce a user-facing message
/// without revealing secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionErrorKind {
    /// Input exceeded [`MAX_INPUT_BYTES`](crate::types::MAX_INPUT_BYTES).
    InputTooLarge {
        /// Actual byte count of the input.
        bytes: usize,
        /// Maximum allowed byte count.
        max: usize,
    },
    /// A configuration parameter was invalid.
    InvalidConfiguration(String),
    /// An empty string was supplied as a configured secret.
    EmptyConfiguredSecret,
    /// More than [`MAX_CONFIGURED_SECRETS`](crate::types::MAX_CONFIGURED_SECRETS) secrets were added.
    TooManyConfiguredSecrets {
        /// Attempted total count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// A configured secret exceeded [`MAX_CONFIGURED_SECRET_LENGTH`](crate::types::MAX_CONFIGURED_SECRET_LENGTH).
    ConfiguredSecretTooLong {
        /// Length of the supplied secret.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A sensitive key pattern was invalid.
    InvalidSensitiveKey(String),
    /// Input bytes were not valid UTF-8.
    UnsupportedBinaryInput,
    /// An internal regex or pattern failed unexpectedly.
    InternalPatternFailure(String),
}

impl RedactionError {
    /// Creates an `InputTooLarge` error.
    pub fn input_too_large(bytes: usize, max: usize) -> Self {
        Self {
            kind: RedactionErrorKind::InputTooLarge { bytes, max },
        }
    }

    /// Creates an `InvalidConfiguration` error with the given detail.
    pub fn invalid_configuration(detail: impl Into<String>) -> Self {
        Self {
            kind: RedactionErrorKind::InvalidConfiguration(detail.into()),
        }
    }

    /// Creates an `EmptyConfiguredSecret` error.
    pub fn empty_configured_secret() -> Self {
        Self {
            kind: RedactionErrorKind::EmptyConfiguredSecret,
        }
    }

    /// Creates a `TooManyConfiguredSecrets` error.
    pub fn too_many_configured_secrets(count: usize, max: usize) -> Self {
        Self {
            kind: RedactionErrorKind::TooManyConfiguredSecrets { count, max },
        }
    }

    /// Creates a `ConfiguredSecretTooLong` error.
    pub fn configured_secret_too_long(length: usize, max: usize) -> Self {
        Self {
            kind: RedactionErrorKind::ConfiguredSecretTooLong { length, max },
        }
    }

    /// Creates an `InvalidSensitiveKey` error with the given detail.
    pub fn invalid_sensitive_key(detail: impl Into<String>) -> Self {
        Self {
            kind: RedactionErrorKind::InvalidSensitiveKey(detail.into()),
        }
    }

    /// Creates an `UnsupportedBinaryInput` error.
    pub fn unsupported_binary_input() -> Self {
        Self {
            kind: RedactionErrorKind::UnsupportedBinaryInput,
        }
    }

    /// Creates an `InternalPatternFailure` error with the given detail.
    pub fn internal_pattern_failure(detail: impl Into<String>) -> Self {
        Self {
            kind: RedactionErrorKind::InternalPatternFailure(detail.into()),
        }
    }
}

impl std::error::Error for RedactionError {}
