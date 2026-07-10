//! Domain validation errors for KAVACH core contracts.
//!
//! These errors are produced while constructing or validating the strongly
//! typed core domain models. They are intentionally narrow: each variant names
//! exactly what failed validation, so callers can surface actionable messages
//! without inspecting unrelated error state.

use std::fmt;

/// A category of domain validation failure.
///
/// Stable machine-readable category used by [`DomainError`]. Variants are kept
/// narrow so that callers can react to specific failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainErrorKind {
    /// An identifier was empty, too long, or contained control characters.
    InvalidId,
    /// A string field exceeded its documented maximum length.
    OversizedField,
    /// Input contained bytes that are not permitted in the target context
    /// (for example null bytes in paths).
    InvalidCharacter,
    /// A strongly typed value could not be constructed from its input.
    InvalidValue,
    /// A map or collection exceeded its documented maximum entry count.
    OversizedCollection,
    /// An enum variant received an unknown or unsupported label.
    UnknownVariant,
    /// A required field was missing.
    Missing,
}

/// Error originating from core domain model validation.
///
/// All public constructors of core newtypes and enums return [`Result`] with
/// this error type instead of panicking or returning a raw string. The error
/// carries a stable kind and a context string; it never carries secret values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct DomainError {
    kind: DomainErrorKind,
    context: String,
}

impl DomainError {
    /// Create a new domain error from a kind and a non-secret context string.
    pub fn new(kind: DomainErrorKind, context: impl fmt::Display) -> Self {
        Self { kind, context: context.to_string() }
    }

    /// Returns the stable error category.
    pub fn kind(&self) -> DomainErrorKind {
        self.kind
    }

    /// Returns a non-secret, human-readable context string describing what was
    /// being validated when the error occurred.
    pub fn context(&self) -> &str {
        &self.context
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.context)
    }
}
