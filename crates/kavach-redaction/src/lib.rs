//! Deterministic, local-only secret detection and redaction.
//!
//! This crate provides a [`Redactor`] trait and a [`CompositeRedactor`] builder that
//! combines multiple content-matched detectors (bearer tokens, JWT, private keys,
//! sensitive key assignments, GitHub tokens, AWS key IDs, exact secrets, and
//! optional entropy-based detection) to find and replace secrets with stable
//! `[REDACTED:<category>]` markers.

/// Secret detector implementations and the [`Detector`](detectors::Detector) trait.
pub mod detectors;
/// Redaction error types.
pub mod error;
/// Convenience functions for redacting secrets from common data sources.
pub mod helpers;
/// The [`Redactor`] trait and [`CompositeRedactor`] builder.
pub mod redactor;
/// Shared types, constants, and result structures.
pub mod types;

pub use error::{RedactionError, RedactionErrorKind};
pub use redactor::{CompositeRedactor, CompositeRedactorBuilder, Redactor};
pub use types::{
    DetectorCategory, MAX_CONFIGURED_SECRET_LENGTH, MAX_CONFIGURED_SECRETS,
    MAX_ENTROPY_CANDIDATE_LENGTH, MAX_INPUT_BYTES, MAX_SENSITIVE_KEY_LENGTH,
    MAX_SENSITIVE_KEY_PATTERNS, MIN_ENTROPY_CANDIDATE_LENGTH, RedactionResult, SecretContainer,
    SecretMatch,
};

#[cfg(test)]
mod proptests;
