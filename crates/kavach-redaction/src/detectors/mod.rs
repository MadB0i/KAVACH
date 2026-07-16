use crate::types::{DetectorCategory, SecretMatch};

/// Internal trait implemented by every secret detector.
///
/// A [`Detector`] scans input text and returns zero or more
/// [`SecretMatch`] values indicating where secrets were found.
pub trait Detector: Send + Sync {
    /// Short, stable identifier for this detector (e.g. `"bearer_token"`).
    fn name(&self) -> &'static str;
    /// Scans `input` and returns all non-overlapping secret matches found.
    fn detect(&self, input: &str) -> Vec<SecretMatch>;
    /// The [`DetectorCategory`] assigned to every match produced by this detector.
    fn category(&self) -> DetectorCategory;
}

/// Detector for sensitive key–value assignments (e.g. `password=...`).
pub mod assignments;
/// Detector for AWS access key IDs.
pub mod aws;
/// Detector for `Bearer <token>` patterns.
pub mod bearer;
/// Detector for high-entropy strings (disabled by default).
pub mod entropy;
/// Detector for exact-match configured secrets.
pub mod exact;
/// Detector for GitHub-style tokens.
pub mod github;
/// Detector for JSON Web Tokens.
pub mod jwt;
/// Detector for PEM-encoded private keys.
pub mod pem;
