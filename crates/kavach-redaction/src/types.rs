use std::collections::BTreeSet;
use std::fmt;

use crate::error::RedactionError;

/// Maximum number of bytes accepted by
/// [`Redactor::redact_text`](crate::redactor::Redactor::redact_text) and
/// [`Redactor::redact_bytes`](crate::redactor::Redactor::redact_bytes).
pub const MAX_INPUT_BYTES: usize = 1_048_576;

/// Maximum number of secrets that can be added to a [`SecretContainer`].
pub const MAX_CONFIGURED_SECRETS: usize = 1000;

/// Maximum byte length of a single configured secret.
pub const MAX_CONFIGURED_SECRET_LENGTH: usize = 1024;

/// Maximum number of sensitive key patterns in
/// [`SensitiveKeyAssignmentDetector`](crate::detectors::assignments::SensitiveKeyAssignmentDetector).
pub const MAX_SENSITIVE_KEY_PATTERNS: usize = 100;

/// Maximum byte length of a single sensitive key pattern.
pub const MAX_SENSITIVE_KEY_LENGTH: usize = 128;

/// Minimum candidate length for entropy-based detection.
pub const MIN_ENTROPY_CANDIDATE_LENGTH: usize = 20;

/// Maximum candidate length for entropy-based detection.
pub const MAX_ENTROPY_CANDIDATE_LENGTH: usize = 256;

/// Classification of a detected secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DetectorCategory {
    /// `Bearer`-prefixed authorization token.
    BearerToken,
    /// JSON Web Token (three-dot-segmented base64url).
    Jwt,
    /// PEM-encoded private key (RSA, EC, DSA, OpenSSH, or generic).
    PrivateKey,
    /// Password or passphrase value in a key–value assignment.
    Password,
    /// Generic API key in a key–value assignment.
    ApiKey,
    /// GitHub-style token (`ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` prefix).
    GitHubToken,
    /// AWS access key ID (`AKIA`, `A3T`, etc.).
    AwsKeyId,
    /// Cloud provider credential (generic fallback).
    CloudCredential,
    /// Environment-level secret (generic fallback).
    EnvSecret,
    /// Secret added via [`SecretContainer`].
    ConfiguredSecret,
    /// High-entropy string flagged by the entropy detector.
    EntropyCandidate,
    /// Value assigned to a known sensitive key (e.g. `password=...`).
    SensitiveKeyAssignment,
}

impl fmt::Display for DetectorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectorCategory::BearerToken => write!(f, "bearer_token"),
            DetectorCategory::Jwt => write!(f, "jwt"),
            DetectorCategory::PrivateKey => write!(f, "private_key"),
            DetectorCategory::Password => write!(f, "password"),
            DetectorCategory::ApiKey => write!(f, "api_key"),
            DetectorCategory::GitHubToken => write!(f, "github_token"),
            DetectorCategory::AwsKeyId => write!(f, "aws_key_id"),
            DetectorCategory::CloudCredential => write!(f, "cloud_credential"),
            DetectorCategory::EnvSecret => write!(f, "env_secret"),
            DetectorCategory::ConfiguredSecret => write!(f, "configured_secret"),
            DetectorCategory::EntropyCandidate => write!(f, "entropy_candidate"),
            DetectorCategory::SensitiveKeyAssignment => write!(f, "sensitive_key_assignment"),
        }
    }
}

/// A single match produced by a detector.
///
/// Specifies the byte range within the input and the category of the detected secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    /// Inclusive byte offset of the start of the match.
    pub start: usize,
    /// Exclusive byte offset of the end of the match.
    pub end: usize,
    /// Category of the detected secret.
    pub category: DetectorCategory,
}

impl SecretMatch {
    /// Creates a new match spanning byte offsets `start..end`.
    pub fn new(start: usize, end: usize, category: DetectorCategory) -> Self {
        Self {
            start,
            end,
            category,
        }
    }

    /// Length of the match in bytes.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` when the match is empty (start >= end).
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// Outcome of a single redaction operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    /// The text after all detected secrets have been replaced with markers.
    pub redacted: String,
    /// Number of distinct secrets that were replaced.
    pub count: usize,
    /// Unique categories among all replaced secrets.
    pub categories: BTreeSet<DetectorCategory>,
    /// Whether any replacement was performed.
    pub changed: bool,
}

impl RedactionResult {
    /// Creates a result indicating that no secrets were found in `input`.
    ///
    /// The `redacted` field is a copy of the original input.
    pub fn unchanged(input: &str) -> Self {
        Self {
            redacted: input.to_string(),
            count: 0,
            categories: BTreeSet::new(),
            changed: false,
        }
    }

    /// Creates a result with a redacted output and the given match metadata.
    pub fn new(redacted: String, count: usize, categories: BTreeSet<DetectorCategory>) -> Self {
        let changed = count > 0;
        Self {
            redacted,
            count,
            categories,
            changed,
        }
    }
}

/// A collection of exact string secrets to detect and redact.
///
/// Secrets are stored sorted longest-first, so that overlapping candidates
/// are resolved in favour of the longer match.  [`Debug`] prints only the
/// count of stored secrets — values are never revealed.
pub struct SecretContainer {
    secrets: Vec<String>,
    sorted_by_len: Vec<String>,
}

impl fmt::Debug for SecretContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretContainer")
            .field("count", &self.secrets.len())
            .finish()
    }
}

impl SecretContainer {
    /// Creates an empty container.
    pub fn new() -> Self {
        Self {
            secrets: Vec::new(),
            sorted_by_len: Vec::new(),
        }
    }

    /// Adds a secret to the container.
    ///
    /// Returns an error if the secret is empty, exceeds
    /// [`MAX_CONFIGURED_SECRET_LENGTH`], or the container already holds
    /// [`MAX_CONFIGURED_SECRETS`] entries.  Duplicates are silently ignored.
    pub fn add(&mut self, secret: String) -> Result<(), RedactionError> {
        if secret.is_empty() {
            return Err(RedactionError::empty_configured_secret());
        }
        if secret.len() > MAX_CONFIGURED_SECRET_LENGTH {
            return Err(RedactionError::configured_secret_too_long(
                secret.len(),
                MAX_CONFIGURED_SECRET_LENGTH,
            ));
        }
        if self.secrets.len() >= MAX_CONFIGURED_SECRETS {
            return Err(RedactionError::too_many_configured_secrets(
                self.secrets.len() + 1,
                MAX_CONFIGURED_SECRETS,
            ));
        }
        if !self.secrets.contains(&secret) {
            self.secrets.push(secret);
        }
        self.resort();
        Ok(())
    }

    /// Adds all secrets from an iterator, returning the first error if any.
    pub fn add_all(&mut self, secrets: Vec<String>) -> Result<(), RedactionError> {
        for s in secrets {
            self.add(s)?;
        }
        Ok(())
    }

    fn resort(&mut self) {
        self.sorted_by_len = self.secrets.clone();
        self.sorted_by_len
            .sort_by_key(|b| std::cmp::Reverse(b.len()));
    }

    /// Returns the number of stored secrets.
    pub fn count(&self) -> usize {
        self.secrets.len()
    }

    /// Returns `true` when no secrets have been added.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    pub(crate) fn secrets_sorted_by_len(&self) -> &[String] {
        &self.sorted_by_len
    }
}

impl Default for SecretContainer {
    fn default() -> Self {
        Self::new()
    }
}
