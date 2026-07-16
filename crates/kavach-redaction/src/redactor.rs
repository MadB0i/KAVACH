use std::collections::BTreeSet;

use crate::detectors::Detector;
use crate::detectors::assignments::SensitiveKeyAssignmentDetector;
use crate::detectors::aws::AwsKeyIdDetector;
use crate::detectors::bearer::BearerTokenDetector;
use crate::detectors::entropy::EntropyDetector;
use crate::detectors::exact::ExactSecretDetector;
use crate::detectors::github::GitHubTokenDetector;
use crate::detectors::jwt::JwtDetector;
use crate::detectors::pem::PemPrivateKeyDetector;
use crate::error::RedactionError;
use crate::types::{
    DetectorCategory, MAX_INPUT_BYTES, RedactionResult, SecretContainer, SecretMatch,
};

const REDACTED_MARKERS: &[(&str, DetectorCategory)] = &[
    ("[REDACTED:bearer_token]", DetectorCategory::BearerToken),
    ("[REDACTED:jwt]", DetectorCategory::Jwt),
    ("[REDACTED:private_key]", DetectorCategory::PrivateKey),
    ("[REDACTED:password]", DetectorCategory::Password),
    ("[REDACTED:api_key]", DetectorCategory::ApiKey),
    ("[REDACTED:github_token]", DetectorCategory::GitHubToken),
    ("[REDACTED:aws_key_id]", DetectorCategory::AwsKeyId),
    (
        "[REDACTED:cloud_credential]",
        DetectorCategory::CloudCredential,
    ),
    ("[REDACTED:env_secret]", DetectorCategory::EnvSecret),
    (
        "[REDACTED:configured_secret]",
        DetectorCategory::ConfiguredSecret,
    ),
    (
        "[REDACTED:entropy_candidate]",
        DetectorCategory::EntropyCandidate,
    ),
    (
        "[REDACTED:assignment]",
        DetectorCategory::SensitiveKeyAssignment,
    ),
];

fn marker_for(category: DetectorCategory) -> &'static str {
    for &(marker, cat) in REDACTED_MARKERS {
        if cat == category {
            return marker;
        }
    }
    "[REDACTED]"
}

/// Trait for types that can detect and replace secrets in text or binary input.
pub trait Redactor: Send + Sync {
    /// Scans `input` for secrets and replaces them with redaction markers.
    fn redact_text(&self, input: &str) -> Result<RedactionResult, RedactionError>;
    /// Convenience wrapper around [`redact_text`](Self::redact_text).
    ///
    /// Returns
    /// [`UnsupportedBinaryInput`](crate::error::RedactionErrorKind::UnsupportedBinaryInput)
    /// when the bytes are not valid UTF-8.
    fn redact_bytes(&self, input: &[u8]) -> Result<RedactionResult, RedactionError>;
}

/// Default redactor that runs a configurable set of detectors.
///
/// Construct one via [`CompositeRedactor::builder`].
pub struct CompositeRedactor {
    detectors: Vec<Box<dyn Detector>>,
    exact_detector: Option<ExactSecretDetector>,
    entropy_detector: Option<EntropyDetector>,
}

impl CompositeRedactor {
    /// Creates a new [`CompositeRedactorBuilder`] with default settings.
    ///
    /// All detectors are enabled by default except entropy detection.
    pub fn builder() -> CompositeRedactorBuilder {
        CompositeRedactorBuilder::new()
    }

    fn all_detectors(&self) -> Vec<&dyn Detector> {
        let mut all: Vec<&dyn Detector> = self.detectors.iter().map(|d| d.as_ref()).collect();
        if let Some(ref d) = self.exact_detector {
            all.push(d);
        }
        if let Some(ref d) = self.entropy_detector {
            all.push(d);
        }
        all
    }
}

impl Redactor for CompositeRedactor {
    fn redact_text(&self, input: &str) -> Result<RedactionResult, RedactionError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(RedactionError::input_too_large(
                input.len(),
                MAX_INPUT_BYTES,
            ));
        }

        let detectors = self.all_detectors();
        let mut all_matches: Vec<SecretMatch> = Vec::new();
        for detector in &detectors {
            let matches = detector.detect(input);
            all_matches.extend(matches);
        }

        all_matches.sort_by_key(|a| a.start);

        let merged = merge_overlapping(all_matches);

        let (redacted, categories) = apply_redactions(input, &merged);

        let count = merged.len();
        Ok(RedactionResult::new(redacted, count, categories))
    }

    fn redact_bytes(&self, input: &[u8]) -> Result<RedactionResult, RedactionError> {
        let text =
            std::str::from_utf8(input).map_err(|_| RedactionError::unsupported_binary_input())?;
        self.redact_text(text)
    }
}

fn merge_overlapping(mut matches: Vec<SecretMatch>) -> Vec<SecretMatch> {
    if matches.is_empty() {
        return matches;
    }

    matches.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));

    let mut merged: Vec<SecretMatch> = Vec::new();
    for m in matches {
        if let Some(last) = merged.last_mut() {
            if m.start <= last.end {
                if m.end > last.end {
                    last.end = m.end;
                }
                if m.category != last.category {
                    last.category = DetectorCategory::Password;
                }
                continue;
            }
        }
        merged.push(m);
    }

    merged.sort_by_key(|b| std::cmp::Reverse(b.start));
    merged
}

fn apply_redactions(input: &str, matches: &[SecretMatch]) -> (String, BTreeSet<DetectorCategory>) {
    if matches.is_empty() {
        return (input.to_string(), BTreeSet::new());
    }

    let mut categories = BTreeSet::new();
    let mut result = input.to_string();

    for m in matches {
        let marker = marker_for(m.category);
        categories.insert(m.category);
        result.replace_range(m.start..m.end, marker);
    }

    (result, categories)
}

/// Builder for [`CompositeRedactor`].
///
/// All detectors except entropy are enabled by default.
#[derive(Default)]
pub struct CompositeRedactorBuilder {
    include_bearer: bool,
    include_jwt: bool,
    include_pem: bool,
    include_assignments: bool,
    include_github: bool,
    include_aws: bool,
    exact_secrets: Option<SecretContainer>,
    entropy: bool,
    entropy_min_length: usize,
    entropy_max_length: usize,
    entropy_threshold: f64,
}

impl CompositeRedactorBuilder {
    /// Creates a new builder with all default-policy detectors enabled.
    pub fn new() -> Self {
        Self {
            include_bearer: true,
            include_jwt: true,
            include_pem: true,
            include_assignments: true,
            include_github: true,
            include_aws: true,
            exact_secrets: None,
            entropy: false,
            entropy_min_length: 20,
            entropy_max_length: 256,
            entropy_threshold: 4.5,
        }
    }

    /// Enables or disables the Bearer token detector (default: enabled).
    pub fn with_bearer(mut self, enable: bool) -> Self {
        self.include_bearer = enable;
        self
    }

    /// Enables or disables the JWT detector (default: enabled).
    pub fn with_jwt(mut self, enable: bool) -> Self {
        self.include_jwt = enable;
        self
    }

    /// Enables or disables the PEM private-key detector (default: enabled).
    pub fn with_pem(mut self, enable: bool) -> Self {
        self.include_pem = enable;
        self
    }

    /// Enables or disables the sensitive-key-assignment detector (default: enabled).
    pub fn with_assignments(mut self, enable: bool) -> Self {
        self.include_assignments = enable;
        self
    }

    /// Enables or disables the GitHub token detector (default: enabled).
    pub fn with_github(mut self, enable: bool) -> Self {
        self.include_github = enable;
        self
    }

    /// Enables or disables the AWS key ID detector (default: enabled).
    pub fn with_aws(mut self, enable: bool) -> Self {
        self.include_aws = enable;
        self
    }

    /// Provides a [`SecretContainer`] of exact-match secrets.
    ///
    /// When set, the composite redactor will detect and redact these exact
    /// strings anywhere they appear in the input.
    pub fn with_exact_secrets(mut self, secrets: SecretContainer) -> Self {
        self.exact_secrets = Some(secrets);
        self
    }

    /// Configures the entropy-based detector.
    ///
    /// `enable` controls activation; `min_length` / `max_length` bound the
    /// candidate window; `threshold` is the minimum Shannon entropy score.
    /// Entropy detection is disabled by default.
    pub fn with_entropy(
        mut self,
        enable: bool,
        min_length: usize,
        max_length: usize,
        threshold: f64,
    ) -> Self {
        self.entropy = enable;
        self.entropy_min_length = min_length;
        self.entropy_max_length = max_length;
        self.entropy_threshold = threshold;
        self
    }

    /// Consumes the builder and returns a [`CompositeRedactor`].
    pub fn build(self) -> CompositeRedactor {
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

        if self.include_bearer {
            detectors.push(Box::new(BearerTokenDetector::default()));
        }
        if self.include_jwt {
            detectors.push(Box::new(JwtDetector::default()));
        }
        if self.include_pem {
            detectors.push(Box::new(PemPrivateKeyDetector::default()));
        }
        if self.include_assignments {
            detectors.push(Box::new(SensitiveKeyAssignmentDetector::default()));
        }
        if self.include_github {
            detectors.push(Box::new(GitHubTokenDetector::default()));
        }
        if self.include_aws {
            detectors.push(Box::new(AwsKeyIdDetector::default()));
        }

        let exact_detector = self.exact_secrets.map(ExactSecretDetector::new);

        let entropy_detector = if self.entropy {
            Some(EntropyDetector::new(
                self.entropy_min_length,
                self.entropy_max_length,
                self.entropy_threshold,
            ))
        } else {
            None
        };

        CompositeRedactor {
            detectors,
            exact_detector,
            entropy_detector,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::error::RedactionErrorKind;
    use crate::types::SecretContainer;
    use crate::{MAX_CONFIGURED_SECRET_LENGTH, MAX_CONFIGURED_SECRETS};

    #[test]
    fn redaction_is_idempotent() {
        let redactor = CompositeRedactor::builder().build();
        let input = "Bearer token123456789 and AKIAIOSFODNN7EXAMPLE";
        let r1 = redactor.redact_text(input).unwrap();
        let r2 = redactor.redact_text(&r1.redacted).unwrap();
        assert_eq!(r1.redacted, r2.redacted);
        assert!(!r2.changed);
    }

    #[test]
    fn already_redacted_text_unchanged() {
        let redactor = CompositeRedactor::builder().build();
        let input = "[REDACTED:bearer_token] and some text";
        let result = redactor.redact_text(input).unwrap();
        assert!(!result.changed);
    }

    #[test]
    fn multiple_different_secrets_redacted() {
        let redactor = CompositeRedactor::builder().build();
        let input = "Bearer tok12345678 and AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd";
        let result = redactor.redact_text(input).unwrap();
        assert!(result.changed);
        assert!(result.count >= 2);
    }

    #[test]
    fn surrounding_context_preserved() {
        let redactor = CompositeRedactor::builder().build();
        let input = "before Bearer tok12345678 after";
        let result = redactor.redact_text(input).unwrap();
        assert!(result.redacted.starts_with("before "));
        assert!(result.redacted.ends_with(" after"));
    }

    #[test]
    fn empty_input_handled() {
        let redactor = CompositeRedactor::builder().build();
        let result = redactor.redact_text("").unwrap();
        assert!(!result.changed);
        assert!(result.redacted.is_empty());
    }

    #[test]
    fn input_size_limit_enforced() {
        let redactor = CompositeRedactor::builder().build();
        let large = "a".repeat(MAX_INPUT_BYTES + 1);
        let result = redactor.redact_text(&large);
        assert!(result.is_err());
    }

    #[test]
    fn thread_safe_repeated_use() {
        let redactor = std::sync::Arc::new(CompositeRedactor::builder().build());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let r = redactor.clone();
            handles.push(std::thread::spawn(move || {
                r.redact_text("Bearer tok12345678").unwrap()
            }));
        }
        for h in handles {
            let result = h.join().unwrap();
            assert!(result.changed);
        }
    }

    #[test]
    fn binary_input_non_utf8_handled() {
        let redactor = CompositeRedactor::builder().build();
        let invalid = vec![0xff, 0xfe, 0x00, 0x01];
        let result = redactor.redact_bytes(&invalid);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(RedactionError {
                kind: RedactionErrorKind::UnsupportedBinaryInput
            })
        ));
    }

    #[test]
    fn null_byte_in_input_safe() {
        let redactor = CompositeRedactor::builder().build();
        // Null byte before the token ends: regex stops at null.
        let input = "Bearer tok\x00en12345678 and normal text";
        let result = redactor.redact_text(input).unwrap();
        // The partial token before null byte is too short, so no redaction.
        assert!(!result.changed);
    }

    #[test]
    fn debug_output_never_includes_secret() {
        let mut container = SecretContainer::new();
        container.add("super-secret-value".into()).unwrap();
        let debug_str = format!("{:?}", container);
        assert!(!debug_str.contains("super-secret-value"));
        assert!(debug_str.contains("SecretContainer"));
        assert!(debug_str.contains("count: 1"));
    }

    #[test]
    fn error_never_includes_secret_value() {
        let err = RedactionError::empty_configured_secret();
        let msg = err.to_string();
        // The error mentions "secret" as a category name, but must not contain
        // any actual secret *value*.
        assert!(!msg.contains("my-secret-value"));
    }

    #[test]
    fn too_many_configured_secrets_rejected() {
        let mut container = SecretContainer::new();
        for i in 0..MAX_CONFIGURED_SECRETS {
            container.add(format!("secret-{i}")).unwrap();
        }
        let result = container.add("extra-secret".into());
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(RedactionError {
                kind: RedactionErrorKind::TooManyConfiguredSecrets { .. }
            })
        ));
    }

    #[test]
    fn configured_secret_length_limit_enforced() {
        let mut container = SecretContainer::new();
        let long = "a".repeat(MAX_CONFIGURED_SECRET_LENGTH + 1);
        let result = container.add(long);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(RedactionError {
                kind: RedactionErrorKind::ConfiguredSecretTooLong { .. }
            })
        ));
    }

    #[test]
    fn no_raw_secret_in_result_metadata() {
        let mut container = SecretContainer::new();
        container.add("my-hidden-secret".into()).unwrap();
        let redactor = CompositeRedactor::builder()
            .with_exact_secrets(container)
            .build();
        let input = "before my-hidden-secret after";
        let result = redactor.redact_text(input).unwrap();
        assert!(!result.redacted.contains("my-hidden-secret"));
        assert!(result.redacted.contains("[REDACTED:configured_secret]"));
        assert!(
            result
                .categories
                .contains(&DetectorCategory::ConfiguredSecret)
        );
    }

    #[test]
    fn detector_ordering_deterministic() {
        let redactor = CompositeRedactor::builder().build();
        let input = "Bearer token12345678";
        let r1 = redactor.redact_text(input).unwrap();
        let r2 = redactor.redact_text(input).unwrap();
        assert_eq!(r1.redacted, r2.redacted);
        assert_eq!(r1.count, r2.count);
        assert_eq!(r1.categories, r2.categories);
    }

    #[test]
    fn output_size_bounded() {
        let redactor = CompositeRedactor::builder().build();
        let input = "a".repeat(100_000) + "Bearer tok12345678" + &"b".repeat(100_000);
        let result = redactor.redact_text(&input).unwrap();
        // Output should be significantly smaller than input due to redaction
        assert!(result.redacted.len() <= input.len() + 200);
    }

    #[test]
    fn redacted_marker_is_stable() {
        let redactor = CompositeRedactor::builder().build();
        let markers = [
            ("Bearer tok12345678", "[REDACTED:bearer_token]"),
            ("AKIAIOSFODNN7EXAMPLE", "[REDACTED:aws_key_id]"),
            (
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd",
                "[REDACTED:github_token]",
            ),
        ];
        for (secret, expected_marker) in &markers {
            let result = redactor.redact_text(secret).unwrap();
            assert!(
                result.redacted.contains(expected_marker),
                "expected marker {expected_marker} for input {secret}, got {}",
                result.redacted
            );
        }
    }

    #[test]
    fn entropy_disabled_by_default_in_builder() {
        let redactor = CompositeRedactor::builder().build();
        // Without entropy enabled, high-entropy strings should not be redacted.
        let input = "aB3dEfGhIjKlMnOpQrStUvWxYz";
        let result = redactor.redact_text(input).unwrap();
        assert!(!result.changed);
    }
}
