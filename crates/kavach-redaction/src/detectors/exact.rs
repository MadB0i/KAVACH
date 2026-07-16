use super::Detector;
use crate::types::{DetectorCategory, SecretContainer, SecretMatch};

/// Detects exact strings that have been configured via a [`SecretContainer`].
///
/// Matching uses longest-match-first ordering to resolve overlapping candidates.
pub struct ExactSecretDetector {
    container: SecretContainer,
}

impl ExactSecretDetector {
    /// Creates a detector backed by the given container.
    pub fn new(container: SecretContainer) -> Self {
        Self { container }
    }

    /// Returns a reference to the underlying container.
    pub fn container(&self) -> &SecretContainer {
        &self.container
    }
}

impl Detector for ExactSecretDetector {
    fn name(&self) -> &'static str {
        "exact_secret"
    }

    fn detect(&self, input: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();
        for secret in self.container.secrets_sorted_by_len() {
            let mut search_start = 0;
            while let Some(pos) = input[search_start..].find(secret) {
                let abs_pos = search_start + pos;
                matches.push(SecretMatch::new(
                    abs_pos,
                    abs_pos + secret.len(),
                    DetectorCategory::ConfiguredSecret,
                ));
                search_start = abs_pos + 1;
            }
        }
        matches
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::ConfiguredSecret
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::SecretContainer;

    #[test]
    fn configured_exact_secret_redacted() {
        let mut container = SecretContainer::new();
        container.add("my-secret-value".into()).unwrap();
        let d = ExactSecretDetector::new(container);
        let input = "prefix my-secret-value suffix";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "my-secret-value");
    }

    #[test]
    fn longest_overlapping_configured_secret_wins() {
        let mut container = SecretContainer::new();
        container.add("secret".into()).unwrap();
        container.add("my-secret-value".into()).unwrap();
        let d = ExactSecretDetector::new(container);
        let input = "before my-secret-value after";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn empty_configured_secret_rejected() {
        let mut container = SecretContainer::new();
        let result = container.add(String::new());
        assert!(result.is_err());
    }

    #[test]
    fn configured_secret_absent_leaves_input_unchanged() {
        let mut container = SecretContainer::new();
        container.add("secret1".into()).unwrap();
        let d = ExactSecretDetector::new(container);
        let input = "no secrets here";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn multiple_occurrences_redacted() {
        let mut container = SecretContainer::new();
        container.add("sekret".into()).unwrap();
        let d = ExactSecretDetector::new(container);
        let input = "sekret and another sekret";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 2);
    }
}
