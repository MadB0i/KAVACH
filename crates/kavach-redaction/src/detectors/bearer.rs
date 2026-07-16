use regex::Regex;

use super::Detector;
use crate::types::{DetectorCategory, SecretMatch};

/// Detects `Bearer <token>` patterns where the token is at least 8 characters.
pub struct BearerTokenDetector {
    re: Regex,
}

#[allow(clippy::expect_used)]
impl Default for BearerTokenDetector {
    fn default() -> Self {
        Self {
            re: Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*\b").expect("valid bearer regex"),
        }
    }
}

impl Detector for BearerTokenDetector {
    fn name(&self) -> &'static str {
        "bearer_token"
    }

    fn detect(&self, input: &str) -> Vec<SecretMatch> {
        self.re
            .find_iter(input)
            .filter(|m| {
                let token = m.as_str();
                let after_prefix = if let Some(idx) = token.find(|c: char| c.is_whitespace()) {
                    token[idx..].trim_start()
                } else {
                    ""
                };
                after_prefix.len() >= 8
            })
            .map(|m| SecretMatch::new(m.start(), m.end(), DetectorCategory::BearerToken))
            .collect()
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::BearerToken
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_redacted() {
        let d = BearerTokenDetector::default();
        let input = "Authorization: Bearer abc123def456ghi789";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "Bearer abc123def456ghi789"
        );
    }

    #[test]
    fn short_bearer_not_matched() {
        let d = BearerTokenDetector::default();
        let input = "Bearer ab";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn multiple_bearer_tokens() {
        let d = BearerTokenDetector::default();
        let input = "first Bearer token1234567 second Bearer token8901234";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 2);
    }
}
