use regex::Regex;

use super::Detector;
use crate::types::{DetectorCategory, SecretMatch};

/// Detects AWS access key IDs (`AKIA`, `A3T`, `AGPA`, `AIDA`, etc. followed by 16 alphanumeric chars).
pub struct AwsKeyIdDetector {
    re: Regex,
}

#[allow(clippy::expect_used)]
impl Default for AwsKeyIdDetector {
    fn default() -> Self {
        Self {
            re: Regex::new(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
                .expect("valid AWS key ID regex"),
        }
    }
}

impl Detector for AwsKeyIdDetector {
    fn name(&self) -> &'static str {
        "aws_key_id"
    }

    fn detect(&self, input: &str) -> Vec<SecretMatch> {
        self.re
            .find_iter(input)
            .map(|m| SecretMatch::new(m.start(), m.end(), DetectorCategory::AwsKeyId))
            .collect()
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::AwsKeyId
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn aws_style_key_id_redacted() {
        let d = AwsKeyIdDetector::default();
        let input = "AKIAIOSFODNN7EXAMPLE";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn no_false_positive_short_prefix() {
        let d = AwsKeyIdDetector::default();
        let input = "AKIA is a prefix but not long enough";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }
}
