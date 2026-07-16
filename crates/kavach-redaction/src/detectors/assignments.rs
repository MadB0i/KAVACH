use regex::Regex;

use super::Detector;
use crate::types::{DetectorCategory, SecretMatch};

const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "api[_-]?key",
    "apikey",
    "token",
    "auth_token",
    "access_key",
    "secret_key",
    "private_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "azure_client_id",
    "azure_client_secret",
    "google_api_key",
    "gcp_service_account",
    "db_password",
    "db_url",
    "connection_string",
    "github_token",
    "gitlab_token",
    "slack_token",
    "discord_token",
    "stripe_api_key",
    "stripe_secret",
    "twilio_auth",
    "sendgrid_api",
    "openai_api_key",
    "anthropic_api_key",
];

/// Detects values assigned to known sensitive keys (e.g. `password=...`, `api_key = ...`).
///
/// The detector is case-insensitive and matches the value portion only
/// (the part after `=` or `:`).  Word boundaries prevent false positives
/// from words that merely _contain_ a sensitive keyword.
pub struct SensitiveKeyAssignmentDetector {
    re: Regex,
}

fn build_assignment_pattern() -> String {
    let keys = SENSITIVE_KEYS.join("|");
    format!(r#"(?i)\b(?:{keys})\b\s*[=:]\s*(?:'([^']*)'|([^\s'"":;)}}]+))"#)
}

#[allow(clippy::expect_used)]
fn build_regex() -> Regex {
    Regex::new(&build_assignment_pattern()).expect("valid assignment regex")
}

impl Default for SensitiveKeyAssignmentDetector {
    fn default() -> Self {
        Self { re: build_regex() }
    }
}

impl Detector for SensitiveKeyAssignmentDetector {
    fn name(&self) -> &'static str {
        "sensitive_key_assignment"
    }

    fn detect(&self, input: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();
        for cap in self.re.captures_iter(input) {
            let m = match cap.get(0) {
                Some(m) => m,
                None => continue,
            };
            let full_text = m.as_str();
            let eq_or_colon = full_text.find(['=', ':']);
            if let Some(pos) = eq_or_colon {
                let value_start = m.start() + pos + 1;
                matches.push(SecretMatch::new(
                    value_start,
                    m.end(),
                    DetectorCategory::SensitiveKeyAssignment,
                ));
            }
        }
        matches
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::SensitiveKeyAssignment
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn password_assignment_redacted() {
        let d = SensitiveKeyAssignmentDetector::default();
        let input = "password=supersecret123";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn api_key_assignment_redacted() {
        let d = SensitiveKeyAssignmentDetector::default();
        let input = "api_key = my-secret-api-key-value";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn quoted_assignment_redacted() {
        let d = SensitiveKeyAssignmentDetector::default();
        let input = "TOKEN=ghp_abc123def456";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn harmless_word_containing_token_unchanged() {
        let d = SensitiveKeyAssignmentDetector::default();
        let inputs = [
            "tokenization is a process",
            "my_tokenizer.py",
            "tokenize this text",
        ];
        for input in &inputs {
            let matches = d.detect(input);
            assert!(matches.is_empty(), "unexpected match for: {input}");
        }
    }

    #[test]
    fn harmless_key_value_pair_unchanged() {
        let d = SensitiveKeyAssignmentDetector::default();
        let input = "name=John";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn case_insensitive_key_detection() {
        let d = SensitiveKeyAssignmentDetector::default();
        let input = "PASSWORD=abc123";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn colon_assignment_detected() {
        let d = SensitiveKeyAssignmentDetector::default();
        let input = "password: qwerty123";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
    }
}
