use regex::Regex;

use super::Detector;
use crate::types::{DetectorCategory, SecretMatch};

const PEM_PATTERNS: &[&str] = &[
    r"-----BEGIN RSA PRIVATE KEY-----\s*[\s\S]*?-----END RSA PRIVATE KEY-----",
    r"-----BEGIN EC PRIVATE KEY-----\s*[\s\S]*?-----END EC PRIVATE KEY-----",
    r"-----BEGIN OPENSSH PRIVATE KEY-----\s*[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
    r"-----BEGIN PRIVATE KEY-----\s*[\s\S]*?-----END PRIVATE KEY-----",
    r"-----BEGIN DSA PRIVATE KEY-----\s*[\s\S]*?-----END DSA PRIVATE KEY-----",
];

#[allow(clippy::expect_used)]
fn build_pem_regex() -> Regex {
    let pattern = PEM_PATTERNS.join("|");
    Regex::new(&pattern).expect("valid PEM regex")
}

/// Detects complete PEM-encoded private key blocks (RSA, EC, OpenSSH, DSA, generic).
///
/// Unterminated blocks (missing `-----END ...-----`) are not matched.
pub struct PemPrivateKeyDetector {
    re: Regex,
}

impl Default for PemPrivateKeyDetector {
    fn default() -> Self {
        Self {
            re: build_pem_regex(),
        }
    }
}

impl Detector for PemPrivateKeyDetector {
    fn name(&self) -> &'static str {
        "private_key"
    }

    fn detect(&self, input: &str) -> Vec<SecretMatch> {
        self.re
            .find_iter(input)
            .map(|m| SecretMatch::new(m.start(), m.end(), DetectorCategory::PrivateKey))
            .collect()
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::PrivateKey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_private_key_block_fully_redacted() {
        let d = PemPrivateKeyDetector::default();
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0+OSlK4Q6+Oa\n-----END RSA PRIVATE KEY-----";
        let matches = d.detect(pem);
        assert_eq!(matches.len(), 1);
        let m = &matches[0];
        assert_eq!(m.start, 0);
        assert_eq!(m.end, pem.len());
    }

    #[test]
    fn openssh_private_key_fully_redacted() {
        let d = PemPrivateKeyDetector::default();
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";
        let matches = d.detect(pem);
        assert_eq!(matches.len(), 1);
        let m = &matches[0];
        assert_eq!(m.start, 0);
        assert_eq!(m.end, pem.len());
    }

    #[test]
    fn ec_private_key_redacted() {
        let d = PemPrivateKeyDetector::default();
        let pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIIm3V2U=\n-----END EC PRIVATE KEY-----";
        let matches = d.detect(pem);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn no_key_in_regular_text() {
        let d = PemPrivateKeyDetector::default();
        let input = "This is just plain text with no keys.";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn unterminated_block_not_matched() {
        let d = PemPrivateKeyDetector::default();
        let input = "-----BEGIN RSA PRIVATE KEY-----\nsome content without end marker";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }
}
