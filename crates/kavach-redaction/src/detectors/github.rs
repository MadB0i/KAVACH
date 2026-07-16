use regex::Regex;

use super::Detector;
use crate::types::{DetectorCategory, SecretMatch};

/// Detects GitHub-style tokens with `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` prefixes.
pub struct GitHubTokenDetector {
    re: Regex,
}

#[allow(clippy::expect_used)]
impl Default for GitHubTokenDetector {
    fn default() -> Self {
        Self {
            re: Regex::new(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,40}")
                .expect("valid GitHub token regex"),
        }
    }
}

impl Detector for GitHubTokenDetector {
    fn name(&self) -> &'static str {
        "github_token"
    }

    fn detect(&self, input: &str) -> Vec<SecretMatch> {
        self.re
            .find_iter(input)
            .map(|m| SecretMatch::new(m.start(), m.end(), DetectorCategory::GitHubToken))
            .collect()
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::GitHubToken
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn github_style_token_redacted() {
        let d = GitHubTokenDetector::default();
        let input = "ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn no_false_positive_on_normal_text() {
        let d = GitHubTokenDetector::default();
        let input = "just some text with ghp_ but not enough";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }
}
