use regex::Regex;

use super::Detector;
use crate::types::{DetectorCategory, SecretMatch};

/// Detects three-dot-segmented base64url tokens that resemble JWTs.
///
/// Avoids matching version strings (e.g. `1.2.3`) and short filenames
/// (e.g. `file.tar.gz`).
pub struct JwtDetector {
    re: Regex,
}

#[allow(clippy::expect_used)]
impl Default for JwtDetector {
    fn default() -> Self {
        Self {
            re: Regex::new(r"[A-Za-z0-9\-_]{4,64}\.[A-Za-z0-9\-_]{4,256}\.[A-Za-z0-9\-_]{4,512}")
                .expect("valid JWT regex"),
        }
    }
}

impl Detector for JwtDetector {
    fn name(&self) -> &'static str {
        "jwt"
    }

    fn detect(&self, input: &str) -> Vec<SecretMatch> {
        self.re
            .find_iter(input)
            .filter(|m| {
                let s = m.as_str();
                let parts: Vec<&str> = s.split('.').collect();
                if parts.len() != 3 {
                    return false;
                }
                if parts.iter().any(|p| p.is_empty()) {
                    return false;
                }
                !is_likely_version(s) && !is_likely_filename(s)
            })
            .map(|m| SecretMatch::new(m.start(), m.end(), DetectorCategory::Jwt))
            .collect()
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::Jwt
    }
}

fn is_likely_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 2 && parts[0].len() <= 3 && parts[0].chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    if parts.len() >= 2
        && parts
            .iter()
            .all(|p| p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
    {
        return true;
    }
    false
}

fn is_likely_filename(s: &str) -> bool {
    s.len() < 20 && s.chars().filter(|&c| c == '.').count() >= 2
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn jwt_like_token_redacted() {
        let d = JwtDetector::default();
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let input = format!("token={token}");
        let matches = d.detect(&input);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn ordinary_dotted_text_not_jwt() {
        let d = JwtDetector::default();
        let inputs = [
            "version 1.2.3",
            "file.tar.gz",
            "hello.world",
            "a.b.c",
            "v1.2.3",
        ];
        for input in &inputs {
            let matches = d.detect(input);
            assert!(matches.is_empty(), "unexpected match for: {input}");
        }
    }

    #[test]
    fn short_jwt_not_matched() {
        let d = JwtDetector::default();
        let input = "a.b.c";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }
}
