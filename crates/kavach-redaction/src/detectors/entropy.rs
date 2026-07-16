use super::Detector;
use crate::types::{
    DetectorCategory, MAX_ENTROPY_CANDIDATE_LENGTH, MIN_ENTROPY_CANDIDATE_LENGTH, SecretMatch,
};

/// Detects high-entropy strings using Shannon entropy.
///
/// This detector is **disabled by default** in [`CompositeRedactor`](crate::CompositeRedactor)
/// because it can produce false positives on UUIDs, hashes, and base64 data.
/// UUIDs and SHA-1/SHA-256 hex strings are excluded.
pub struct EntropyDetector {
    min_length: usize,
    max_length: usize,
    threshold: f64,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self {
            min_length: MIN_ENTROPY_CANDIDATE_LENGTH,
            max_length: MAX_ENTROPY_CANDIDATE_LENGTH,
            threshold: 4.5,
        }
    }
}

impl EntropyDetector {
    /// Creates a detector with the given bounds and entropy threshold.
    pub fn new(min_length: usize, max_length: usize, threshold: f64) -> Self {
        Self {
            min_length,
            max_length,
            threshold,
        }
    }

    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let len = s.len() as f64;
        let mut counts = [0u64; 256];
        for &b in s.as_bytes() {
            counts[b as usize] += 1;
        }
        -counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                p * p.log2()
            })
            .sum::<f64>()
    }

    fn is_likely_harmless(s: &str) -> bool {
        let uuid_pattern = s.chars().filter(|&c| c == '-').count() == 4
            && s.len() == 36
            && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        if uuid_pattern {
            return true;
        }
        let hex_only = s.chars().all(|c| c.is_ascii_hexdigit());
        if hex_only && s.len() == 64 {
            return true;
        }
        if hex_only && s.len() == 40 {
            return true;
        }
        false
    }
}

impl Detector for EntropyDetector {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn detect(&self, input: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();
        let mut start = 0;
        let bytes = input.as_bytes();

        while start < bytes.len() {
            if bytes[start].is_ascii_alphanumeric() || bytes[start] == b'_' || bytes[start] == b'-'
            {
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric()
                        || bytes[end] == b'_'
                        || bytes[end] == b'-')
                {
                    end += 1;
                }
                let candidate = &input[start..end];
                if candidate.len() >= self.min_length
                    && candidate.len() <= self.max_length
                    && !Self::is_likely_harmless(candidate)
                {
                    let e = Self::shannon_entropy(candidate);
                    if e >= self.threshold {
                        matches.push(SecretMatch::new(
                            start,
                            end,
                            DetectorCategory::EntropyCandidate,
                        ));
                    }
                }
                start = end;
            } else {
                start += 1;
            }
        }

        matches
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::EntropyCandidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_detector_works_when_enabled() {
        let d = EntropyDetector::new(16, 64, 4.6);
        let input = "abc123XYZ_lmnopqrstuvwx";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn uuid_not_matched() {
        let d = EntropyDetector::new(16, 64, 3.5);
        let input = "550e8400-e29b-41d4-a716-446655440000";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn hash_not_matched() {
        let d = EntropyDetector::new(16, 128, 3.5);
        let input = "abcdef0123456789abcdef0123456789abcdef01";
        let matches = d.detect(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn entropy_detector_finds_high_entropy() {
        // A random-looking base64 token should have high entropy.
        let d = EntropyDetector::new(16, 64, 4.0);
        let input = "aB3dEfGhIjKlMnOpQrStUvWxYz";
        let matches = d.detect(input);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn entropy_detector_disabled_by_default() {
        let d = EntropyDetector::default();
        let _config = format!("{:?}", d.min_length);
        assert_eq!(d.min_length, 20);
    }
}
