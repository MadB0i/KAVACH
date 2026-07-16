use std::fmt;

use sha2::{Digest, Sha256};

const GENESIS_PHRASE: &[u8] = b"kavach-audit-genesis-v1";

/// A validated 32-byte SHA-256 hash value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HashValue([u8; 32]);

impl HashValue {
    /// Creates a `HashValue` from the raw 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes `SHA-256(previous || canonical)`.
    pub fn compute(previous: &HashValue, canonical: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(previous.as_bytes());
        hasher.update(canonical);
        Self(hasher.finalize().into())
    }

    /// Returns the genesis hash: `SHA-256("kavach-audit-genesis-v1")`.
    pub fn genesis() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(GENESIS_PHRASE);
        Self(hasher.finalize().into())
    }
}

impl fmt::Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HashValue({})", hex::encode(self.0))
    }
}

impl fmt::Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hash_is_deterministic() {
        let a = HashValue::genesis();
        let b = HashValue::genesis();
        assert_eq!(a, b);
    }

    #[test]
    fn hash_chain_is_deterministic() {
        let genesis = HashValue::genesis();
        let h1 = HashValue::compute(&genesis, b"event-1");
        let h2 = HashValue::compute(&genesis, b"event-1");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_input_produces_different_hash() {
        let genesis = HashValue::genesis();
        let h1 = HashValue::compute(&genesis, b"event-1");
        let h2 = HashValue::compute(&genesis, b"event-2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_is_32_bytes() {
        let genesis = HashValue::genesis();
        assert_eq!(genesis.as_bytes().len(), 32);
    }

    #[test]
    fn display_is_hex_encoded() {
        let h = HashValue::genesis();
        let s = h.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
