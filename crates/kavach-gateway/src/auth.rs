use sha2::{Digest, Sha256};

/// A 256-bit bearer token for API authentication.
///
/// Production startup accepts an operator-supplied 64-hex token and stores
/// only its SHA-256 hash for verification. The raw token is never persisted.
#[derive(Clone)]
pub struct GatewayToken {
    /// SHA-256 hash of the raw token.
    token_hash: [u8; 32],
}

impl GatewayToken {
    /// Generate a new random token.  Panics if the OS RNG fails.
    pub fn generate() -> (Self, String) {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).expect("OS RNG failure during gateway token generation");
        let token_hex = hex::encode(raw);
        let token_hash = {
            let mut hasher = Sha256::new();
            hasher.update(raw);
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        };
        (Self { token_hash }, token_hex)
    }

    /// Create from a pre-computed SHA-256 hash (e.g. from config).
    pub fn from_hash(hash: [u8; 32]) -> Self {
        Self { token_hash: hash }
    }

    /// Return the stored SHA-256 hash bytes.
    pub fn hash(&self) -> [u8; 32] {
        self.token_hash
    }

    /// Verify a raw token hex string against the stored hash.
    /// Uses constant-time comparison.
    pub fn verify(&self, token_hex: &str) -> bool {
        if token_hex.len() != 64 || !token_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
        let raw = match hex::decode(token_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if raw.len() != 32 {
            return false;
        }
        let mut hasher = Sha256::new();
        hasher.update(&raw);
        let computed = hasher.finalize();
        constant_time_eq::constant_time_eq(&computed, &self.token_hash)
    }
}

impl std::fmt::Debug for GatewayToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayToken")
            .field("token_hash", &"<redacted>")
            .finish()
    }
}
