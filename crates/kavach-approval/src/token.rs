use std::fmt;

use constant_time_eq::constant_time_eq;
use sha2::{Digest, Sha256};

/// A cryptographically secure one-time approval token.
///
/// # Security Properties
///
/// - **256-bit entropy**: Generated using a CSPRNG.
/// - **Single-use**: The token can be consumed exactly once; the stored hash is
///   cleared on consumption.
/// - **Constant-time verification**: Token comparison uses
///   `constant_time_eq` to prevent timing side-channels.
/// - **Never logged**: `Debug` and `Display` reveal only that a token
///   exists, never the value.
/// - **Prevents accidental serialization**: No `Serialize` or
///   `Deserialize` implementation is provided.
#[derive(Clone)]
pub struct ApprovalToken {
    value: [u8; 32],
}

impl ApprovalToken {
    /// Generates a new random token using a CSPRNG.
    pub fn generate() -> Result<Self, crate::error::ApprovalError> {
        let mut value = [0u8; 32];
        getrandom::getrandom(&mut value).map_err(|e| {
            crate::error::ApprovalError::invalid_configuration(format!(
                "failed to generate random token: {e}"
            ))
        })?;
        Ok(Self { value })
    }

    /// Returns the SHA-256 hash of this token for storage.
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.value);
        hasher.finalize().to_vec()
    }

    /// Verifies a stored hash against this token in constant time.
    pub fn verify_hash(&self, stored_hash: &[u8]) -> bool {
        let computed = self.hash();
        constant_time_eq(&computed, stored_hash)
    }
}

impl fmt::Debug for ApprovalToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalToken").finish_non_exhaustive()
    }
}

impl fmt::Display for ApprovalToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalToken([redacted])")
    }
}
