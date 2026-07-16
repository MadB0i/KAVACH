use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use crate::ids::{RequestId, RuleId};

/// Strongly typed execution permit scope.
///
/// Each variant corresponds to a coarse-grained operation category. The runtime
/// issues the minimum scope required by the request, and the enforcement
/// adapter verifies that the permit's scope is sufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PermitScope {
    /// Reading a file (no mutation).
    FilesystemRead,
    /// Writing to an existing file.
    FilesystemWrite,
    /// Creating, deleting, or moving filesystem entries.
    FilesystemMutation,
    /// Low-risk command (informational, read-only).
    CommandLowRisk,
    /// Elevated command (modifies system state but not destructive).
    CommandElevated,
    /// Destructive command (rm -rf, dd, format, etc.).
    CommandDestructive,
    /// Outbound HTTP/HTTPS request.
    NetworkRequest,
}

/// A request-bound, single-use, time-limited execution permit.
///
/// # Security Properties
///
/// - **Request-bound**: Contains a digest of the original request; the permit
///   is valid only for that exact request.
/// - **Single-use**: Once consumed, the permit is marked as used and cannot
///   be reused.
/// - **Time-limited**: The permit expires after a configurable duration.
/// - **Unforgeable**: The permit carries a cryptographically random token
///   stored only as a SHA-256 hash; the actual 256-bit random value must be
///   presented at consumption time.
/// - **Scoped**: The permit carries a [`PermitScope`] that limits which
///   operations it authorises.
#[derive(Debug, Clone)]
pub struct ExecutionPermit {
    /// Opaque token (SHA-256 digest of the random permit secret).
    permit_token_hash: Vec<u8>,
    /// The request ID this permit is bound to.
    pub request_id: RequestId,
    /// The scope of operations this permit authorises.
    pub scope: PermitScope,
    /// IDs of the rules that matched to allow this operation.
    pub matched_rule_ids: Vec<RuleId>,
    /// When the permit was issued.
    pub issued_at: SystemTime,
    /// When the permit expires.
    pub expires_at: SystemTime,
    /// SHA-256 digest of the request this permit is bound to.
    pub request_digest: [u8; 32],
    /// Whether this permit has been consumed.
    pub consumed: bool,
}

impl ExecutionPermit {
    /// Create a new permit bound to a request digest, valid for the given
    /// duration and scope.
    ///
    /// The caller must store the `permit_secret` securely and present it at
    /// consumption time. The permit only stores a SHA-256 hash of the secret.
    pub fn new(
        permit_secret: &[u8],
        request_id: RequestId,
        scope: PermitScope,
        matched_rule_ids: Vec<RuleId>,
        request_digest: [u8; 32],
        ttl: Duration,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(permit_secret);
        let hash = hasher.finalize().to_vec();

        let now = SystemTime::now();
        Self {
            permit_token_hash: hash,
            request_id,
            scope,
            matched_rule_ids,
            issued_at: now,
            expires_at: now.checked_add(ttl).unwrap_or(now),
            request_digest,
            consumed: false,
        }
    }

    /// Verify that a presented secret matches this permit's stored token hash.
    /// Uses constant-time comparison.
    pub fn verify_secret(&self, secret: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        let hash = hasher.finalize();
        constant_time_eq::constant_time_eq(&hash, &self.permit_token_hash)
    }

    /// Whether the permit has expired.
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    /// Whether the permit has been consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Whether the permit is still valid (not expired and not consumed).
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_consumed()
    }

    /// Mark this permit as consumed. Returns `false` if already consumed.
    pub fn consume(&mut self) -> bool {
        if self.consumed {
            return false;
        }
        self.consumed = true;
        true
    }

    /// Re-verify that the permit's request digest matches the given digest.
    pub fn verify_request_digest(&self, digest: &[u8; 32]) -> bool {
        constant_time_eq::constant_time_eq(&self.request_digest, digest)
    }

    /// Borrow the permit token hash (SHA-256 of the secret).
    pub fn permit_token_hash(&self) -> &[u8] {
        &self.permit_token_hash
    }

    /// Borrow the issuance timestamp.
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// Borrow the expiry timestamp.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Borrow the request digest.
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    /// Reconstruct a permit from its serialised parts (used by the HTTP
    /// gateway when a client sends a permit back for execution).
    #[allow(clippy::too_many_arguments)]
    pub fn from_existing(
        permit_token_hash: Vec<u8>,
        request_id: crate::ids::RequestId,
        scope: PermitScope,
        matched_rule_ids: Vec<crate::ids::RuleId>,
        issued_at: SystemTime,
        expires_at: SystemTime,
        request_digest: [u8; 32],
        consumed: bool,
    ) -> Self {
        Self {
            permit_token_hash,
            request_id,
            scope,
            matched_rule_ids,
            issued_at,
            expires_at,
            request_digest,
            consumed,
        }
    }
}

/// Determine the minimum [`PermitScope`] required for the given operation.
pub fn required_scope(operation: &crate::request::Operation) -> PermitScope {
    use crate::request::Operation;
    match operation {
        Operation::FileRead { .. } => PermitScope::FilesystemRead,
        Operation::FileWrite => PermitScope::FilesystemWrite,
        Operation::FileCreate | Operation::FileDelete | Operation::FileMove { .. } => {
            PermitScope::FilesystemMutation
        }
        Operation::DirectoryList | Operation::DirectoryCreate | Operation::DirectoryDelete => {
            PermitScope::FilesystemMutation
        }
        Operation::CommandExecute => PermitScope::CommandLowRisk,
        Operation::NetworkRequest => PermitScope::NetworkRequest,
        Operation::SecretAccess | Operation::ToolInvoke { .. } => {
            // These operations have no dedicated adapter; assign the most
            // restrictive scope so any permit issued for them is unusable.
            PermitScope::FilesystemRead
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[allow(clippy::needless_pass_by_value)]
    fn make_req_id() -> crate::ids::RequestId {
        crate::ids::RequestId::new("permit-test").unwrap()
    }

    #[test]
    fn verify_secret_matches() {
        let secret = [42u8; 32];
        let permit = ExecutionPermit::new(
            &secret,
            make_req_id(),
            PermitScope::FilesystemRead,
            vec![],
            [0u8; 32],
            Duration::from_secs(300),
        );
        assert!(permit.verify_secret(&secret));
    }

    #[test]
    fn verify_secret_wrong() {
        let permit = ExecutionPermit::new(
            &[1u8; 32],
            make_req_id(),
            PermitScope::FilesystemRead,
            vec![],
            [0u8; 32],
            Duration::from_secs(300),
        );
        assert!(!permit.verify_secret(&[99u8; 32]));
    }

    #[test]
    fn permit_is_valid_initially() {
        let permit = ExecutionPermit::new(
            &[1u8; 32],
            make_req_id(),
            PermitScope::FilesystemRead,
            vec![],
            [0u8; 32],
            Duration::from_secs(300),
        );
        assert!(permit.is_valid());
        assert!(!permit.is_expired());
        assert!(!permit.is_consumed());
    }

    #[test]
    fn permit_single_use() {
        let mut permit = ExecutionPermit::new(
            &[1u8; 32],
            make_req_id(),
            PermitScope::FilesystemRead,
            vec![],
            [0u8; 32],
            Duration::from_secs(300),
        );
        assert!(permit.consume());
        assert!(!permit.consume());
        assert!(permit.is_consumed());
        assert!(!permit.is_valid());
    }

    #[test]
    fn permit_expires() {
        let permit = ExecutionPermit::new(
            &[1u8; 32],
            make_req_id(),
            PermitScope::FilesystemRead,
            vec![],
            [0u8; 32],
            Duration::from_secs(0),
        );
        assert!(permit.is_expired());
        assert!(!permit.is_valid());
    }

    #[test]
    fn permit_verify_request_digest() {
        let permit = ExecutionPermit::new(
            &[1u8; 32],
            make_req_id(),
            PermitScope::FilesystemRead,
            vec![],
            [42u8; 32],
            Duration::from_secs(300),
        );
        assert!(permit.verify_request_digest(&[42u8; 32]));
        assert!(!permit.verify_request_digest(&[99u8; 32]));
    }

    #[test]
    fn permit_scope_is_preserved() {
        let permit = ExecutionPermit::new(
            &[1u8; 32],
            make_req_id(),
            PermitScope::CommandDestructive,
            vec![],
            [0u8; 32],
            Duration::from_secs(300),
        );
        assert_eq!(permit.scope, PermitScope::CommandDestructive);
    }
}
