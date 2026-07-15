//! KAVACH runtime guard and execution permit contracts.
//!
//! The runtime layer connects validation, policy evaluation, and enforcement.
//! A [`Guard`] evaluates a [`ToolRequest`](kavach_core::request::ToolRequest) and returns a [`GuardOutcome`]:
//! either [`Denied`](GuardOutcome::Denied),
//! [`ApprovalRequired`](GuardOutcome::ApprovalRequired), or
//! [`Permitted`](GuardOutcome::Permitted) with an [`ExecutionPermit`].
//!
//! Execution permits are single-use, request-bound, time-limited, and
//! cryptographically unforgeable tokens that must be presented to enforcement
//! adapters before any operation is executed.

use std::time::{Duration, SystemTime};

use kavach_core::ids::RuleId;

/// Errors that can arise during guard evaluation.
#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    /// The request failed validation.
    #[error("request validation failed: {0}")]
    InvalidRequest(String),
    /// The guard encountered an internal error.
    #[error("internal guard error: {0}")]
    Internal(String),
}

/// Outcome of a guard evaluation.
#[derive(Debug, Clone)]
pub enum GuardOutcome {
    /// The request is explicitly denied.
    Denied {
        /// Reason code from the policy engine.
        reason: String,
        /// Matched rule IDs that caused the denial.
        matched_rule_ids: Vec<RuleId>,
    },
    /// The request requires human approval before execution.
    ApprovalRequired {
        /// Reason from the policy engine.
        reason: String,
        /// Matched rule IDs that triggered the approval requirement.
        matched_rule_ids: Vec<RuleId>,
    },
    /// The request is permitted — an [`ExecutionPermit`] is issued.
    Permitted(ExecutionPermit),
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
#[derive(Debug, Clone)]
pub struct ExecutionPermit {
    /// Opaque token (SHA-256 digest of the random permit secret).
    permit_token_hash: Vec<u8>,
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
    /// Create a new permit bound to a request digest, valid for the given duration.
    ///
    /// The caller must store the `permit_secret` securely and present it at
    /// consumption time. The permit only stores a SHA-256 hash of the secret.
    pub fn new(
        permit_secret: &[u8],
        matched_rule_ids: Vec<RuleId>,
        request_digest: [u8; 32],
        ttl: Duration,
    ) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(permit_secret);
        let hash = hasher.finalize().to_vec();

        let now = SystemTime::now();
        Self {
            permit_token_hash: hash,
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
        use sha2::{Digest, Sha256};
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
}

/// Compute a SHA-256 digest of a request for permit binding.
pub fn compute_request_digest(request: &kavach_core::request::ToolRequest) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let json = serde_json::to_string(request).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

/// The central guard trait. Evaluates a request and returns a decision.
pub trait Guard {
    /// Evaluate a request. Returns a [`GuardOutcome`].
    fn evaluate(
        &self,
        request: &kavach_core::request::ToolRequest,
    ) -> Result<GuardOutcome, GuardError>;
}

/// A guard backed by the KAVACH policy engine.
pub struct PolicyGuard {
    engine: kavach_policy::PolicyEngine,
    permit_ttl: Duration,
}

impl PolicyGuard {
    /// Create a new policy guard with the given policies and permit TTL.
    pub fn new(
        policies: Vec<kavach_policy::Policy>,
        permit_ttl: Duration,
    ) -> Result<Self, kavach_policy::PolicyValidationError> {
        let engine = kavach_policy::PolicyEngine::new(policies)?;
        Ok(Self { engine, permit_ttl })
    }
}

impl Guard for PolicyGuard {
    fn evaluate(
        &self,
        request: &kavach_core::request::ToolRequest,
    ) -> Result<GuardOutcome, GuardError> {
        let decision = self.engine.evaluate(request);

        let matched: Vec<RuleId> = decision.matched_rule_ids.into_iter().collect();
        let reason = decision.explanation.clone();

        match decision.effect {
            kavach_core::DecisionEffect::Deny => Ok(GuardOutcome::Denied {
                reason,
                matched_rule_ids: matched,
            }),
            kavach_core::DecisionEffect::RequireApproval => Ok(GuardOutcome::ApprovalRequired {
                reason,
                matched_rule_ids: matched,
            }),
            kavach_core::DecisionEffect::Allow => {
                // Generate a cryptographically random permit secret.
                let mut secret = [0u8; 32];
                getrandom::getrandom(&mut secret).map_err(|e| {
                    GuardError::Internal(format!("failed to generate permit secret: {e}"))
                })?;
                let digest = compute_request_digest(request);
                let permit = ExecutionPermit::new(&secret, matched, digest, self.permit_ttl);
                Ok(GuardOutcome::Permitted(permit))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
    use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
    use kavach_core::resource::Resource;
    use kavach_policy::{DefaultEffect, Effect as PolicyEffect, Rule, RuleConditions};

    fn make_request() -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent-1").unwrap(),
                SessionId::new("sess-1").unwrap(),
            )
            .trust_level(kavach_core::subject::TrustLevel::Standard)
            .build(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/foo.txt").unwrap(),
            RequestContext::new(None, None, None, None, false).unwrap(),
        )
    }

    fn allow_read_policy() -> kavach_policy::Policy {
        kavach_policy::Policy {
            id: PolicyId::new("pol-1").unwrap(),
            name: "test".into(),
            description: "".into(),
            default_effect: DefaultEffect::Deny,
            rules: vec![Rule {
                id: RuleId::new("allow-read").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        }
    }

    fn deny_all_policy() -> kavach_policy::Policy {
        kavach_policy::Policy {
            id: PolicyId::new("pol-1").unwrap(),
            name: "test".into(),
            description: "".into(),
            default_effect: DefaultEffect::Deny,
            rules: vec![Rule {
                id: RuleId::new("deny-all").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Deny,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        }
    }

    #[test]
    fn guard_returns_permitted_for_allowed_request() {
        let guard = PolicyGuard::new(vec![allow_read_policy()], Duration::from_secs(300)).unwrap();
        let outcome = guard.evaluate(&make_request()).unwrap();
        assert!(matches!(outcome, GuardOutcome::Permitted(_)));
    }

    #[test]
    fn guard_returns_denied_for_denied_request() {
        let guard = PolicyGuard::new(vec![deny_all_policy()], Duration::from_secs(300)).unwrap();
        let outcome = guard.evaluate(&make_request()).unwrap();
        assert!(matches!(outcome, GuardOutcome::Denied { .. }));
    }

    #[test]
    fn execution_permit_verify_secret() {
        let secret = [42u8; 32];
        let permit = ExecutionPermit::new(&secret, vec![], [0u8; 32], Duration::from_secs(300));
        assert!(permit.verify_secret(&secret));
        assert!(!permit.verify_secret(&[99u8; 32]));
    }

    #[test]
    fn execution_permit_is_valid() {
        let permit = ExecutionPermit::new(&[1u8; 32], vec![], [0u8; 32], Duration::from_secs(300));
        assert!(permit.is_valid());
        assert!(!permit.is_expired());
        assert!(!permit.is_consumed());
    }

    #[test]
    fn execution_permit_single_use() {
        let mut permit =
            ExecutionPermit::new(&[1u8; 32], vec![], [0u8; 32], Duration::from_secs(300));
        assert!(permit.consume());
        assert!(!permit.consume()); // Double consumption rejected
        assert!(permit.is_consumed());
        assert!(!permit.is_valid());
    }

    #[test]
    fn execution_permit_expires() {
        let permit = ExecutionPermit::new(
            &[1u8; 32],
            vec![],
            [0u8; 32],
            Duration::from_secs(0), // Instant expiry
        );
        assert!(permit.is_expired());
        assert!(!permit.is_valid());
    }

    #[test]
    fn execution_permit_verify_request_digest() {
        let permit = ExecutionPermit::new(&[1u8; 32], vec![], [42u8; 32], Duration::from_secs(300));
        assert!(permit.verify_request_digest(&[42u8; 32]));
        assert!(!permit.verify_request_digest(&[99u8; 32]));
    }

    #[test]
    fn request_digest_is_deterministic() {
        let req = make_request();
        let d1 = compute_request_digest(&req);
        let d2 = compute_request_digest(&req);
        assert_eq!(d1, d2);
    }
}
