//! KAVACH runtime guard, execution permits, and production orchestration.
//!
//! The runtime layer connects validation, policy evaluation, approval,
//! enforcement, audit, and redaction into one end-to-end flow.
//!
//! - [`KavachRuntime`](crate::runtime::KavachRuntime) — production orchestration with
//!   [`evaluate`](crate::runtime::KavachRuntime::evaluate),
//!   [`execute`](crate::runtime::KavachRuntime::execute), and approval-consume flows.
//! - [`Guard`] / [`PolicyGuard`] — legacy single-pass guard.
//! - [`ExecutionPermit`] — request-bound, single-use, time-limited permit
//!   (re-exported from [`kavach_core`]).
//! - [`compute_request_digest`] — canonical request digest (re-exported from
//!   [`kavach_core`]).
//!
//! The new [`KavachRuntime`](crate::runtime::KavachRuntime) replaces the legacy [`PolicyGuard`] for
//! production use.

/// Configuration for the production runtime.
pub mod config;
/// Typed runtime errors.
pub mod error;
/// Evaluation outcome, execution input, and result types.
pub mod outcome;
/// Enforcement adapter registry.
pub mod registry;
/// Production [`KavachRuntime`](crate::runtime::KavachRuntime) and [`RuntimeBuilder`](crate::runtime::RuntimeBuilder).
pub mod runtime;

// ── Legacy re-exports (backward compatible) ──────────────────────────────

pub use kavach_core::compute_request_digest;
pub use kavach_core::permit::required_scope;
pub use kavach_core::permit::{ExecutionPermit, PermitScope};

// ── Legacy guard API ────────────────────────────────────────────────────

use std::time::Duration;

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

// Legacy `ExecutionPermit` and `compute_request_digest` are now re-exported
// from `kavach_core` above.

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
                let digest = kavach_core::compute_request_digest(request);
                let scope = kavach_core::required_scope(&request.operation);
                let permit = ExecutionPermit::new(
                    &secret,
                    request.request_id.clone(),
                    scope,
                    matched,
                    digest,
                    self.permit_ttl,
                );
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
    fn guard_execution_permit_verify_secret() {
        let secret = [42u8; 32];
        let req_id = RequestId::new("guard-test").unwrap();
        let permit = ExecutionPermit::new(
            &secret,
            req_id,
            PermitScope::FilesystemRead,
            vec![],
            [0u8; 32],
            Duration::from_secs(300),
        );
        assert!(permit.verify_secret(&secret));
        assert!(!permit.verify_secret(&[99u8; 32]));
    }

    #[test]
    fn guard_execution_permit_single_use() {
        let req_id = RequestId::new("guard-test2").unwrap();
        let mut permit = ExecutionPermit::new(
            &[1u8; 32],
            req_id,
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
    fn guard_request_digest_is_deterministic() {
        let req = make_request();
        let d1 = kavach_core::compute_request_digest(&req);
        let d2 = kavach_core::compute_request_digest(&req);
        assert_eq!(d1, d2);
    }
}
