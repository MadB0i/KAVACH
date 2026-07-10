//! Authorization decisions produced by the policy engine.
//!
//! A decision carries the final effect, a stable reason code, a human
//! explanation that must **never** drive authorization logic, the matched rule
//! IDs in stable sorted order, and the request/evaluation metadata needed for
//! audit correlation.

use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use crate::error::{DomainError, DomainErrorKind};
use crate::ids::{ApprovalId, RequestId, RuleId};
use std::collections::BTreeSet;

/// The final authorization effect for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionEffect {
    /// Operation is permitted.
    Allow,
    /// Operation is forbidden. Deny precedence overrides allow and approval.
    Deny,
    /// Operation is permitted only after explicit human approval.
    RequireApproval,
}

impl DecisionEffect {
    /// Stable snake_case label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
        }
    }
}

impl fmt::Display for DecisionEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable machine-readable reason codes.
///
/// These strings are the only part of an [`AuthorizationDecision`] that may
/// drive programmatic authorization logic in downstream consumers. The human
/// [`explanation`](AuthorizationDecision::explanation) is a display hint only.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// A rule explicitly allowed the request.
    KavachAllowPolicyMatch,
    /// A rule explicitly denied the request.
    KavachDenyExplicitRule,
    /// No rule matched and the policy default (deny) applied.
    KavachDenyDefault,
    /// The request was malformed and denied as a fail-closed response.
    KavachDenyInvalidRequest,
    /// A rule required human approval before allowing the request.
    KavachApprovalRequired,
    /// A rule required approval because the operation is considered destructive.
    KavachApprovalDestructiveOperation,
    /// The targeted resource type is unknown and was denied.
    KavachDenyUnknownResource,
    /// A workspace-root escape attempt was detected and denied.
    KavachDenyPathEscape,
}

impl ReasonCode {
    /// Stable snake_case label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KavachAllowPolicyMatch => "kavach_allow_policy_match",
            Self::KavachDenyExplicitRule => "kavach_deny_explicit_rule",
            Self::KavachDenyDefault => "kavach_deny_default",
            Self::KavachDenyInvalidRequest => "kavach_deny_invalid_request",
            Self::KavachApprovalRequired => "kavach_approval_required",
            Self::KavachApprovalDestructiveOperation => "kavach_approval_destructive_operation",
            Self::KavachDenyUnknownResource => "kavach_deny_unknown_resource",
            Self::KavachDenyPathEscape => "kavach_deny_path_escape",
        }
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReasonCode {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kavach_allow_policy_match" => Ok(Self::KavachAllowPolicyMatch),
            "kavach_deny_explicit_rule" => Ok(Self::KavachDenyExplicitRule),
            "kavach_deny_default" => Ok(Self::KavachDenyDefault),
            "kavach_deny_invalid_request" => Ok(Self::KavachDenyInvalidRequest),
            "kavach_approval_required" => Ok(Self::KavachApprovalRequired),
            "kavach_approval_destructive_operation" => Ok(Self::KavachApprovalDestructiveOperation),
            "kavach_deny_unknown_resource" => Ok(Self::KavachDenyUnknownResource),
            "kavach_deny_path_escape" => Ok(Self::KavachDenyPathEscape),
            other => Err(DomainError::new(
                DomainErrorKind::UnknownVariant,
                format!("unknown reason code: {other}"),
            )),
        }
    }
}

/// Approval requirements when [`DecisionEffect::RequireApproval`] is returned.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApprovalRequirements {
    /// Identifier of the approval flow (assigned by the future approval broker).
    pub approval_id: ApprovalId,
    /// Human-readable, non-secret summary of what is being approved.
    pub summary: String,
}

/// A finalized authorization decision for a single tool request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizationDecision {
    /// Final effect (allow, deny, require approval). Deny precedence is already
    /// applied by the engine before this value is set.
    pub effect: DecisionEffect,
    /// Stable machine-readable reason code.
    pub reason: ReasonCode,
    /// Human-readable explanation. **Must not** be used for authorization logic.
    pub explanation: String,
    /// IDs of rules that matched, in stable sorted order (deny rules sorted
    /// alongside allow/approval rules).
    pub matched_rule_ids: Vec<RuleId>,
    /// When the engine produced this decision.
    pub evaluated_at: SystemTime,
    /// The request id this decision pertains to.
    pub request_id: RequestId,
    /// Optional numeric risk score in the range `[0, 100]`. Lower is safer.
    pub risk_score: Option<u8>,
    /// Optional approval requirements if the effect is [`DecisionEffect::RequireApproval`].
    pub approval: Option<ApprovalRequirements>,
}

impl AuthorizationDecision {
    /// Construct a decision, ensuring rule IDs are sorted deterministically.
    ///
    /// The eight parameters mirror the eight documented fields of
    /// [`AuthorizationDecision`]; splitting them now would be premature
    /// abstraction for an immutable data record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        effect: DecisionEffect,
        reason: ReasonCode,
        explanation: impl Into<String>,
        matched_rule_ids: BTreeSet<RuleId>,
        evaluated_at: SystemTime,
        request_id: RequestId,
        risk_score: Option<u8>,
        approval: Option<ApprovalRequirements>,
    ) -> Self {
        let mut ids: Vec<RuleId> = matched_rule_ids.into_iter().collect();
        ids.sort();
        Self {
            effect,
            reason,
            explanation: explanation.into(),
            matched_rule_ids: ids,
            evaluated_at,
            request_id,
            risk_score,
            approval,
        }
    }
}
