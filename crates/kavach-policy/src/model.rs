use std::collections::BTreeSet;

use kavach_core::ids::{PolicyId, RuleId};
use kavach_core::resource::ResourceKind;
use kavach_core::subject::TrustLevel;

/// Authorization effect produced by a matching rule.
///
/// Used internally in the policy model. Converted to
/// [`kavach_core::DecisionEffect`] when building the final
/// [`kavach_core::AuthorizationDecision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Explicitly allow the operation.
    Allow,
    /// Explicitly deny the operation. Deny always wins.
    Deny,
    /// Allow only after human approval.
    RequireApproval,
}

impl Effect {
    /// Convert to the core decision effect type.
    pub fn to_decision_effect(self) -> kavach_core::DecisionEffect {
        match self {
            Effect::Allow => kavach_core::DecisionEffect::Allow,
            Effect::Deny => kavach_core::DecisionEffect::Deny,
            Effect::RequireApproval => kavach_core::DecisionEffect::RequireApproval,
        }
    }
}

/// Policy-level default effect when no rule matches.
///
/// Only [`Deny`](DefaultEffect::Deny) and [`RequireApproval`](DefaultEffect::RequireApproval)
/// are permitted. A plain [`Allow`](Effect::Allow) default is rejected at the
/// type level to enforce a fail-closed posture by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultEffect {
    /// Deny the request. The standard fail-closed default.
    Deny,
    /// Require human approval before allowing the request.
    RequireApproval,
}

impl DefaultEffect {
    /// Convert to the matching [`ReasonCode`](kavach_core::ReasonCode).
    pub(crate) fn reason_code(self) -> kavach_core::ReasonCode {
        match self {
            Self::Deny => kavach_core::ReasonCode::KavachDenyDefault,
            Self::RequireApproval => kavach_core::ReasonCode::KavachApprovalRequired,
        }
    }

    /// Convert to a core [`DecisionEffect`](kavach_core::DecisionEffect).
    pub fn to_decision_effect(self) -> kavach_core::DecisionEffect {
        match self {
            Self::Deny => kavach_core::DecisionEffect::Deny,
            Self::RequireApproval => kavach_core::DecisionEffect::RequireApproval,
        }
    }
}

/// Errors that can arise during policy validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyValidationError {
    /// A rule ID appears more than once.
    #[error("duplicate rule id: {0}")]
    DuplicateRuleId(RuleId),
    /// An ordinary rule has no active matchers (all condition fields empty).
    #[error("rule {0} has no active conditions; empty conditions are not allowed")]
    EmptyConditions(RuleId),
}

/// Conditions that must all be satisfied for a rule to match a request.
///
/// Each field is optional; when left at its default (empty or `None`) that
/// dimension is not checked, meaning the condition matches any value.
///
/// At least one field must be non-default, otherwise [`RuleConditions::is_empty`]
/// returns `true` and the rule will be rejected by validation.
#[derive(Debug, Clone, Default)]
pub struct RuleConditions {
    /// If non-empty, only matches when the operation discriminant appears in
    /// this set (e.g., `"file_read"`, `"command_execute"`).
    pub operations: Vec<String>,
    /// If non-empty, only matches when the resource kind appears in this set.
    pub resource_kinds: Vec<ResourceKind>,
    /// If non-empty, only matches when the agent ID appears in this set.
    pub agent_ids: Vec<String>,
    /// If set, only matches when the subject's trust level ranks at or above
    /// this value.
    pub min_trust_level: Option<TrustLevel>,
    /// If non-empty, the subject must declare all of these capabilities.
    pub required_capabilities: Vec<String>,
    /// If set, the declared intent must start with this prefix.
    pub intent_prefix: Option<String>,
}

impl RuleConditions {
    /// Returns `true` when every condition field is at its default (empty or
    /// `None`), meaning the rule would match any request — which is rejected.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
            && self.resource_kinds.is_empty()
            && self.agent_ids.is_empty()
            && self.min_trust_level.is_none()
            && self.required_capabilities.is_empty()
            && self.intent_prefix.is_none()
    }
}

/// A single policy rule with deterministic matching conditions.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Unique identifier for this rule (must be stable across restarts).
    pub id: RuleId,
    /// Human-readable description of what this rule does.
    pub description: String,
    /// Effect when all conditions match.
    pub effect: Effect,
    /// Conditions that must all be satisfied.
    pub conditions: RuleConditions,
}

/// A complete policy document containing an ordered list of rules.
///
/// Rules are evaluated in declaration order; the highest-precedence matching
/// effect wins (Deny > RequireApproval > Allow > default).
///
/// The [`default_effect`](Policy::default_effect) field uses [`DefaultEffect`],
/// which explicitly forbids [`Allow`](Effect::Allow), ensuring a fail-closed
/// posture when no rule matches.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Unique identifier for this policy document.
    pub id: PolicyId,
    /// Human-readable name.
    pub name: String,
    /// Description of this policy's purpose.
    pub description: String,
    /// Default effect when no rule matches (Deny or RequireApproval only).
    pub default_effect: DefaultEffect,
    /// Rules evaluated in this order (first in list is checked first, but
    /// precedence is determined by effect priority, not position).
    pub rules: Vec<Rule>,
}

impl Policy {
    /// Validate internal consistency: no duplicate rule IDs and no empty
    /// conditions on any ordinary rule.
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        let mut seen = BTreeSet::new();
        for rule in &self.rules {
            if rule.conditions.is_empty() {
                return Err(PolicyValidationError::EmptyConditions(rule.id.clone()));
            }
            if !seen.insert(rule.id.clone()) {
                return Err(PolicyValidationError::DuplicateRuleId(rule.id.clone()));
            }
        }
        Ok(())
    }
}

/// Convert a trust level to a numeric rank for comparison.
pub(crate) fn trust_level_rank(level: &TrustLevel) -> u8 {
    match level {
        TrustLevel::Untrusted => 0,
        TrustLevel::Restricted => 1,
        TrustLevel::Standard => 2,
        TrustLevel::Trusted => 3,
        TrustLevel::System => 4,
    }
}
