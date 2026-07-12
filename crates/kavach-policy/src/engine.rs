use std::collections::BTreeSet;
use std::time::SystemTime;

use kavach_core::ids::RuleId;
use kavach_core::request::ToolRequest;
use kavach_core::{AuthorizationDecision, DecisionEffect, ReasonCode};

use crate::model::{DefaultEffect, Effect, Policy, PolicyValidationError, trust_level_rank};

/// In-memory policy evaluator with deterministic precedence.
///
/// Precedence (highest to lowest):
///   1. Explicit Deny
///   2. Require Approval
///   3. Explicit Allow
///   4. Policy default (Deny or RequireApproval only)
///
/// Only rule IDs from the winning precedence group appear in the output
/// [`AuthorizationDecision`], sorted lexicographically.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policies: Vec<Policy>,
}

impl PolicyEngine {
    /// Create a new engine from an ordered list of policies.
    ///
    /// Returns an error if any policy contains duplicate rule IDs or a rule
    /// with empty conditions (no active matchers).
    ///
    /// Policies are evaluated in the order given; rules within each policy are
    /// evaluated in their declaration order.
    pub fn new(policies: Vec<Policy>) -> Result<Self, PolicyValidationError> {
        // Validate within each policy.
        for policy in &policies {
            policy.validate()?;
        }
        // Validate cross-policy duplicates.
        let mut seen: BTreeSet<RuleId> = BTreeSet::new();
        for policy in &policies {
            for rule in &policy.rules {
                if !seen.insert(rule.id.clone()) {
                    return Err(PolicyValidationError::DuplicateRuleId(rule.id.clone()));
                }
            }
        }
        Ok(Self { policies })
    }

    /// Evaluate a [`ToolRequest`] against all loaded policies.
    ///
    /// # Flow
    ///
    /// 1. **Validate** the request via [`ToolRequest::validate()`]. If
    ///    validation fails, return [`DecisionEffect::Deny`] with
    ///    [`ReasonCode::KavachDenyInvalidRequest`].
    /// 2. **Match** every rule across all policies, collecting IDs grouped
    ///    by effect.
    /// 3. **Resolve** the highest-precedence group and return only those IDs,
    ///    sorted lexicographically.
    /// 4. If no rule matched, apply the first policy's default effect (or
    ///    [`DefaultEffect::Deny`] if no policies are configured).
    pub fn evaluate(&self, request: &ToolRequest) -> AuthorizationDecision {
        let evaluated_at = SystemTime::now();
        let request_id = request.request_id.clone();

        // Step 1: Validate request; fail closed.
        if let Err(err) = request.validate() {
            return AuthorizationDecision::new(
                DecisionEffect::Deny,
                ReasonCode::KavachDenyInvalidRequest,
                format!("request validation failed: {}", err),
                BTreeSet::new(),
                evaluated_at,
                request_id,
                None,
                None,
            );
        }

        // Step 2: Evaluate all rules, collecting IDs by effect group.
        let mut deny_ids: BTreeSet<RuleId> = BTreeSet::new();
        let mut approval_ids: BTreeSet<RuleId> = BTreeSet::new();
        let mut allow_ids: BTreeSet<RuleId> = BTreeSet::new();

        for policy in &self.policies {
            for rule in &policy.rules {
                if rule_matches(rule, request) {
                    match rule.effect {
                        Effect::Deny => deny_ids.insert(rule.id.clone()),
                        Effect::RequireApproval => approval_ids.insert(rule.id.clone()),
                        Effect::Allow => allow_ids.insert(rule.id.clone()),
                    };
                }
            }
        }

        // Step 3: Resolve precedence — highest-priority group with at least
        // one match wins.
        if !deny_ids.is_empty() {
            let ids: Vec<RuleId> = deny_ids.into_iter().collect();
            AuthorizationDecision::new(
                DecisionEffect::Deny,
                ReasonCode::KavachDenyExplicitRule,
                format!("denied by explicit rules: {}", join_ids(&ids)),
                ids.into_iter().collect(),
                evaluated_at,
                request_id,
                None,
                None,
            )
        } else if !approval_ids.is_empty() {
            let ids: Vec<RuleId> = approval_ids.into_iter().collect();
            AuthorizationDecision::new(
                DecisionEffect::RequireApproval,
                ReasonCode::KavachApprovalRequired,
                format!("approval required by rules: {}", join_ids(&ids)),
                ids.into_iter().collect(),
                evaluated_at,
                request_id,
                None,
                None,
            )
        } else if !allow_ids.is_empty() {
            let ids: Vec<RuleId> = allow_ids.into_iter().collect();
            AuthorizationDecision::new(
                DecisionEffect::Allow,
                ReasonCode::KavachAllowPolicyMatch,
                format!("allowed by rules: {}", join_ids(&ids)),
                ids.into_iter().collect(),
                evaluated_at,
                request_id,
                None,
                None,
            )
        } else {
            // No rule matched — policy default (Allow is impossible at type level).
            let default = self
                .policies
                .first()
                .map(|p| p.default_effect)
                .unwrap_or(DefaultEffect::Deny);
            AuthorizationDecision::new(
                default.to_decision_effect(),
                default.reason_code(),
                format!(
                    "no rule matched; policy default applied ({})",
                    default.to_decision_effect()
                ),
                BTreeSet::new(),
                evaluated_at,
                request_id,
                None,
                None,
            )
        }
    }
}

/// Join rule IDs into a comma-separated string for human explanation.
fn join_ids(ids: &[RuleId]) -> String {
    ids.iter()
        .map(|id| id.as_str().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Check whether a rule's conditions match the given request.
fn rule_matches(rule: &crate::model::Rule, request: &ToolRequest) -> bool {
    let cond = &rule.conditions;

    // --- Operation check ---
    if !cond.operations.is_empty() {
        let op = request.operation.discriminant();
        if !cond.operations.iter().any(|o| o == op) {
            return false;
        }
    }

    // --- Resource kind check ---
    if !cond.resource_kinds.is_empty() {
        let kind = request.resource.kind();
        if !cond.resource_kinds.contains(&kind) {
            return false;
        }
    }

    // --- Agent ID check ---
    if !cond.agent_ids.is_empty() {
        let agent = request.subject.agent_id.as_str();
        if !cond.agent_ids.iter().any(|a| a == agent) {
            return false;
        }
    }

    // --- Trust level check ---
    if let Some(min_trust) = cond.min_trust_level {
        let subject_rank = trust_level_rank(&request.subject.trust_level);
        let min_rank = trust_level_rank(&min_trust);
        if subject_rank < min_rank {
            return false;
        }
    }

    // --- Capability check ---
    if !cond.required_capabilities.is_empty() {
        let declared: Vec<&str> = request
            .subject
            .declared_capabilities
            .iter()
            .map(|c| c.as_str())
            .collect();
        for required in &cond.required_capabilities {
            if !declared.contains(&required.as_str()) {
                return false;
            }
        }
    }

    // --- Declared intent prefix check ---
    if let Some(prefix) = &cond.intent_prefix {
        match &request.context.declared_intent {
            Some(intent) => {
                if !intent.starts_with(prefix) {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use kavach_core::DecisionEffect;
    use kavach_core::ids::{AgentId, RequestId, RuleId, SessionId};
    use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
    use kavach_core::resource::Resource;
    use kavach_core::subject::Capability;

    use crate::model::{DefaultEffect, Effect as PolicyEffect, Policy, Rule, RuleConditions};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_subject() -> kavach_core::subject::AgentSubject {
        AgentSubjectBuilder::new(
            AgentId::new("agent-1").unwrap(),
            SessionId::new("sess-1").unwrap(),
        )
        .trust_level(kavach_core::subject::TrustLevel::Standard)
        .build()
    }

    fn make_subject_with_caps(caps: &[&str]) -> kavach_core::subject::AgentSubject {
        let mut builder = AgentSubjectBuilder::new(
            AgentId::new("agent-1").unwrap(),
            SessionId::new("sess-1").unwrap(),
        )
        .trust_level(kavach_core::subject::TrustLevel::Standard);
        for c in caps {
            builder = builder.capability(Capability::new(c).unwrap());
        }
        builder.build()
    }

    fn make_context() -> RequestContext {
        RequestContext::new(None, None, None, None, false).unwrap()
    }

    fn make_context_with_intent(intent: &str) -> RequestContext {
        RequestContext::new(None, Some(intent), None, None, false).unwrap()
    }

    fn make_request(subject: kavach_core::subject::AgentSubject) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            subject,
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/foo.txt").unwrap(),
            make_context(),
        )
    }

    fn make_request_with(
        subject: kavach_core::subject::AgentSubject,
        operation: Operation,
        resource: Resource,
        context: RequestContext,
    ) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            subject,
            operation,
            resource,
            context,
        )
    }

    fn policy(default_effect: DefaultEffect, rules: Vec<Rule>) -> Policy {
        Policy {
            id: kavach_core::ids::PolicyId::new("pol-1").unwrap(),
            name: "test".into(),
            description: "".into(),
            default_effect,
            rules,
        }
    }

    fn policy_with_id(id: &str, default_effect: DefaultEffect, rules: Vec<Rule>) -> Policy {
        Policy {
            id: kavach_core::ids::PolicyId::new(id).unwrap(),
            name: "test".into(),
            description: "".into(),
            default_effect,
            rules,
        }
    }

    // -----------------------------------------------------------------------
    // Precedence tests — winning IDs only
    // -----------------------------------------------------------------------

    #[test]
    fn deny_decision_contains_deny_ids_only() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("approve-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::RequireApproval,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("deny-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(
            decision.matched_rule_ids,
            vec![RuleId::new("deny-rule").unwrap()]
        );
    }

    #[test]
    fn approval_decision_contains_approval_ids_only() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("approve-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::RequireApproval,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::RequireApproval);
        assert_eq!(
            decision.matched_rule_ids,
            vec![RuleId::new("approve-rule").unwrap()]
        );
    }

    #[test]
    fn allow_decision_contains_allow_ids_only() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-rule-a").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("allow-rule-b").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        resource_kinds: vec![kavach_core::resource::ResourceKind::File],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Allow);
        let mut expected: Vec<RuleId> = vec![
            RuleId::new("allow-rule-a").unwrap(),
            RuleId::new("allow-rule-b").unwrap(),
        ];
        expected.sort();
        assert_eq!(decision.matched_rule_ids, expected);
    }

    #[test]
    fn default_deny_has_empty_matched_ids() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("write-only").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_write".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyDefault);
        assert!(decision.matched_rule_ids.is_empty());
    }

    #[test]
    fn default_approval_has_empty_matched_ids() {
        let engine =
            PolicyEngine::new(vec![policy(DefaultEffect::RequireApproval, vec![])]).unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::RequireApproval);
        assert_eq!(decision.reason, ReasonCode::KavachApprovalRequired);
        assert!(decision.matched_rule_ids.is_empty());
    }

    #[test]
    fn winning_ids_are_sorted() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("z-deny").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("a-deny").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        resource_kinds: vec![kavach_core::resource::ResourceKind::File],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("m-deny").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        agent_ids: vec!["agent-1".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        let ids = decision.matched_rule_ids;
        assert_eq!(ids.len(), 3);
        assert!(ids.windows(2).all(|w| w[0] <= w[1]), "not sorted");
    }

    // -----------------------------------------------------------------------
    // Duplicate rule ID validation
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_ids_within_one_policy_are_rejected() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("dup").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("dup").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_write".into()],
                        ..Default::default()
                    },
                },
            ],
        )]);

        match result {
            Err(PolicyValidationError::DuplicateRuleId(id)) => {
                assert_eq!(id.as_str(), "dup");
            }
            _ => panic!("expected DuplicateRuleId error"),
        }
    }

    #[test]
    fn duplicate_ids_across_policies_are_rejected() {
        let result = PolicyEngine::new(vec![
            policy_with_id(
                "pol-1",
                DefaultEffect::Deny,
                vec![Rule {
                    id: RuleId::new("shared").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                }],
            ),
            policy_with_id(
                "pol-2",
                DefaultEffect::Deny,
                vec![Rule {
                    id: RuleId::new("shared").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_write".into()],
                        ..Default::default()
                    },
                }],
            ),
        ]);

        match result {
            Err(PolicyValidationError::DuplicateRuleId(id)) => {
                assert_eq!(id.as_str(), "shared");
            }
            _ => panic!("expected DuplicateRuleId error"),
        }
    }

    // -----------------------------------------------------------------------
    // Empty conditions validation
    // -----------------------------------------------------------------------

    #[test]
    fn empty_conditions_are_rejected() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("catch-all").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions::default(),
            }],
        )]);

        match result {
            Err(PolicyValidationError::EmptyConditions(id)) => {
                assert_eq!(id.as_str(), "catch-all");
            }
            _ => panic!("expected EmptyConditions error"),
        }
    }

    // -----------------------------------------------------------------------
    // Precedence tests (existing)
    // -----------------------------------------------------------------------

    #[test]
    fn deny_precedence_over_allow() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("deny-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        // Only deny IDs survive.
        assert!(
            !decision
                .matched_rule_ids
                .contains(&RuleId::new("allow-all").unwrap())
        );
        assert!(
            decision
                .matched_rule_ids
                .contains(&RuleId::new("deny-all").unwrap())
        );
    }

    #[test]
    fn deny_precedence_over_approval() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("approve-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::RequireApproval,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("deny-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
    }

    #[test]
    fn approval_precedence_over_allow() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("approve-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::RequireApproval,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::RequireApproval);
    }

    #[test]
    fn allow_when_only_allow_rules_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-read").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Allow);
        assert_eq!(decision.reason, ReasonCode::KavachAllowPolicyMatch);
    }

    #[test]
    fn no_match_falls_to_policy_default_deny() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("only-write").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_write".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyDefault);
        assert!(decision.matched_rule_ids.is_empty());
    }

    #[test]
    fn invalid_request_fails_closed() {
        let ctx = RequestContext {
            timestamp: std::time::SystemTime::now(),
            working_directory: None,
            declared_intent: Some("read\x00source".into()),
            parent_request_id: None,
            metadata: kavach_core::resource::RequestMetadata::new(),
            dry_run: false,
        };
        let request = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/safe.txt").unwrap(),
            ctx,
        );

        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::RequireApproval,
            vec![Rule {
                id: RuleId::new("allow-all").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&request);
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyInvalidRequest);
        assert!(decision.matched_rule_ids.is_empty());
    }

    // -----------------------------------------------------------------------
    // Dimension matching tests
    // -----------------------------------------------------------------------

    #[test]
    fn matches_by_operation() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-read").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("deny-write").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_write".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        assert_eq!(
            engine.evaluate(&make_request(make_subject())).effect,
            DecisionEffect::Allow
        );

        let write_req = make_request_with(
            make_subject(),
            Operation::FileWrite,
            Resource::file("/workspace/bar.txt").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&write_req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn matches_by_resource_kind() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-command").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    resource_kinds: vec![kavach_core::resource::ResourceKind::Command],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyDefault);
    }

    #[test]
    fn matches_by_agent_id() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-agent-1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    agent_ids: vec!["agent-1".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Allow);
    }

    #[test]
    fn matches_by_trust_level() {
        let trusted_subject = {
            let b = AgentSubjectBuilder::new(
                AgentId::new("agent-trusted").unwrap(),
                SessionId::new("sess-1").unwrap(),
            )
            .trust_level(kavach_core::subject::TrustLevel::Trusted);
            b.build()
        };

        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-trusted").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    min_trust_level: Some(kavach_core::subject::TrustLevel::Trusted),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        assert_eq!(
            engine.evaluate(&make_request(trusted_subject)).effect,
            DecisionEffect::Allow
        );

        let standard_decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(standard_decision.effect, DecisionEffect::Deny);
        assert_eq!(standard_decision.reason, ReasonCode::KavachDenyDefault);
    }

    #[test]
    fn matches_by_capability() {
        let capped_subject = make_subject_with_caps(&["read_secrets"]);
        let uncapped_subject = make_subject();

        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-secret-readers").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    required_capabilities: vec!["read_secrets".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        assert_eq!(
            engine.evaluate(&make_request(capped_subject)).effect,
            DecisionEffect::Allow
        );
        assert_eq!(
            engine.evaluate(&make_request(uncapped_subject)).effect,
            DecisionEffect::Deny
        );
    }

    #[test]
    fn matches_by_intent_prefix() {
        let reading_ctx = make_context_with_intent("read source");
        let writing_ctx = make_context_with_intent("write output");

        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-read-intent").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    intent_prefix: Some("read".into()),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let base_subject = make_subject();
        assert_eq!(
            engine
                .evaluate(&make_request_with(
                    base_subject.clone(),
                    Operation::FileRead { max_bytes: None },
                    Resource::file("/workspace/foo.txt").unwrap(),
                    reading_ctx,
                ))
                .effect,
            DecisionEffect::Allow
        );
        assert_eq!(
            engine
                .evaluate(&make_request_with(
                    base_subject,
                    Operation::FileWrite,
                    Resource::file("/workspace/bar.txt").unwrap(),
                    writing_ctx,
                ))
                .effect,
            DecisionEffect::Deny
        );
    }

    // -----------------------------------------------------------------------
    // AND semantics — multiple matchers required
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_matchers_use_and_semantics() {
        // Rule matches only when ALL of: operation == file_read AND
        // resource_kind == File AND agent_id == agent-1.
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("strict").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    resource_kinds: vec![kavach_core::resource::ResourceKind::File],
                    agent_ids: vec!["agent-1".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // All three match → allow.
        assert_eq!(
            engine.evaluate(&make_request(make_subject())).effect,
            DecisionEffect::Allow
        );

        // Same operation but wrong resource kind  → deny.
        let cmd_req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::directory("/workspace").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&cmd_req).effect, DecisionEffect::Deny);

        // Wrong operation → deny.
        let write_req = make_request_with(
            make_subject(),
            Operation::FileWrite,
            Resource::file("/workspace/bar.txt").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&write_req).effect, DecisionEffect::Deny);
    }

    // -----------------------------------------------------------------------
    // Multiple policies
    // -----------------------------------------------------------------------

    #[test]
    fn rules_from_multiple_policies_are_evaluated() {
        let engine = PolicyEngine::new(vec![
            policy_with_id(
                "base",
                DefaultEffect::Deny,
                vec![Rule {
                    id: RuleId::new("base-allow-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                }],
            ),
            policy_with_id(
                "override",
                DefaultEffect::Deny,
                vec![Rule {
                    id: RuleId::new("override-deny").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                }],
            ),
        ])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        // Only deny-group IDs.
        assert!(
            !decision
                .matched_rule_ids
                .contains(&RuleId::new("base-allow-all").unwrap())
        );
        assert!(
            decision
                .matched_rule_ids
                .contains(&RuleId::new("override-deny").unwrap())
        );
    }

    #[test]
    fn empty_policies_default_to_deny() {
        let engine = PolicyEngine::new(vec![]).unwrap();
        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyDefault);
    }

    #[test]
    fn default_effect_cannot_be_allow() {
        match crate::model::DefaultEffect::Deny {
            crate::model::DefaultEffect::Deny => {}
            crate::model::DefaultEffect::RequireApproval => {}
        }
    }

    #[test]
    fn no_match_falls_to_default_require_approval() {
        let engine =
            PolicyEngine::new(vec![policy(DefaultEffect::RequireApproval, vec![])]).unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::RequireApproval);
        assert_eq!(decision.reason, ReasonCode::KavachApprovalRequired);
    }

    // -----------------------------------------------------------------------
    // Determinism — repeated evaluation gives same result
    // -----------------------------------------------------------------------

    #[test]
    fn repeated_evaluation_identical_decision() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("read-ok").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request(make_subject());
        let d1 = engine.evaluate(&req);
        let d2 = engine.evaluate(&req);
        // Compare everything except evaluated_at (SystemTime changes).
        assert_eq!(d1.effect, d2.effect);
        assert_eq!(d1.reason, d2.reason);
        assert_eq!(d1.matched_rule_ids, d2.matched_rule_ids);
        assert_eq!(d1.request_id, d2.request_id);
    }
}
