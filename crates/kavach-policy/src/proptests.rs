#![allow(clippy::unwrap_used, unused_imports)]

use crate::engine::PolicyEngine;
use crate::{DefaultEffect, Effect, Policy, Rule, RuleConditions};
use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use proptest::prelude::*;

proptest! {
    #[test]
    fn policy_decision_is_deterministic(
        path in "[a-zA-Z0-9/._-]{1,40}",
        op_name in "file_read|file_delete|command_execute|network_request",
        agent in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let policy = Policy {
            id: PolicyId::new("test-pol").unwrap(),
            name: "test".into(),
            description: "".into(),
            default_effect: DefaultEffect::Deny,
            rules: vec![
                Rule {
                    id: RuleId::new("allow-read").unwrap(),
                    description: "".into(),
                    effect: Effect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        path_globs: Some(vec!["/allowed/**".into()]),
                        ..Default::default()
                    },
                },
            ],
        };
        let engine = PolicyEngine::new(vec![policy]).unwrap();
        let operation = match op_name.as_str() {
            "file_delete" => Operation::FileDelete,
            "command_execute" => Operation::CommandExecute,
            "network_request" => Operation::NetworkRequest,
            _ => Operation::FileRead { max_bytes: None },
        };
        let resource = Resource::file(&path).unwrap_or_else(|_| Resource::file("/tmp/default.txt").unwrap());
        let req = ToolRequest::new(
            RequestId::new("prop-req").unwrap(),
            AgentSubjectBuilder::new(AgentId::new(&agent).unwrap(), SessionId::new("prop-sess").unwrap())
                .trust_level(TrustLevel::Standard).build(),
            operation,
            resource,
            RequestContext::new(None, None, None, None, false).unwrap(),
        );
        let d1 = engine.evaluate(&req);
        let d2 = engine.evaluate(&req);
        assert_eq!(d1.effect, d2.effect);
        assert_eq!(d1.matched_rule_ids, d2.matched_rule_ids);
        assert_eq!(d1.reason, d2.reason);
    }
}
