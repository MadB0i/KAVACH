#![allow(clippy::unwrap_used, unused_imports)]

use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use kavach_policy::{DefaultEffect, Effect, Policy, Rule, RuleConditions};
use kavach_runtime::config::RuntimeConfig;
use kavach_runtime::outcome::RuntimeOutcome;
use kavach_runtime::runtime::RuntimeBuilder;
use proptest::prelude::*;
use std::time::Duration;

fn build_approval_policy() -> Policy {
    Policy {
        id: PolicyId::new("prop-approval").unwrap(),
        name: "prop-test".into(),
        description: "".into(),
        default_effect: DefaultEffect::Deny,
        rules: vec![
            Rule {
                id: RuleId::new("require-approval").unwrap(),
                description: "".into(),
                effect: Effect::RequireApproval,
                conditions: RuleConditions {
                    operations: vec!["file_delete".into()],
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("allow-read").unwrap(),
                description: "".into(),
                effect: Effect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            },
        ],
    }
}

proptest! {
    #[test]
    fn approval_required_for_delete(agent in "[a-zA-Z0-9_-]{1,16}", path in "[a-zA-Z0-9/._-]{1,40}") {
        let ws = std::env::temp_dir().join("kavach-prop-approval");
        let _ = std::fs::create_dir_all(&ws);
        let runtime = RuntimeBuilder::new()
            .with_config(RuntimeConfig { permit_ttl: Duration::from_secs(60), ..Default::default() })
            .with_workspace_root(ws.clone())
            .add_policy(build_approval_policy())
            .build().unwrap();
        let req = ToolRequest::new(
            RequestId::new("prop-req").unwrap(),
            AgentSubjectBuilder::new(AgentId::new(&agent).unwrap(), SessionId::new("prop-sess").unwrap())
                .trust_level(TrustLevel::Standard).build(),
            Operation::FileDelete,
            Resource::file(&path).unwrap_or_else(|_| Resource::file("/tmp/file.txt").unwrap()),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );
        let outcome = runtime.evaluate(&req).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::ApprovalRequired { .. }),
            "file delete must always require approval");
    }

    #[test]
    fn read_is_permitted_for_any_path(agent in "[a-zA-Z0-9_-]{1,16}", path in "[a-zA-Z0-9/._-]{1,40}") {
        let ws = std::env::temp_dir().join("kavach-prop-approval-2");
        let _ = std::fs::create_dir_all(&ws);
        let runtime = RuntimeBuilder::new()
            .with_config(RuntimeConfig { permit_ttl: Duration::from_secs(60), ..Default::default() })
            .with_workspace_root(ws.clone())
            .add_policy(build_approval_policy())
            .build().unwrap();
        let req = ToolRequest::new(
            RequestId::new("prop-req-2").unwrap(),
            AgentSubjectBuilder::new(AgentId::new(&agent).unwrap(), SessionId::new("prop-sess").unwrap())
                .trust_level(TrustLevel::Standard).build(),
            Operation::FileRead { max_bytes: Some(1024) },
            Resource::file(&path).unwrap_or_else(|_| Resource::file("/tmp/file.txt").unwrap()),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );
        let outcome = runtime.evaluate(&req).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Permitted(_)),
            "file read must always be permitted by policy");
    }
}
