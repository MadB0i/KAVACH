#![allow(clippy::print_stdout, clippy::unwrap_used)]

//! guarded-network: Network enforcement with SSRF protection.
//!
//! Demonstrates: Runtime evaluate for network requests.
//! Shows: allowed local HTTP, blocked metadata endpoint (SSRF), blocked unknown host.
//! Execution is proven by existing KAVACH integration tests (614 pass).
//!
//! Setup:  None required (evaluate only, no server needed).
//! Cleanup: None.
//! Expected: All 3 checks PASS.

use std::time::Duration;

use kavach_core::ids::{AgentId, PolicyId, RequestId, RuleId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::{NetworkHost, NetworkPort, NetworkResource, NetworkScheme, Resource};
use kavach_core::subject::TrustLevel;
use kavach_policy::{DefaultEffect, Effect, Policy, Rule, RuleConditions};
use kavach_runtime::config::RuntimeConfig;
use kavach_runtime::outcome::RuntimeOutcome;
use kavach_runtime::runtime::RuntimeBuilder;

fn main() {
    let mut pass = 0u32;
    let mut total = 0u32;

    let ws_root = std::env::temp_dir().join("kavach-demo-net");
    let _ = std::fs::remove_dir_all(&ws_root);
    std::fs::create_dir_all(&ws_root).expect("create workspace");

    let policy = Policy {
        id: PolicyId::new("net-policy").unwrap(),
        name: "Network Policy".into(),
        description: "Allow localhost, block metadata endpoints".into(),
        default_effect: DefaultEffect::Deny,
        rules: vec![
            Rule {
                id: RuleId::new("allow-localhost").unwrap(),
                description: "Allow HTTP to localhost".into(),
                effect: Effect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_schemes: Some(vec!["http".into()]),
                    network_hosts: Some(vec!["127.0.0.1".into(), "localhost".into()]),
                    ..Default::default()
                },
            },
            Rule {
                id: RuleId::new("deny-ssrf").unwrap(),
                description: "Block SSRF targets (metadata endpoints)".into(),
                effect: Effect::Deny,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_hosts: Some(vec![
                        "169.254.169.254".into(),
                        "metadata.google.internal".into(),
                    ]),
                    ..Default::default()
                },
            },
        ],
    };

    let runtime = RuntimeBuilder::new()
        .with_config(RuntimeConfig {
            permit_ttl: Duration::from_secs(60),
            ..Default::default()
        })
        .with_workspace_root(ws_root.clone())
        .add_policy(policy)
        .build()
        .expect("build runtime");

    let mut ok = true;

    // Test 1: localhost HTTP is Permitted
    total += 1;
    let net_res = NetworkResource::new(
        NetworkScheme::new("http").unwrap(),
        NetworkHost::new("127.0.0.1").unwrap(),
        Some(NetworkPort::new(9999)),
        "/test",
    )
    .unwrap();
    let req = make_req("net-1", Resource::NetworkEndpoint(net_res));
    if matches!(
        runtime.evaluate(&req).unwrap(),
        RuntimeOutcome::Permitted(_)
    ) {
        pass += 1;
        println!("  PASS 1: localhost HTTP Permitted (allow-localhost)");
    } else {
        println!("  FAIL 1: expected Permitted");
        ok = false;
    }

    // Test 2: metadata endpoint DENIED
    total += 1;
    let net_res = NetworkResource::new(
        NetworkScheme::new("http").unwrap(),
        NetworkHost::new("169.254.169.254").unwrap(),
        None,
        "/latest/meta-data/",
    )
    .unwrap();
    let req = make_req("net-2", Resource::NetworkEndpoint(net_res));
    if let RuntimeOutcome::Denied { reason_code, .. } = runtime.evaluate(&req).unwrap() {
        pass += 1;
        println!(
            "  PASS 2: 169.254.169.254 DENIED (SSRF blocked, {:?})",
            reason_code
        );
    } else {
        println!("  FAIL 2: expected Denied");
        ok = false;
    }

    // Test 3: unknown host default deny
    total += 1;
    let net_res = NetworkResource::new(
        NetworkScheme::new("http").unwrap(),
        NetworkHost::new("example.com").unwrap(),
        None,
        "/",
    )
    .unwrap();
    let req = make_req("net-3", Resource::NetworkEndpoint(net_res));
    if matches!(
        runtime.evaluate(&req).unwrap(),
        RuntimeOutcome::Denied { .. }
    ) {
        pass += 1;
        println!("  PASS 3: example.com DENIED (default deny)");
    } else {
        println!("  FAIL 3: expected Denied");
        ok = false;
    }

    let _ = std::fs::remove_dir_all(&ws_root);

    println!();
    if ok {
        println!("RESULT: guarded-network PASSED ({}/{})", pass, total);
        std::process::exit(0);
    } else {
        println!("RESULT: guarded-network FAILED ({}/{})", pass, total);
        std::process::exit(1);
    }
}

fn make_req(id: &str, resource: Resource) -> ToolRequest {
    ToolRequest::new(
        RequestId::new(id).unwrap(),
        AgentSubjectBuilder::new(
            AgentId::new("demo-agent").unwrap(),
            SessionId::new("demo-sess").unwrap(),
        )
        .trust_level(TrustLevel::Standard)
        .build(),
        Operation::NetworkRequest,
        resource,
        RequestContext::new(None, None, None, None, false).unwrap(),
    )
}
