#![allow(clippy::unwrap_used, unused_imports)]

use crate::digest::compute_request_digest;
use crate::ids::{AgentId, RequestId, SessionId};
use crate::permit::ExecutionPermit;
use crate::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use crate::resource::{CommandResource, NetworkHost, NetworkScheme, NormalizedPath, Resource};
use crate::subject::TrustLevel;
use proptest::prelude::*;

proptest! {
    #[test]
    fn agent_id_round_trip(id in "[a-zA-Z0-9_-]{1,32}") {
        let aid = AgentId::new(&id).unwrap();
        assert_eq!(aid.as_str(), id);
    }

    #[test]
    fn request_id_round_trip(id in "[a-zA-Z0-9_-]{1,64}") {
        let rid = RequestId::new(&id).unwrap();
        assert_eq!(rid.as_str(), id);
    }

    #[test]
    fn session_id_round_trip(id in "[a-zA-Z0-9_-]{1,32}") {
        let sid = SessionId::new(&id).unwrap();
        assert_eq!(sid.as_str(), id);
    }

    #[test]
    fn path_normalization_does_not_crash(path in ".{0,100}") {
        let _ = NormalizedPath::new(&path);
    }

    #[test]
    fn network_host_does_not_crash(host in ".{0,50}") {
        let _ = NetworkHost::new(&host);
    }

    #[test]
    fn network_scheme_does_not_crash(scheme in ".{0,20}") {
        let _ = NetworkScheme::new(&scheme);
    }

    #[test]
    fn command_resource_valid_does_not_panic(exe in "[a-zA-Z0-9]{1,16}", args in prop::collection::vec("[a-zA-Z0-9]{0,8}", 0..4)) {
        let _ = CommandResource::new(exe, args);
    }
}

proptest! {
    #[test]
    fn request_digest_is_deterministic(
        id in "[a-zA-Z0-9_-]{1,16}",
        agent in "[a-zA-Z0-9_-]{1,16}",
        session in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let req = ToolRequest::new(
            RequestId::new(&id).unwrap(),
            AgentSubjectBuilder::new(AgentId::new(&agent).unwrap(), SessionId::new(&session).unwrap())
                .trust_level(TrustLevel::Standard).build(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/test/path.txt").unwrap(),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );
        // Digest of the same request must be identical
        let d1 = compute_request_digest(&req);
        let d2 = compute_request_digest(&req);
        assert_eq!(d1, d2, "digest of same request must be deterministic");
    }
}

proptest! {
    #[test]
    fn permit_single_use_enforced(id in "[a-zA-Z0-9_-]{1,16}", scope in 0u8..3u8) {
        use std::time::Duration;
        use crate::permit::PermitScope;
        use crate::ids::RuleId;

        let rid = RequestId::new(&id).unwrap();
        let rule = RuleId::new("test-rule").unwrap();
        let digest = [0u8; 32];
        let scope_enum = match scope % 3 {
            0 => PermitScope::FilesystemRead,
            1 => PermitScope::CommandLowRisk,
            _ => PermitScope::NetworkRequest,
        };

        let mut permit = ExecutionPermit::new(
            &[0u8; 32], rid, scope_enum, vec![rule],
            digest, Duration::from_secs(60),
        );
        assert!(!permit.is_consumed(), "fresh permit must not be consumed");
        permit.consume();
        assert!(permit.is_consumed(), "consumed permit must report consumed");
    }
}
