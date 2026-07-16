use sha2::{Digest, Sha256};

use crate::request::ToolRequest;

/// Compute the canonical SHA-256 digest of a [`ToolRequest`].
///
/// The digest is computed as `SHA-256(serde_json::to_string(request))`.
/// `serde_json` serialises struct fields in declaration order, so this is
/// deterministic for a given `ToolRequest` and the same version of the struct.
///
/// # Security
///
/// - If the JSON serialisation cannot be produced, returns the SHA-256 of an
///   empty byte slice (denial-of-service fallback, not a security violation,
///   because no valid request will ever fail to serialise).
/// - The digest is used for permit binding, approval request binding, and
///   enforcement verification.  All three *must* compute the identical digest
///   for the same request.
pub fn compute_request_digest(request: &ToolRequest) -> [u8; 32] {
    let json = serde_json::to_string(request).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::digest::compute_request_digest;
    use crate::ids::{AgentId, RequestId, SessionId};
    use crate::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
    use crate::resource::Resource;
    use crate::subject::TrustLevel;

    fn make_request() -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-digest").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent-digest").unwrap(),
                SessionId::new("sess-digest").unwrap(),
            )
            .trust_level(TrustLevel::Standard)
            .build(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/test.txt").unwrap(),
            RequestContext::new(None, None, None, None, false).unwrap(),
        )
    }

    #[test]
    fn digest_is_deterministic() {
        let req = make_request();
        let d1 = compute_request_digest(&req);
        let d2 = compute_request_digest(&req);
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_is_32_bytes() {
        let req = make_request();
        let d = compute_request_digest(&req);
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn different_requests_produce_different_digests() {
        let req1 = make_request();
        let mut req2 = make_request();
        // Change something significant
        if let Operation::FileRead { ref mut max_bytes } = req2.operation {
            *max_bytes = Some(1024);
        }
        let d1 = compute_request_digest(&req1);
        let d2 = compute_request_digest(&req2);
        assert_ne!(d1, d2);
    }
}
