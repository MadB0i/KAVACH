#![allow(clippy::unwrap_used, unused_imports)]

use crate::{CompositeRedactor, Redactor};
use proptest::prelude::*;

fn build_redactor() -> CompositeRedactor {
    CompositeRedactor::builder()
        .with_bearer(true)
        .with_jwt(true)
        .with_pem(true)
        .with_assignments(true)
        .with_github(true)
        .with_aws(true)
        .build()
}

proptest! {
    #[test]
    fn redaction_is_idempotent(input in ".{0,200}") {
        let redactor = build_redactor();
        let first = redactor.redact_text(&input).unwrap();
        let second = redactor.redact_text(&first.redacted).unwrap();
        assert_eq!(first.redacted, second.redacted, "redaction must be idempotent");
    }

    #[test]
    fn redact_empty_text_returns_empty(input in "") {
        let redactor = build_redactor();
        let result = redactor.redact_text(&input).unwrap();
        assert_eq!(result.redacted, "");
        assert!(!result.changed);
    }

    #[test]
    fn redact_bearer_token(prefix in ".{0,5}", token in "[A-Za-z0-9_-]{10,32}", suffix in "[[:punct:] ]{0,5}") {
        let haystack = format!("{} Bearer {}{}", prefix, token, suffix);
        let redactor = crate::CompositeRedactor::builder().with_bearer(true).build();
        let result = redactor.redact_text(&haystack).unwrap();
        assert!(result.changed, "Bearer token must be detected");
        assert!(result.redacted.contains("[REDACTED"), "redacted text must contain markers");
    }
}
