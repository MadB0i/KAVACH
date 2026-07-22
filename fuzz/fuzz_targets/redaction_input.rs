#![no_main]

use kavach_redaction::{CompositeRedactor, Redactor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let redactor = CompositeRedactor::builder()
        .with_bearer(true)
        .with_jwt(true)
        .with_pem(true)
        .with_assignments(true)
        .with_github(true)
        .with_aws(true)
        .build();

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = redactor.redact_text(s);
    }
    let _ = redactor.redact_bytes(data);
});
