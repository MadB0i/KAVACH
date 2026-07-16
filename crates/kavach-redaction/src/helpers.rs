use crate::error::RedactionError;
use crate::redactor::Redactor;
use crate::types::RedactionResult;

/// Redacts secrets from an error message string, returning only the redacted text.
pub fn redact_error_message(redactor: &dyn Redactor, msg: &str) -> Result<String, RedactionError> {
    let result = redactor.redact_text(msg)?;
    Ok(result.redacted)
}

/// Redacts secrets from a tracing field value.
pub fn redact_tracing_field(
    redactor: &dyn Redactor,
    field: &str,
) -> Result<String, RedactionError> {
    let result = redactor.redact_text(field)?;
    Ok(result.redacted)
}

/// Redacts secrets from command stdout and stderr byte buffers.
pub fn redact_command_output(
    redactor: &dyn Redactor,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(RedactionResult, RedactionResult), RedactionError> {
    let out_result = redactor.redact_bytes(stdout)?;
    let err_result = redactor.redact_bytes(stderr)?;
    Ok((out_result, err_result))
}

/// Redacts secrets from an HTTP response or request body.
pub fn redact_network_body(
    redactor: &dyn Redactor,
    body: &[u8],
) -> Result<RedactionResult, RedactionError> {
    redactor.redact_bytes(body)
}

/// Redacts secrets from a single HTTP header value.
pub fn redact_header_value(
    redactor: &dyn Redactor,
    value: &str,
) -> Result<RedactionResult, RedactionError> {
    redactor.redact_text(value)
}

/// Redacts secrets from a filesystem preview string (e.g. file reads for display).
pub fn redact_filesystem_preview(
    redactor: &dyn Redactor,
    preview: &str,
) -> Result<RedactionResult, RedactionError> {
    redactor.redact_text(preview)
}

/// Redacts secrets from an approval summary string.
pub fn redact_approval_summary(
    redactor: &dyn Redactor,
    summary: &str,
) -> Result<RedactionResult, RedactionError> {
    redactor.redact_text(summary)
}

/// Redacts secrets from an audit metadata string.
pub fn redact_audit_metadata(
    redactor: &dyn Redactor,
    metadata: &str,
) -> Result<RedactionResult, RedactionError> {
    redactor.redact_text(metadata)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::redactor::CompositeRedactor;

    #[test]
    fn error_message_redacted() {
        let redactor = CompositeRedactor::builder().build();
        let msg = "Failed to authenticate: Bearer tok12345678";
        let result = redact_error_message(&redactor, msg).unwrap();
        assert!(result.contains("[REDACTED:bearer_token]"));
        assert!(!result.contains("tok12345678"));
    }

    #[test]
    fn tracing_field_redacted() {
        let redactor = CompositeRedactor::builder().build();
        let field = "api_key = sk-abc123xyz456";
        let result = redact_tracing_field(&redactor, field).unwrap();
        assert!(result.contains("[REDACTED:"));
    }
}
