use std::path::Path;

use crate::error::CliError;
use crate::exit::ExitCode;
use crate::output::{CliOutput, OutputMode};

pub fn validate(path: &str, mode: OutputMode) -> Result<(), CliError> {
    let request_path = Path::new(path);
    if !request_path.is_file() {
        return Err(CliError::new(
            ExitCode::InvalidInput,
            format!("request file not found: {}", request_path.display()),
        ));
    }

    let contents = std::fs::read_to_string(request_path)
        .map_err(|e| CliError::new(ExitCode::InternalError, format!("failed to read file: {e}")))?;

    let request: kavach_core::request::ToolRequest = serde_json::from_str(&contents)
        .map_err(|e| CliError::new(ExitCode::InvalidInput, format!("invalid JSON: {e}")))?;

    request
        .validate()
        .map_err(|e| CliError::new(ExitCode::InvalidInput, format!("validation failed: {e}")))?;

    let output = CliOutput::with_data(serde_json::json!({
        "request_id": request.request_id.to_string(),
        "operation": request.operation.as_str(),
        "valid": true,
    }));
    output.render(mode);
    Ok(())
}
