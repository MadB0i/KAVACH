use crate::exit::ExitCode;
use crate::output::{CliOutput, OutputMode};

/// Typed CLI error with stable exit code and sanitized message.
#[derive(Debug)]
pub struct CliError {
    pub code: ExitCode,
    pub message: String,
    pub mode: OutputMode,
}

impl CliError {
    pub fn new(code: ExitCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            mode: OutputMode::Human,
        }
    }

    pub fn render(&self) {
        let output = CliOutput::error(&self.message);
        output.render_error(self.mode);
    }

    pub fn exit(&self) -> ! {
        self.render();
        self.code.exit();
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ExitCode::InternalError, format!("I/O error: {e}"))
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(ExitCode::InvalidInput, format!("JSON error: {e}"))
    }
}
