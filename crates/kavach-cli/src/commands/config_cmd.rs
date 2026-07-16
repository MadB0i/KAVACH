use std::path::Path;

use crate::error::CliError;
use crate::exit::ExitCode;
use crate::output::{CliOutput, OutputMode};

pub fn validate(path: &str, mode: OutputMode) -> Result<(), CliError> {
    let path = Path::new(path);
    if !path.is_file() {
        return Err(CliError::new(
            ExitCode::InvalidInput,
            format!("config file not found: {}", path.display()),
        ));
    }

    match kavach_config::load_config(path) {
        Ok(_cfg) => {
            let output = CliOutput::with_message(format!("config is valid: {}", path.display()));
            output.render(mode);
            Ok(())
        }
        Err(e) => {
            let msg = match &e {
                kavach_config::ConfigError::Io(inner) => format!("I/O error: {inner}"),
                kavach_config::ConfigError::Parse(detail) => format!("parse error: {detail}"),
                kavach_config::ConfigError::Validation(detail) => {
                    format!("validation error: {detail}")
                }
                kavach_config::ConfigError::Env(detail) => format!("environment error: {detail}"),
            };
            Err(CliError::new(ExitCode::InvalidInput, msg))
        }
    }
}
