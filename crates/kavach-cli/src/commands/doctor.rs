use std::path::Path;

use crate::error::CliError;
use crate::output::{CliOutput, OutputMode};

pub fn run(mode: OutputMode) -> Result<(), CliError> {
    let mut checks: Vec<serde_json::Value> = Vec::new();
    let mut all_ok = true;

    // Check workspace existence.
    let ws = Path::new(".");
    let ws_ok = ws.is_dir();
    checks.push(serde_json::json!({
        "check": "workspace_root",
        "status": if ws_ok { "ok" } else { "fail" },
        "path": ".",
    }));
    if !ws_ok {
        all_ok = false;
    }

    // Check config file.
    let config_paths = ["./kavach.toml", "./config/kavach.toml"];
    let config_ok = config_paths.iter().any(|p| Path::new(p).is_file());
    let found_config = config_paths.iter().find(|p| Path::new(p).is_file());
    checks.push(serde_json::json!({
        "check": "config",
        "status": if config_ok { "ok" } else { "warn" },
        "path": found_config.unwrap_or(&"not found"),
    }));

    // Check default policy path.
    let policy_path = Path::new("./config/default-policy.toml");
    let policy_ok = policy_path.is_file();
    checks.push(serde_json::json!({
        "check": "default_policy",
        "status": if policy_ok { "ok" } else { "warn" },
        "path": "./config/default-policy.toml",
    }));
    if !policy_ok {
        all_ok = false;
    }

    // Check default data directory.
    let data_dir = Path::new("./data");
    let data_ok = data_dir.is_dir();
    checks.push(serde_json::json!({
        "check": "data_directory",
        "status": if data_ok { "ok" } else { "warn" },
        "path": "./data",
    }));

    let overall = if all_ok { "ok" } else { "degraded" };
    let output = CliOutput::with_data(serde_json::json!({
        "overall": overall,
        "checks": checks,
    }));
    output.render(mode);
    Ok(())
}
