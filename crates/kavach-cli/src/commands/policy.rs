use std::path::Path;

use crate::error::CliError;
use crate::exit::ExitCode;
use crate::output::{CliOutput, OutputMode};

fn load_policy(path: &str) -> Result<kavach_policy::Policy, CliError> {
    let policy_path = Path::new(path);
    if !policy_path.is_file() {
        return Err(CliError::new(
            ExitCode::InvalidInput,
            format!("policy file not found: {path}"),
        ));
    }
    kavach_policy::load_policy_from_file(policy_path).map_err(|e| {
        let msg = match &e {
            kavach_policy::PolicyLoadError::Io(detail) => format!("I/O error: {detail}"),
            kavach_policy::PolicyLoadError::FileTooLarge => {
                "policy file exceeds maximum size (1 MiB)".into()
            }
            kavach_policy::PolicyLoadError::Parse(detail) => format!("parse error: {detail}"),
            kavach_policy::PolicyLoadError::Validation(inner) => {
                format!("validation error: {inner}")
            }
            kavach_policy::PolicyLoadError::InvalidRuleId(id, detail) => {
                format!("invalid rule ID '{id}': {detail}")
            }
            kavach_policy::PolicyLoadError::InvalidPolicyId(id, detail) => {
                format!("invalid policy ID '{id}': {detail}")
            }
            kavach_policy::PolicyLoadError::UnsupportedSchemaVersion(v) => {
                format!("unsupported schema version: {v}")
            }
        };
        CliError::new(ExitCode::PolicyError, msg)
    })
}

fn load_request(path: &str) -> Result<kavach_core::request::ToolRequest, CliError> {
    let request_path = Path::new(path);
    if !request_path.is_file() {
        return Err(CliError::new(
            ExitCode::InvalidInput,
            format!("request file not found: {path}"),
        ));
    }
    let contents = std::fs::read_to_string(request_path).map_err(|e| {
        CliError::new(
            ExitCode::InternalError,
            format!("failed to read request: {e}"),
        )
    })?;
    let request: kavach_core::request::ToolRequest = serde_json::from_str(&contents)
        .map_err(|e| CliError::new(ExitCode::InvalidInput, format!("invalid request JSON: {e}")))?;
    request.validate().map_err(|e| {
        CliError::new(
            ExitCode::InvalidInput,
            format!("request validation failed: {e}"),
        )
    })?;
    Ok(request)
}

pub fn validate(path: &str, mode: OutputMode) -> Result<(), CliError> {
    let policy = load_policy(path)?;
    let rule_count = policy.rules.len();
    let effect_str = format!("{:?}", policy.default_effect);
    let output = CliOutput::with_data(serde_json::json!({
        "policy_id": policy.id.to_string(),
        "name": policy.name,
        "default_effect": effect_str,
        "rule_count": rule_count,
        "valid": true,
    }));
    output.render(mode);
    Ok(())
}

pub fn check(policy_path: &str, request_path: &str, mode: OutputMode) -> Result<(), CliError> {
    let policy = load_policy(policy_path)?;
    let request = load_request(request_path)?;

    let engine = kavach_policy::PolicyEngine::new(vec![policy])
        .map_err(|e| CliError::new(ExitCode::PolicyError, format!("engine build failed: {e}")))?;

    let decision = engine.evaluate(&request);
    let effect_str = format!("{:?}", decision.effect);
    let reason_str = format!("{:?}", decision.reason);
    let matched: Vec<String> = decision
        .matched_rule_ids
        .iter()
        .map(|r| r.to_string())
        .collect();

    let is_ok = matches!(
        decision.effect,
        kavach_core::decision::DecisionEffect::Allow
    );
    let output = CliOutput::with_data(serde_json::json!({
        "effect": effect_str,
        "reason": reason_str,
        "explanation": decision.explanation,
        "matched_rule_ids": matched,
        "allowed": is_ok,
    }));
    output.render(mode);

    if !is_ok {
        let has_approval = matches!(
            decision.effect,
            kavach_core::decision::DecisionEffect::RequireApproval
        );
        let code = if has_approval {
            ExitCode::ApprovalRequired
        } else {
            ExitCode::Deny
        };
        Err(CliError::new(code, decision.explanation))
    } else {
        Ok(())
    }
}

pub fn explain(policy_path: &str, request_path: &str, mode: OutputMode) -> Result<(), CliError> {
    let policy = load_policy(policy_path)?;
    let request = load_request(request_path)?;

    let engine = kavach_policy::PolicyEngine::new(vec![policy])
        .map_err(|e| CliError::new(ExitCode::PolicyError, format!("engine build failed: {e}")))?;

    let decision = engine.evaluate(&request);
    let effect_str = format!("{:?}", decision.effect);
    let reason_str = format!("{:?}", decision.reason);
    let matched: Vec<String> = decision
        .matched_rule_ids
        .iter()
        .map(|r| r.to_string())
        .collect();

    let output = CliOutput::with_data(serde_json::json!({
        "effect": effect_str,
        "reason": reason_str,
        "explanation": decision.explanation,
        "matched_rule_ids": matched,
        "request_id": decision.request_id.to_string(),
    }));
    output.render(mode);
    Ok(())
}
