use std::io::{IsTerminal, Write};
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

/// Evaluate a request against a policy file, returning the decision.
///
/// Shared by `check` and `explain` so both subcommands run the exact same
/// evaluation path.
fn evaluate(
    policy_path: &str,
    request_path: &str,
) -> Result<
    (
        kavach_core::request::ToolRequest,
        kavach_core::AuthorizationDecision,
    ),
    CliError,
> {
    let policy = load_policy(policy_path)?;
    let request = load_request(request_path)?;

    let engine = kavach_policy::PolicyEngine::new(vec![policy])
        .map_err(|e| CliError::new(ExitCode::PolicyError, format!("engine build failed: {e}")))?;

    let decision = engine.evaluate(&request);
    Ok((request, decision))
}

/// Resolve the decision-feed log path: explicit flag wins, then the
/// `KAVACH_FEED_LOG` environment variable, otherwise no feed output.
fn feed_log_path(flag: Option<&str>) -> Option<String> {
    flag.map(str::to_string).or_else(|| {
        std::env::var("KAVACH_FEED_LOG")
            .ok()
            .filter(|v| !v.is_empty())
    })
}

pub fn check(
    policy_path: &str,
    request_path: &str,
    mode: OutputMode,
    feed_log: Option<&str>,
) -> Result<(), CliError> {
    let (request, decision) = evaluate(policy_path, request_path)?;
    if let Some(feed) = feed_log_path(feed_log) {
        append_feed_log(&feed, &decision, &request)?;
    }
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

/// Summarize the targeted resource for display: `command <exe> <args>` or
/// the file/directory path. Pure echo of what was parsed, so input-parsing
/// mistakes are visible before the decision.
pub(crate) fn resource_summary(request: &kavach_core::request::ToolRequest) -> String {
    use kavach_core::resource::Resource;
    match &request.resource {
        Resource::Command(cmd) => {
            let mut parts = vec![shell_quote(cmd.executable())];
            parts.extend(cmd.arguments().iter().map(|a| shell_quote(a)));
            format!("command {}", parts.join(" "))
        }
        Resource::File { path } | Resource::Directory { path } => {
            format!("{} {}", request.resource.kind(), path.normalized())
        }
        Resource::NetworkEndpoint(net) => {
            let port = net
                .port()
                .map(|p| format!(":{}", p.value()))
                .unwrap_or_default();
            format!(
                "network_endpoint {}://{}{}{}",
                net.scheme(),
                net.host(),
                port,
                net.path().normalized()
            )
        }
        Resource::Secret { identifier } => format!("secret {identifier}"),
        Resource::ExternalTool { identifier } => format!("external_tool {identifier}"),
        Resource::Unknown => "unknown".to_string(),
        // `Resource` is non-exhaustive: future variants fail closed here.
        _ => "unknown".to_string(),
    }
}

/// Quote one shell word for display when it contains whitespace or shell
/// metacharacters; plain words pass through unchanged.
fn shell_quote(word: &str) -> String {
    if word.is_empty()
        || word.bytes().any(|b| {
            b.is_ascii_whitespace()
                || matches!(
                    b,
                    b'\''
                        | b'"'
                        | b'$'
                        | b'`'
                        | b'|'
                        | b';'
                        | b'&'
                        | b'('
                        | b')'
                        | b'<'
                        | b'>'
                        | b'\\'
                )
        })
    {
        format!("'{}'", word.replace('\'', "'\\''"))
    } else {
        word.to_string()
    }
}

/// Whether ANSI colors are enabled: explicitly disabled when `NO_COLOR` is
/// present (any value), otherwise only on tty stdout.
pub(crate) fn paint_enabled(no_color_present: bool, is_tty: bool) -> bool {
    !no_color_present && is_tty
}

fn runtime_paint_enabled() -> bool {
    paint_enabled(
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    )
}

/// Wrap `text` in an ANSI color code when `enabled`, else return it plain.
pub(crate) fn paint(code: u8, text: &str, enabled: bool) -> String {
    if enabled {
        format!("\u{1b}[{code}m{text}\u{1b}[0m")
    } else {
        text.to_string()
    }
}

fn paint_effect(effect: kavach_core::DecisionEffect, enabled: bool) -> String {
    use kavach_core::DecisionEffect;
    let label = format!("{effect:?}");
    match effect {
        DecisionEffect::Allow => paint(32, &label, enabled),
        DecisionEffect::Deny => paint(31, &label, enabled),
        DecisionEffect::RequireApproval => paint(33, &label, enabled),
    }
}

/// Human-readable explanation of a decision: resource echo, color-coded
/// verdict, then baseline reason or matched rules / failed conditions.
///
/// `failed_conditions` are capped at 5 entries with a "+N more" note.
pub(crate) fn format_explain_human(
    decision: &kavach_core::AuthorizationDecision,
    request: &kavach_core::request::ToolRequest,
    color: bool,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Resource: {}", resource_summary(request));
    let _ = writeln!(out, "Decision: {}", paint_effect(decision.effect, color));
    if let Some(trace) = &decision.trace {
        if let Some(baseline) = &trace.baseline_triggered {
            let _ = writeln!(out, "Baseline: {baseline}");
        }
    }
    if decision.matched_rule_ids.is_empty() {
        let _ = writeln!(out, "Matched rules: (none)");
    } else {
        let ids: Vec<String> = decision
            .matched_rule_ids
            .iter()
            .map(|r| r.to_string())
            .collect();
        let _ = writeln!(out, "Matched rules: {}", ids.join(", "));
    }
    let failed: &[String] = decision
        .trace
        .as_ref()
        .map(|t| t.failed_conditions.as_slice())
        .unwrap_or(&[]);
    if !failed.is_empty() {
        const CAP: usize = 5;
        let shown: Vec<&str> = failed.iter().take(CAP).map(String::as_str).collect();
        let mut line = format!("Failed conditions: {}", shown.join(", "));
        if failed.len() > CAP {
            line.push_str(&format!(" (+{} more)", failed.len() - CAP));
        }
        let _ = writeln!(out, "{line}");
    }
    let _ = writeln!(out, "Reason: {:?}", decision.reason);
    out
}

/// One JSONL feed line for the local dashboard: full decision fields plus
/// a resource summary (executable/args or path) for filtering.
pub(crate) fn decision_feed_line(
    decision: &kavach_core::AuthorizationDecision,
    request: &kavach_core::request::ToolRequest,
) -> serde_json::Value {
    use kavach_core::resource::Resource;
    let resource = match &request.resource {
        Resource::Command(cmd) => serde_json::json!({
            "kind": "command",
            "executable": cmd.executable(),
            "arguments": cmd.arguments(),
        }),
        Resource::File { path } | Resource::Directory { path } => serde_json::json!({
            "kind": request.resource.kind().to_string(),
            "path": path.normalized(),
        }),
        Resource::NetworkEndpoint(net) => serde_json::json!({
            "kind": "network_endpoint",
            "host": net.host().as_str(),
            "scheme": net.scheme().as_str(),
        }),
        Resource::Secret { identifier } => serde_json::json!({
            "kind": "secret",
            "identifier": identifier,
        }),
        Resource::ExternalTool { identifier } => serde_json::json!({
            "kind": "external_tool",
            "identifier": identifier,
        }),
        Resource::Unknown => serde_json::json!({ "kind": "unknown" }),
        // `Resource` is non-exhaustive: future variants fail closed here.
        _ => serde_json::json!({ "kind": "unknown" }),
    };
    let evaluated_at_secs = decision
        .evaluated_at
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    serde_json::json!({
        "source": "cli",
        "effect": format!("{:?}", decision.effect),
        "reason": format!("{:?}", decision.reason),
        "explanation": decision.explanation,
        "matched_rule_ids": decision.matched_rule_ids.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        "request_id": decision.request_id.to_string(),
        "evaluated_at_secs": evaluated_at_secs,
        "resource": resource,
        "trace": decision.trace.as_ref().map(|t| serde_json::json!({
            "baseline_triggered": t.baseline_triggered,
            "failed_conditions": t.failed_conditions,
        })),
    })
}

/// Append one feed line to the dashboard decision log. Explicitly requested
/// via `--feed-log`/`KAVACH_FEED_LOG`, so a write failure is a hard error.
fn append_feed_log(
    path: &str,
    decision: &kavach_core::AuthorizationDecision,
    request: &kavach_core::request::ToolRequest,
) -> Result<(), CliError> {
    use std::fs::OpenOptions;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = decision_feed_line(decision, request);
    writeln!(file, "{}", serde_json::to_string(&line)?)?;
    Ok(())
}

/// One policy-test scenario: a request plus the expected decision effect.
///
/// Scenario files are JSON: `{"scenarios": [{"name", "expected", "request"
/// | "request_file"}]}`. `expected` is `allow`, `deny` or `require_approval`
/// (case-insensitive). The inline `request` object uses the exact same
/// ToolRequest JSON format as `policy check --request`; `request_file` is an
/// alternative path, resolved relative to the scenarios file's directory.
#[derive(Debug, serde::Deserialize)]
struct TestScenario {
    name: String,
    expected: String,
    request: Option<serde_json::Value>,
    request_file: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct TestScenarioFile {
    scenarios: Vec<TestScenario>,
}

/// Normalize an expected/actual effect label for comparison.
///
/// Accepts `Deny`, `deny`, `RequireApproval`, `require_approval` and
/// `require-approval` alike.
pub(crate) fn normalize_effect_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len() + 2);
    let mut prev_lower = false;
    for c in label.trim().chars() {
        if c == '-' || c == ' ' {
            out.push('_');
            prev_lower = false;
        } else if c.is_ascii_uppercase() {
            if prev_lower {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
            prev_lower = false;
        } else {
            out.push(c);
            prev_lower = c.is_ascii_lowercase();
        }
    }
    out
}

fn build_scenario_request(
    scenario: &TestScenario,
    scenarios_dir: &Path,
) -> Result<kavach_core::request::ToolRequest, CliError> {
    if let Some(path) = &scenario.request_file {
        let full = if Path::new(path).is_absolute() {
            path.clone()
        } else {
            scenarios_dir.join(path).to_string_lossy().into_owned()
        };
        return load_request(&full);
    }
    let value = scenario.request.as_ref().ok_or_else(|| {
        CliError::new(
            ExitCode::InvalidInput,
            format!(
                "scenario '{}' needs either 'request' or 'request_file'",
                scenario.name
            ),
        )
    })?;
    // Round-trip through text: several core newtypes deserialize from a
    // borrowed `&str`, which `serde_json::from_value` cannot provide.
    let text = serde_json::to_string(value).map_err(|e| {
        CliError::new(
            ExitCode::InvalidInput,
            format!("scenario '{}' has invalid request JSON: {e}", scenario.name),
        )
    })?;
    let request: kavach_core::request::ToolRequest = serde_json::from_str(&text).map_err(|e| {
        CliError::new(
            ExitCode::InvalidInput,
            format!("scenario '{}' has invalid request JSON: {e}", scenario.name),
        )
    })?;
    request.validate().map_err(|e| {
        CliError::new(
            ExitCode::InvalidInput,
            format!(
                "scenario '{}' request validation failed: {e}",
                scenario.name
            ),
        )
    })?;
    Ok(request)
}

pub fn test_policy(
    policy_path: &str,
    scenarios_path: &str,
    mode: OutputMode,
) -> Result<(), CliError> {
    let policy = load_policy(policy_path)?;
    let engine = kavach_policy::PolicyEngine::new(vec![policy])
        .map_err(|e| CliError::new(ExitCode::PolicyError, format!("engine build failed: {e}")))?;

    let scenarios_file = Path::new(scenarios_path);
    if !scenarios_file.is_file() {
        return Err(CliError::new(
            ExitCode::InvalidInput,
            format!("scenarios file not found: {scenarios_path}"),
        ));
    }
    let contents = std::fs::read_to_string(scenarios_file)?;
    let parsed: TestScenarioFile = serde_json::from_str(&contents).map_err(|e| {
        CliError::new(
            ExitCode::InvalidInput,
            format!("invalid scenarios JSON: {e}"),
        )
    })?;
    let scenarios_dir = scenarios_file.parent().unwrap_or_else(|| Path::new("."));

    let mut passed = 0usize;
    let mut failures: Vec<(String, String, String)> = Vec::new();
    for scenario in &parsed.scenarios {
        let request = build_scenario_request(scenario, scenarios_dir)?;
        let decision = engine.evaluate(&request);
        let actual = normalize_effect_label(&format!("{:?}", decision.effect));
        let expected = normalize_effect_label(&scenario.expected);
        if actual == expected {
            passed += 1;
        } else {
            let detail = format_explain_human(&decision, &request, runtime_paint_enabled());
            failures.push((scenario.name.clone(), scenario.expected.clone(), detail));
        }
    }

    let total = parsed.scenarios.len();
    let failed = failures.len();
    if mode == OutputMode::Json {
        let output = CliOutput::with_data(serde_json::json!({
            "total": total,
            "passed": passed,
            "failed": failed,
            "failures": failures.iter().map(|(name, expected, _)| {
                serde_json::json!({ "scenario": name, "expected": expected })
            }).collect::<Vec<_>>(),
        }));
        output.render(mode);
    } else {
        let mut out = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(
            out,
            "policy test: total={total} passed={passed} failed={failed}"
        );
        for (name, expected, detail) in &failures {
            let _ = writeln!(out, "--- FAIL: {name} (expected {expected}) ---");
            let _ = write!(out, "{detail}");
        }
        let _ = write!(std::io::stdout().lock(), "{out}");
    }

    if failed > 0 {
        return Err(CliError::new(
            ExitCode::TestFailures,
            format!("{failed}/{total} policy test scenarios failed"),
        ));
    }
    Ok(())
}

pub fn explain(
    policy_path: &str,
    request_path: &str,
    mode: OutputMode,
    json_full: bool,
    feed_log: Option<&str>,
) -> Result<(), CliError> {
    let (request, decision) = evaluate(policy_path, request_path)?;
    if let Some(feed) = feed_log_path(feed_log) {
        append_feed_log(&feed, &decision, &request)?;
    }

    if json_full {
        // Full AuthorizationDecision (including trace) for scripting.
        let value = serde_json::to_value(&decision)?;
        let text = serde_json::to_string_pretty(&value)?;
        let _ = writeln!(std::io::stdout().lock(), "{text}");
        return Ok(());
    }

    if mode == OutputMode::Json {
        // Envelope form, matching `check` conventions plus trace fields.
        let matched: Vec<String> = decision
            .matched_rule_ids
            .iter()
            .map(|r| r.to_string())
            .collect();
        let output = CliOutput::with_data(serde_json::json!({
            "effect": format!("{:?}", decision.effect),
            "reason": format!("{:?}", decision.reason),
            "explanation": decision.explanation,
            "matched_rule_ids": matched,
            "request_id": decision.request_id.to_string(),
            "resource": resource_summary(&request),
            "trace": decision.trace.as_ref().map(|t| serde_json::json!({
                "baseline_triggered": t.baseline_triggered,
                "failed_conditions": t.failed_conditions,
            })),
        }));
        output.render(mode);
        return Ok(());
    }

    let text = format_explain_human(&decision, &request, runtime_paint_enabled());
    let _ = write!(std::io::stdout().lock(), "{text}");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use kavach_core::decision::DecisionTrace;
    use kavach_core::ids::{AgentId, RequestId, SessionId};
    use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
    use kavach_core::resource::Resource;
    use kavach_core::{DecisionEffect, ReasonCode};
    use std::collections::BTreeSet;
    use std::time::SystemTime;

    fn subject() -> kavach_core::subject::AgentSubject {
        AgentSubjectBuilder::new(
            AgentId::new("agent-1").unwrap(),
            SessionId::new("sess-1").unwrap(),
        )
        .trust_level(kavach_core::subject::TrustLevel::Standard)
        .build()
    }

    fn context() -> RequestContext {
        RequestContext::new(None, None, None, None, false).unwrap()
    }

    fn cmd_request(exe: &str, args: &[&str]) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            subject(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new(
                    exe,
                    args.iter().map(|s| s.to_string()).collect(),
                )
                .unwrap(),
            ),
            context(),
        )
    }

    fn decision_with_trace(trace: DecisionTrace) -> kavach_core::AuthorizationDecision {
        kavach_core::AuthorizationDecision::new(
            DecisionEffect::Deny,
            ReasonCode::KavachDenyExplicitRule,
            "denied",
            BTreeSet::new(),
            SystemTime::UNIX_EPOCH,
            RequestId::new("req-1").unwrap(),
            None,
            None,
        )
        .with_trace(trace)
    }

    #[test]
    fn resource_summary_echoes_command() {
        let req = cmd_request("echo", &["x", ">", "file"]);
        assert_eq!(resource_summary(&req), "command echo x '>' file");
    }

    #[test]
    fn resource_summary_echoes_file_path() {
        let req = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/a.txt").unwrap(),
            context(),
        );
        assert_eq!(resource_summary(&req), "file /workspace/a.txt");
    }

    #[test]
    fn normalize_effect_label_handles_variants() {
        assert_eq!(normalize_effect_label("Deny"), "deny");
        assert_eq!(
            normalize_effect_label("RequireApproval"),
            "require_approval"
        );
        assert_eq!(
            normalize_effect_label("require-approval"),
            "require_approval"
        );
        assert_eq!(normalize_effect_label("  ALLOW "), "allow");
    }

    #[test]
    fn paint_respects_no_color_and_tty() {
        assert!(!paint_enabled(true, true));
        assert!(!paint_enabled(false, false));
        assert!(paint_enabled(false, true));
        assert_eq!(paint(31, "Deny", false), "Deny");
        assert_eq!(paint(31, "Deny", true), "\u{1b}[31mDeny\u{1b}[0m");
    }

    #[test]
    fn explain_shows_baseline_and_caps_failed_conditions() {
        let req = cmd_request("echo", &["x", ">", "file"]);
        let trace = DecisionTrace {
            baseline_triggered: Some("shell hazards in arguments: redirect_out".into()),
            failed_conditions: vec![
                "a".into(),
                "b".into(),
                "c".into(),
                "d".into(),
                "e".into(),
                "f".into(),
                "g".into(),
            ],
        };
        let text = format_explain_human(&decision_with_trace(trace), &req, false);
        assert!(text.contains("Resource: command echo x '>' file"), "{text}");
        assert!(text.contains("Decision: Deny"), "{text}");
        assert!(
            text.contains("Baseline: shell hazards in arguments: redirect_out"),
            "{text}"
        );
        assert!(
            text.contains("Failed conditions: a, b, c, d, e (+2 more)"),
            "{text}"
        );
    }
}
