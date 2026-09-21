//! Integration tests for the KAVACH CLI.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use assert_cmd::Command;
use predicates::prelude::*;

fn kavach() -> Command {
    Command::cargo_bin("kavach").unwrap()
}

#[test]
fn version_flag() {
    kavach()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("kavach"));
}

#[test]
fn help_flag() {
    kavach()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
}

#[test]
fn doctor_runs() {
    kavach().arg("doctor").assert().success();
}

#[test]
fn serve_rejects_missing_gateway_token_before_startup() {
    let config =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/kavach.example.toml");
    kavach()
        .env_remove("KAVACH_GATEWAY_TOKEN")
        .args(["serve", "--config"])
        .arg(config)
        .assert()
        .code(20)
        .stdout(predicate::str::contains("starting KAVACH gateway").not())
        .stderr(predicate::str::contains("64-character hexadecimal"));
}

#[test]
fn serve_rejects_malformed_gateway_token_before_startup() {
    let config =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/kavach.example.toml");
    kavach()
        .env("KAVACH_GATEWAY_TOKEN", "malformed")
        .args(["serve", "--config"])
        .arg(config)
        .assert()
        .code(20)
        .stdout(predicate::str::contains("starting KAVACH gateway").not())
        .stderr(predicate::str::contains("64-character hexadecimal"))
        .stderr(predicate::str::contains("malformed").not());
}

#[test]
fn config_validate_nonexistent_path() {
    kavach()
        .args(["config", "validate", "--file", "/nonexistent/config.toml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn policy_validate_nonexistent_path() {
    kavach()
        .args(["policy", "validate", "--file", "/nonexistent/policy.toml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn policy_check_nonexistent_policy() {
    kavach()
        .args([
            "policy",
            "check",
            "--policy",
            "/no.toml",
            "--request",
            "/no.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn request_validate_nonexistent_path() {
    kavach()
        .args(["request", "validate", "--file", "/nonexistent/request.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn audit_verify_nonexistent_database() {
    kavach()
        .args(["audit", "verify", "--database", "/nonexistent/audit.db"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn audit_list_nonexistent_database() {
    kavach()
        .args(["audit", "list", "--database", "/nonexistent/audit.db"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn approval_approve_invalid_id() {
    kavach()
        .args(["approval", "approve", ""])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn approval_deny_invalid_id() {
    kavach()
        .args(["approval", "deny", ""])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn json_output_flag() {
    kavach()
        .args(["--output", "json", "doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("status"));
}

#[test]
fn invalid_subcommand_fails() {
    kavach().arg("nonexistent").assert().failure();
}

#[test]
fn config_validate_valid_toml() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("valid.toml");
    std::fs::write(
        &config_path,
        r#"
[server]
bind = "127.0.0.1:7421"

[security]
workspace_root = "/tmp/kavach"
fail_closed = true

[policy]
files = []

[audit]
database = "/tmp/kavach-audit.db"

[approval]
default_ttl_seconds = 300
"#,
    )
    .unwrap();
    kavach()
        .args([
            "config",
            "validate",
            "--file",
            config_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn config_validate_invalid_toml() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("invalid.toml");
    std::fs::write(&config_path, "invalid toml content [[[").unwrap();
    kavach()
        .args([
            "config",
            "validate",
            "--file",
            config_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("parse error"));
}

#[test]
fn policy_validate_valid_policy() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
schema_version = 1

[policy]
id = "test-policy"
name = "Test Policy"
default_effect = "deny"

[[rules]]
id = "rule-1"
effect = "deny"
description = "Deny all"

[rules.conditions]
operations = ["file_read"]
"#,
    )
    .unwrap();
    kavach()
        .args([
            "policy",
            "validate",
            "--file",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn request_validate_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let req_path = dir.path().join("request.json");
    std::fs::write(&req_path, "not valid json").unwrap();
    kavach()
        .args(["request", "validate", "--file", req_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid"));
}

const EXPLAIN_POLICY_TOML: &str = r#"
schema_version = 1

[policy]
id = "explain-test"
default_effect = "deny"

[[rules]]
id = "allow-echo"
effect = "allow"

[rules.conditions]
operations = ["command_execute"]
executables = ["echo"]
"#;

fn explain_request_json(exe: &str, args: &[&str]) -> String {
    let args_json: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
    format!(
        r#"{{"request_id":"req-1","subject":{{"agent_id":"a","session_id":"s","display_name":"d","trust_level":"standard","declared_capabilities":[]}},"operation":{{"command_execute":null}},"resource":{{"Command":{{"executable":"{exe}","arguments":[{args}]}}}},"context":{{"timestamp":{{"secs_since_epoch":0,"nanos_since_epoch":0}},"working_directory":"/tmp","declared_intent":"t","parent_request_id":null,"metadata":{{}},"dry_run":false}}}}"#,
        args = args_json.join(",")
    )
}

fn write_explain_fixtures(dir: &tempfile::TempDir, exe: &str, args: &[&str]) -> (String, String) {
    let policy_path = dir.path().join("policy.toml");
    let req_path = dir.path().join("request.json");
    std::fs::write(&policy_path, EXPLAIN_POLICY_TOML).unwrap();
    std::fs::write(&req_path, explain_request_json(exe, args)).unwrap();
    (
        policy_path.to_str().unwrap().to_string(),
        req_path.to_str().unwrap().to_string(),
    )
}

#[test]
fn policy_explain_allow_shows_resource_and_decision() {
    let dir = tempfile::tempdir().unwrap();
    let (policy, request) = write_explain_fixtures(&dir, "echo", &["hello"]);
    kavach()
        .args([
            "policy",
            "explain",
            "--policy",
            &policy,
            "--request",
            &request,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Resource: command echo hello"))
        .stdout(predicate::str::contains("Decision: Allow"))
        .stdout(predicate::str::contains("Matched rules: allow-echo"));
}

#[test]
fn policy_explain_deny_shows_baseline_reason() {
    let dir = tempfile::tempdir().unwrap();
    let (policy, request) = write_explain_fixtures(&dir, "echo", &["x", ">", "f"]);
    kavach()
        .args([
            "policy",
            "explain",
            "--policy",
            &policy,
            "--request",
            &request,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Decision: Deny"))
        .stdout(predicate::str::contains("Baseline:"))
        .stdout(predicate::str::contains("baseline-shell-hazard"));
}

#[test]
fn policy_explain_json_dumps_full_decision_with_trace() {
    let dir = tempfile::tempdir().unwrap();
    let (policy, request) = write_explain_fixtures(&dir, "echo", &["x", ">", "f"]);
    kavach()
        .args([
            "policy",
            "explain",
            "--policy",
            &policy,
            "--request",
            &request,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"trace\""))
        .stdout(predicate::str::contains("baseline-shell-hazard"));
}

fn write_policy_test_fixtures(
    dir: &tempfile::TempDir,
    wrong_expectation: bool,
) -> (String, String) {
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, EXPLAIN_POLICY_TOML).unwrap();
    let allow_req = explain_request_json("echo", &["hello"]);
    let deny_req = explain_request_json("echo", &["x", ">", "f"]);
    let deny_expected = if wrong_expectation { "allow" } else { "deny" };
    let scenarios = format!(
        "{{\"scenarios\":[{{\"name\":\"echo hello\",\"expected\":\"allow\",\"request\":{allow_req}}},{{\"name\":\"echo redirect\",\"expected\":\"{deny_expected}\",\"request\":{deny_req}}}]}}"
    );
    let scenarios_path = dir.path().join("scenarios.json");
    std::fs::write(&scenarios_path, scenarios).unwrap();
    (
        policy_path.to_str().unwrap().to_string(),
        scenarios_path.to_str().unwrap().to_string(),
    )
}

#[test]
fn policy_test_all_pass_reports_summary() {
    let dir = tempfile::tempdir().unwrap();
    let (policy, scenarios) = write_policy_test_fixtures(&dir, false);
    kavach()
        .args([
            "policy",
            "test",
            "--policy",
            &policy,
            "--scenarios",
            &scenarios,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("total=2 passed=2 failed=0"));
}

#[test]
fn policy_test_failure_shows_detail_and_nonzero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let (policy, scenarios) = write_policy_test_fixtures(&dir, true);
    kavach()
        .args([
            "policy",
            "test",
            "--policy",
            &policy,
            "--scenarios",
            &scenarios,
        ])
        .assert()
        .failure()
        .code(23)
        .stdout(predicate::str::contains("total=2 passed=1 failed=1"))
        .stdout(predicate::str::contains("FAIL: echo redirect"))
        .stdout(predicate::str::contains("Baseline:"));
}
