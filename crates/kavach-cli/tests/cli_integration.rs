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
