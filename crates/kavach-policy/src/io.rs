//! TOML policy document parsing and file loading.
//!
//! Supports one [Policy] per TOML document.

use crate::model::{DefaultEffect, Effect, Policy, PolicyValidationError, Rule, RuleConditions};
use kavach_core::ids::{PolicyId, RuleId};
use kavach_core::resource::ResourceKind;
use kavach_core::subject::TrustLevel;
use std::collections::BTreeSet;
use std::path::Path;

/// Maximum allowed size for a policy file (1 MiB).
pub const MAX_POLICY_FILE_SIZE: u64 = 1024 * 1024;

/// Errors that can arise during policy loading from TOML.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PolicyLoadError {
    /// I/O error reading the policy file.
    #[error("failed to read policy file: {0}")]
    Io(String),
    /// File exceeds the maximum allowed size.
    #[error("policy file exceeds maximum size of {} bytes", MAX_POLICY_FILE_SIZE)]
    FileTooLarge,
    /// TOML parse error (syntax, unknown enum variant, or unknown field).
    #[error("failed to parse policy TOML: {0}")]
    Parse(String),
    /// Policy validation error (empty conditions, duplicate rule IDs).
    #[error("{0}")]
    Validation(#[from] PolicyValidationError),
    /// Rule ID in the document failed core validation (e.g. empty or too long).
    #[error("invalid rule id '{0}': {1}")]
    InvalidRuleId(String, String),
    /// Policy ID in the document failed core validation.
    #[error("invalid policy id '{0}': {1}")]
    InvalidPolicyId(String, String),
    /// Schema version other than 1 was specified.
    #[error("unsupported schema_version: {0}; only 1 is supported")]
    UnsupportedSchemaVersion(u32),
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlDocument {
    schema_version: u32,
    policy: TomlPolicyHeader,
    #[serde(default)]
    rules: Vec<TomlRule>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlPolicyHeader {
    id: String,
    name: Option<String>,
    description: Option<String>,
    default_effect: DefaultEffect,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRule {
    id: String,
    description: Option<String>,
    effect: Effect,
    conditions: Option<TomlRuleConditions>,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlRuleConditions {
    #[serde(default)]
    operations: Vec<String>,
    #[serde(default)]
    resource_kinds: Vec<ResourceKind>,
    #[serde(default)]
    agent_ids: Vec<String>,
    min_trust_level: Option<TrustLevel>,
    #[serde(default)]
    required_capabilities: Vec<String>,
    intent_prefix: Option<String>,
    path_globs: Option<Vec<String>>,
    executables: Option<Vec<String>>,
    network_hosts: Option<Vec<String>>,
    network_schemes: Option<Vec<String>>,
    secret_identifiers: Option<Vec<String>>,
    tool_identifiers: Option<Vec<String>>,
    network_ports: Option<Vec<u16>>,
}

/// Load a [Policy] from a TOML file at the given path.
///
/// The file must not exceed [`MAX_POLICY_FILE_SIZE`] (1 MiB). The size is
/// checked via file metadata before reading and again after reading to handle
/// races or unusual filesystems.
pub fn load_policy_from_file(path: impl AsRef<Path>) -> Result<Policy, PolicyLoadError> {
    let path = path.as_ref();

    // Check size via metadata.
    let metadata = std::fs::metadata(path)
        .map_err(|e| PolicyLoadError::Io(format!("{}: {}", path.display(), e)))?;
    if metadata.len() > MAX_POLICY_FILE_SIZE {
        return Err(PolicyLoadError::FileTooLarge);
    }

    let contents = std::fs::read_to_string(path)
        .map_err(|e| PolicyLoadError::Io(format!("{}: {}", path.display(), e)))?;

    // Post-read size check (defence-in-depth).
    if contents.len() as u64 > MAX_POLICY_FILE_SIZE {
        return Err(PolicyLoadError::FileTooLarge);
    }

    load_policy_from_str(&contents)
}

/// Parse a [Policy] from a TOML string.
pub fn load_policy_from_str(toml_str: &str) -> Result<Policy, PolicyLoadError> {
    let doc: TomlDocument =
        toml::from_str(toml_str).map_err(|e| PolicyLoadError::Parse(e.to_string()))?;
    if doc.schema_version != 1 {
        return Err(PolicyLoadError::UnsupportedSchemaVersion(
            doc.schema_version,
        ));
    }
    convert(doc)
}

fn convert(doc: TomlDocument) -> Result<Policy, PolicyLoadError> {
    let policy_id = PolicyId::new(&doc.policy.id)
        .map_err(|e| PolicyLoadError::InvalidPolicyId(doc.policy.id.clone(), e.to_string()))?;
    let mut rules = Vec::with_capacity(doc.rules.len());
    for toml_rule in &doc.rules {
        let rule_id = RuleId::new(&toml_rule.id)
            .map_err(|e| PolicyLoadError::InvalidRuleId(toml_rule.id.clone(), e.to_string()))?;
        let conditions = match &toml_rule.conditions {
            Some(c) => RuleConditions {
                operations: c.operations.clone(),
                resource_kinds: c.resource_kinds.clone(),
                agent_ids: c.agent_ids.clone(),
                min_trust_level: c.min_trust_level,
                required_capabilities: c.required_capabilities.clone(),
                intent_prefix: c.intent_prefix.clone(),
                path_globs: c.path_globs.clone(),
                executables: c.executables.clone(),
                network_hosts: c.network_hosts.clone(),
                network_schemes: c.network_schemes.clone(),
                secret_identifiers: c.secret_identifiers.clone(),
                tool_identifiers: c.tool_identifiers.clone(),
                network_ports: c.network_ports.clone(),
            },
            None => RuleConditions::default(),
        };
        rules.push(Rule {
            id: rule_id,
            description: toml_rule.description.clone().unwrap_or_default(),
            effect: toml_rule.effect,
            conditions,
        });
    }
    {
        let mut seen = BTreeSet::new();
        for rule in &rules {
            if !seen.insert(rule.id.clone()) {
                return Err(PolicyLoadError::Validation(
                    PolicyValidationError::DuplicateRuleId(rule.id.clone()),
                ));
            }
        }
    }
    let policy = Policy {
        id: policy_id,
        name: doc.policy.name.unwrap_or_default(),
        description: doc.policy.description.unwrap_or_default(),
        default_effect: doc.policy.default_effect,
        rules,
    };
    policy.validate()?;
    Ok(policy)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::Effect;
    use crate::model::{
        MAX_EXECUTABLE_LENGTH, MAX_EXECUTABLE_PATTERNS, MAX_NETWORK_HOST_PATTERNS,
        MAX_PATH_GLOB_LENGTH, MAX_PATH_GLOB_PATTERNS,
    };

    #[test]
    fn parse_minimal_policy() {
        let toml = r#"
schema_version = 1

[policy]
id = "minimal"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(policy.id.as_str(), "minimal");
        assert_eq!(policy.default_effect, DefaultEffect::Deny);
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].id.as_str(), "r1");
        assert_eq!(policy.rules[0].effect, Effect::Allow);
        assert_eq!(policy.rules[0].conditions.operations, vec!["file_read"]);
    }

    #[test]
    fn parse_full_policy() {
        let toml = r#"
schema_version = 1

[policy]
id = "project-default"
name = "Project Default Policy"
description = "Default local development restrictions"
default_effect = "deny"

[[rules]]
id = "allow-project-read"
description = "Allow approved agents to read project files"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
resource_kinds = ["file"]
agent_ids = ["coding-agent"]
min_trust_level = "restricted"
required_capabilities = ["file_read"]
intent_prefix = "read project"

[[rules]]
id = "deny-write-tmp"
description = "Deny writes to /tmp"
effect = "deny"

[rules.conditions]
operations = ["file_write"]
resource_kinds = ["file", "directory"]
agent_ids = ["coding-agent"]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(policy.id.as_str(), "project-default");
        assert_eq!(policy.name, "Project Default Policy");
        assert_eq!(policy.default_effect, DefaultEffect::Deny);
        assert_eq!(policy.rules.len(), 2);

        let r0 = &policy.rules[0];
        assert_eq!(r0.id.as_str(), "allow-project-read");
        assert_eq!(
            r0.description,
            "Allow approved agents to read project files"
        );
        assert_eq!(r0.effect, Effect::Allow);
        assert_eq!(r0.conditions.operations, vec!["file_read"]);
        assert_eq!(r0.conditions.resource_kinds, vec![ResourceKind::File]);
        assert_eq!(r0.conditions.agent_ids, vec!["coding-agent"]);
        assert_eq!(r0.conditions.min_trust_level, Some(TrustLevel::Restricted));
        assert_eq!(r0.conditions.required_capabilities, vec!["file_read"]);
        assert_eq!(r0.conditions.intent_prefix, Some("read project".into()));

        let r1 = &policy.rules[1];
        assert_eq!(r1.id.as_str(), "deny-write-tmp");
        assert_eq!(r1.effect, Effect::Deny);
        assert_eq!(r1.conditions.operations, vec!["file_write"]);
        assert_eq!(
            r1.conditions.resource_kinds,
            vec![ResourceKind::File, ResourceKind::Directory]
        );
    }

    #[test]
    fn parse_approval_default_effect() {
        let toml = r#"
schema_version = 1

[policy]
id = "approval-only"
default_effect = "require_approval"
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(policy.default_effect, DefaultEffect::RequireApproval);
    }

    #[test]
    fn parse_require_approval_rule_effect() {
        let toml = r#"
schema_version = 1

[policy]
id = "approval-policy"
default_effect = "deny"

[[rules]]
id = "approve-read"
effect = "require_approval"

[rules.conditions]
operations = ["file_read"]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(policy.rules[0].effect, Effect::RequireApproval);
    }

    #[test]
    fn parse_rule_without_conditions_is_rejected() {
        let toml = r#"
schema_version = 1

[policy]
id = "no-conditions"
default_effect = "deny"

[[rules]]
id = "catch-all"
effect = "deny"
"#;
        let result = load_policy_from_str(toml);
        match result {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyConditions(id))) => {
                assert_eq!(id.as_str(), "catch-all");
            }
            _ => panic!("expected EmptyConditions error"),
        }
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let toml = r#"
schema_version = 1

[policy]
id = "dup-policy"
default_effect = "deny"

[[rules]]
id = "dup-rule"
effect = "allow"

[rules.conditions]
operations = ["file_read"]

[[rules]]
id = "dup-rule"
effect = "deny"

[rules.conditions]
operations = ["file_write"]
"#;
        let result = load_policy_from_str(toml);
        match result {
            Err(PolicyLoadError::Validation(PolicyValidationError::DuplicateRuleId(id))) => {
                assert_eq!(id.as_str(), "dup-rule");
            }
            _ => panic!("expected DuplicateRuleId error"),
        }
    }

    #[test]
    fn reject_empty_rule_id() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = ""
effect = "allow"

[rules.conditions]
operations = ["file_read"]
"#;
        let result = load_policy_from_str(toml);
        match result {
            Err(PolicyLoadError::InvalidRuleId(id, _)) => assert!(id.is_empty()),
            _ => panic!("expected InvalidRuleId error"),
        }
    }

    #[test]
    fn reject_empty_policy_id() {
        let toml = r#"
schema_version = 1

[policy]
id = ""
default_effect = "deny"
"#;
        let result = load_policy_from_str(toml);
        match result {
            Err(PolicyLoadError::InvalidPolicyId(id, _)) => assert!(id.is_empty()),
            _ => panic!("expected InvalidPolicyId error"),
        }
    }

    #[test]
    fn reject_unsupported_schema_version() {
        let toml = r#"
schema_version = 99

[policy]
id = "test"
default_effect = "deny"
"#;
        let result = load_policy_from_str(toml);
        match result {
            Err(PolicyLoadError::UnsupportedSchemaVersion(v)) => assert_eq!(v, 99),
            _ => panic!("expected UnsupportedSchemaVersion error"),
        }
    }

    #[test]
    fn reject_invalid_toml() {
        match load_policy_from_str("this is not toml {{{") {
            Err(PolicyLoadError::Parse(_)) => {}
            _ => panic!("expected Parse error"),
        }
    }

    #[test]
    fn reject_missing_rule_effect() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "no-effect"

[rules.conditions]
operations = ["file_read"]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!("expected Parse error, got {:?}", other),
        }
    }

    #[test]
    fn reject_invalid_effect_string() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "bad-effect"
effect = "maybe"

[rules.conditions]
operations = ["file_read"]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!("expected Parse error, got {:?}", other),
        }
    }

    #[test]
    fn reject_invalid_resource_kind() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "bad-kind"
effect = "deny"

[rules.conditions]
resource_kinds = ["floppy_disk"]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!("expected Parse error, got {:?}", other),
        }
    }

    #[test]
    fn reject_invalid_trust_level() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "bad-trust"
effect = "deny"

[rules.conditions]
min_trust_level = "ultra"
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!("expected Parse error, got {:?}", other),
        }
    }

    #[test]
    fn reject_allow_default_effect() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "allow"
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!("expected Parse error for allow default, got {:?}", other),
        }
    }

    #[test]
    fn reject_empty_rules_conditions() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "empty-cond"
effect = "allow"

[rules.conditions]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyConditions(id))) => {
                assert_eq!(id.as_str(), "empty-cond");
            }
            other => panic!("expected EmptyConditions, got {:?}", other),
        }
    }

    #[test]
    fn reject_missing_schema_version() {
        let toml = r#"
[policy]
id = "no-schema-version"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!(
                "expected Parse error for missing schema_version, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn reject_unknown_top_level_field() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

unknown_key = "value"
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!("expected Parse error for unknown field, got {:?}", other),
        }
    }

    #[test]
    fn reject_unknown_policy_header_field() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"
unknown_field = "boom"
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!(
                "expected Parse error for unknown policy field, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn reject_unknown_rule_field() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"
unknown_rule_key = "nope"

[rules.conditions]
operations = ["file_read"]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!(
                "expected Parse error for unknown rule field, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn reject_unknown_conditions_field() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
unknown_cond = "bad"
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            other => panic!(
                "expected Parse error for unknown conditions field, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn parse_path_globs() {
        let toml = r#"
schema_version = 1

[policy]
id = "glob-policy"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
path_globs = ["src/**/*.rs", "Cargo.toml"]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(
            policy.rules[0].conditions.path_globs,
            Some(vec!["src/**/*.rs".to_string(), "Cargo.toml".to_string()])
        );
    }

    #[test]
    fn reject_invalid_glob_pattern() {
        let toml = r#"
schema_version = 1

[policy]
id = "bad-glob"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
path_globs = ["[invalid"]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::InvalidGlobPattern(
                id,
                idx,
            ))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            other => panic!("expected InvalidGlobPattern, got {:?}", other),
        }
    }

    #[test]
    fn reject_empty_path_globs_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
path_globs = []
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyPathGlobs(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected EmptyPathGlobs, got {:?}", other),
        }
    }

    #[test]
    fn reject_too_many_path_globs_toml() {
        let mut toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
path_globs = ["#
            .to_string();
        for i in 1..=(MAX_PATH_GLOB_PATTERNS + 1) {
            if i > 1 {
                toml.push_str(", ");
            }
            toml.push_str(&format!("\"pat-{}\"", i));
        }
        toml.push_str("]\n");
        match load_policy_from_str(&toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::TooManyPathGlobs(
                id,
                count,
            ))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(count, MAX_PATH_GLOB_PATTERNS + 1);
            }
            other => panic!("expected TooManyPathGlobs, got {:?}", other),
        }
    }

    #[test]
    fn reject_empty_glob_pattern_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
path_globs = [""]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyGlobPattern(id, idx))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            other => panic!("expected EmptyGlobPattern, got {:?}", other),
        }
    }

    #[test]
    fn reject_glob_pattern_too_long_toml() {
        let long = "a".repeat(MAX_PATH_GLOB_LENGTH + 1);
        let toml = format!(
            r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
path_globs = ["{long}"]
"#
        );
        match load_policy_from_str(&toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::GlobPatternTooLong(
                id,
                idx,
                len,
            ))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
                assert_eq!(len, MAX_PATH_GLOB_LENGTH + 1);
            }
            other => panic!("expected GlobPatternTooLong, got {:?}", other),
        }
    }

    #[test]
    fn reject_duplicate_glob_pattern_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["file_read"]
path_globs = ["src/**/*.rs", "src/**/*.rs"]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::DuplicateGlobPattern(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected DuplicateGlobPattern, got {:?}", other),
        }
    }

    #[test]
    fn reject_path_glob_null_byte_toml() {
        // Inject a null byte programmatically; TOML itself does not allow \0.
        let toml = format!(
            "schema_version = 1\n\n[policy]\nid = \"test\"\ndefault_effect = \"deny\"\n\n[[rules]]\nid = \"r1\"\neffect = \"allow\"\n\n[rules.conditions]\noperations = [\"file_read\"]\npath_globs = [\"{}\"]\n",
            "src/**/*.rs\0"
        );
        match load_policy_from_str(&toml) {
            // The TOML spec forbids null bytes in strings, so serde may
            // reject it as a Parse error before our validation runs.
            Err(PolicyLoadError::Parse(_)) => {}
            Err(PolicyLoadError::Validation(PolicyValidationError::InvalidGlobPattern(
                id,
                idx,
            ))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            other => panic!("expected Parse or InvalidGlobPattern, got {:?}", other),
        }
    }

    #[test]
    fn reject_path_glob_control_char_toml() {
        let toml = "schema_version = 1\n\n[policy]\nid = \"test\"\ndefault_effect = \"deny\"\n\n[[rules]]\nid = \"r1\"\neffect = \"allow\"\n\n[rules.conditions]\noperations = [\"file_read\"]\npath_globs = [\"src/**/*.rs\\n\"]\n";
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::InvalidGlobPattern(
                id,
                idx,
            ))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            other => panic!("expected InvalidGlobPattern, got {:?}", other),
        }
    }

    #[test]
    fn reject_file_too_large() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("kavach_test_too_large");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("big.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        // Write just over the limit.
        let data = vec![b'x'; (MAX_POLICY_FILE_SIZE as usize) + 1];
        f.write_all(&data).unwrap();
        drop(f);

        match load_policy_from_file(&path) {
            Err(PolicyLoadError::FileTooLarge) => {}
            other => panic!("expected FileTooLarge, got {:?}", other),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_executables() {
        let toml = r#"
schema_version = 1

[policy]
id = "exec-policy"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["command_execute"]
executables = ["kubectl", "docker"]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(
            policy.rules[0].conditions.executables,
            Some(vec!["kubectl".to_string(), "docker".to_string()])
        );
    }

    #[test]
    fn reject_empty_executables_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["command_execute"]
executables = []
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyExecutables(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected EmptyExecutables, got {:?}", other),
        }
    }

    #[test]
    fn reject_too_many_executables_toml() {
        let mut toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["command_execute"]
executables = ["#
            .to_string();
        for i in 1..=(MAX_EXECUTABLE_PATTERNS + 1) {
            if i > 1 {
                toml.push_str(", ");
            }
            toml.push_str(&format!("\"exe-{}\"", i));
        }
        toml.push_str("]\n");
        match load_policy_from_str(&toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::TooManyExecutables(
                id,
                count,
            ))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(count, MAX_EXECUTABLE_PATTERNS + 1);
            }
            other => panic!("expected TooManyExecutables, got {:?}", other),
        }
    }

    #[test]
    fn reject_empty_executable_pattern_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["command_execute"]
executables = [""]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyExecutable(id, idx))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            other => panic!("expected EmptyExecutable, got {:?}", other),
        }
    }

    #[test]
    fn reject_executable_too_long_toml() {
        let long = "a".repeat(MAX_EXECUTABLE_LENGTH + 1);
        let toml = format!(
            r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["command_execute"]
executables = ["{long}"]
"#
        );
        match load_policy_from_str(&toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::ExecutableTooLong(
                id,
                idx,
                len,
            ))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
                assert_eq!(len, MAX_EXECUTABLE_LENGTH + 1);
            }
            other => panic!("expected ExecutableTooLong, got {:?}", other),
        }
    }

    #[test]
    fn reject_duplicate_executable_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["command_execute"]
executables = ["kubectl", "kubectl"]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::DuplicateExecutable(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected DuplicateExecutable, got {:?}", other),
        }
    }

    #[test]
    fn reject_executable_null_byte_toml() {
        let toml = format!(
            "schema_version = 1\n\n[policy]\nid = \"test\"\ndefault_effect = \"deny\"\n\n[[rules]]\nid = \"r1\"\neffect = \"allow\"\n\n[rules.conditions]\noperations = [\"command_execute\"]\nexecutables = [\"{}\"]\n",
            "kubectl\0"
        );
        match load_policy_from_str(&toml) {
            Err(PolicyLoadError::Parse(_)) => {}
            Err(PolicyLoadError::Validation(PolicyValidationError::InvalidExecutable(id, idx))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            other => panic!("expected Parse or InvalidExecutable, got {:?}", other),
        }
    }

    #[test]
    fn reject_executable_control_char_toml() {
        let toml = "schema_version = 1\n\n[policy]\nid = \"test\"\ndefault_effect = \"deny\"\n\n[[rules]]\nid = \"r1\"\neffect = \"allow\"\n\n[rules.conditions]\noperations = [\"command_execute\"]\nexecutables = [\"kubectl\\n\"]\n";
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::InvalidExecutable(id, idx))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            other => panic!("expected InvalidExecutable, got {:?}", other),
        }
    }

    #[test]
    fn parse_network_hosts() {
        let toml = r#"
schema_version = 1

[policy]
id = "net-policy"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["network_request"]
network_hosts = ["example.com", "internal.org"]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(
            policy.rules[0].conditions.network_hosts,
            Some(vec!["example.com".to_string(), "internal.org".to_string()])
        );
    }

    #[test]
    fn parse_network_schemes() {
        let toml = r#"
schema_version = 1

[policy]
id = "scheme-policy"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["network_request"]
network_schemes = ["https", "wss"]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(
            policy.rules[0].conditions.network_schemes,
            Some(vec!["https".to_string(), "wss".to_string()])
        );
    }

    #[test]
    fn parse_secret_identifiers() {
        let toml = r#"
schema_version = 1

[policy]
id = "secret-policy"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["secret_access"]
secret_identifiers = ["db_password", "api_key"]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(
            policy.rules[0].conditions.secret_identifiers,
            Some(vec!["db_password".to_string(), "api_key".to_string()])
        );
    }

    #[test]
    fn parse_tool_identifiers() {
        let toml = r#"
schema_version = 1

[policy]
id = "tool-policy"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["tool_invoke"]
tool_identifiers = ["kubectl", "docker"]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(
            policy.rules[0].conditions.tool_identifiers,
            Some(vec!["kubectl".to_string(), "docker".to_string()])
        );
    }

    #[test]
    fn reject_empty_network_hosts_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["network_request"]
network_hosts = []
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyNetworkHosts(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected EmptyNetworkHosts, got {:?}", other),
        }
    }

    #[test]
    fn reject_empty_network_schemes_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["network_request"]
network_schemes = []
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyNetworkSchemes(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected EmptyNetworkSchemes, got {:?}", other),
        }
    }

    #[test]
    fn reject_empty_secret_identifiers_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["secret_access"]
secret_identifiers = []
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptySecretIdentifiers(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected EmptySecretIdentifiers, got {:?}", other),
        }
    }

    #[test]
    fn reject_empty_tool_identifiers_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["tool_invoke"]
tool_identifiers = []
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyToolIdentifiers(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected EmptyToolIdentifiers, got {:?}", other),
        }
    }

    #[test]
    fn reject_too_many_network_hosts_toml() {
        let mut toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["network_request"]
network_hosts = ["#
            .to_string();
        for i in 1..=(MAX_NETWORK_HOST_PATTERNS + 1) {
            if i > 1 {
                toml.push_str(", ");
            }
            toml.push_str(&format!("\"host-{}.com\"", i));
        }
        toml.push_str("]\n");
        match load_policy_from_str(&toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::TooManyNetworkHosts(
                id,
                count,
            ))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(count, MAX_NETWORK_HOST_PATTERNS + 1);
            }
            other => panic!("expected TooManyNetworkHosts, got {:?}", other),
        }
    }

    #[test]
    fn reject_duplicate_network_host_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["network_request"]
network_hosts = ["example.com", "example.com"]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::DuplicateNetworkHost(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected DuplicateNetworkHost, got {:?}", other),
        }
    }

    #[test]
    fn reject_network_host_control_char_toml() {
        let toml = "schema_version = 1\n\n[policy]\nid = \"test\"\ndefault_effect = \"deny\"\n\n[[rules]]\nid = \"r1\"\neffect = \"allow\"\n\n[rules.conditions]\noperations = [\"network_request\"]\nnetwork_hosts = [\"example.com\\n\"]\n";
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::InvalidNetworkHost(
                id,
                idx,
            ))) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            other => panic!("expected InvalidNetworkHost, got {:?}", other),
        }
    }

    #[test]
    fn parse_network_ports() {
        let toml = r#"
schema_version = 1

[policy]
id = "port-policy"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["network_request"]
network_ports = [443, 80, 8080]
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(
            policy.rules[0].conditions.network_ports,
            Some(vec![443, 80, 8080])
        );
    }

    #[test]
    fn reject_empty_network_ports_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["network_request"]
network_ports = []
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::EmptyNetworkPorts(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected EmptyNetworkPorts, got {:?}", other),
        }
    }

    #[test]
    fn reject_duplicate_network_port_toml() {
        let toml = r#"
schema_version = 1

[policy]
id = "test"
default_effect = "deny"

[[rules]]
id = "r1"
effect = "allow"

[rules.conditions]
operations = ["network_request"]
network_ports = [443, 443]
"#;
        match load_policy_from_str(toml) {
            Err(PolicyLoadError::Validation(PolicyValidationError::DuplicateNetworkPort(id))) => {
                assert_eq!(id.as_str(), "r1");
            }
            other => panic!("expected DuplicateNetworkPort, got {:?}", other),
        }
    }
}
