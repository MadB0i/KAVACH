use std::collections::BTreeSet;

use kavach_core::ids::{PolicyId, RuleId};
use kavach_core::resource::ResourceKind;
use kavach_core::subject::TrustLevel;

/// Maximum number of path glob patterns allowed per rule.
pub const MAX_PATH_GLOB_PATTERNS: usize = 32;
/// Maximum length (in bytes) of a single path glob pattern.
pub const MAX_PATH_GLOB_LENGTH: usize = 1024;

/// Maximum number of executable patterns allowed per rule.
pub const MAX_EXECUTABLE_PATTERNS: usize = 64;
/// Maximum length (in bytes) of a single executable pattern.
pub const MAX_EXECUTABLE_LENGTH: usize = 256;

/// Authorization effect produced by a matching rule.
///
/// Used internally in the policy model. Converted to
/// [`kavach_core::DecisionEffect`] when building the final
/// [`kavach_core::AuthorizationDecision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Explicitly allow the operation.
    Allow,
    /// Explicitly deny the operation. Deny always wins.
    Deny,
    /// Allow only after human approval.
    RequireApproval,
}

impl Effect {
    /// Convert to the core decision effect type.
    pub fn to_decision_effect(self) -> kavach_core::DecisionEffect {
        match self {
            Effect::Allow => kavach_core::DecisionEffect::Allow,
            Effect::Deny => kavach_core::DecisionEffect::Deny,
            Effect::RequireApproval => kavach_core::DecisionEffect::RequireApproval,
        }
    }
}

/// Policy-level default effect when no rule matches.
///
/// Only [`Deny`](DefaultEffect::Deny) and [`RequireApproval`](DefaultEffect::RequireApproval)
/// are permitted. A plain [`Allow`](Effect::Allow) default is rejected at the
/// type level to enforce a fail-closed posture by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultEffect {
    /// Deny the request. The standard fail-closed default.
    Deny,
    /// Require human approval before allowing the request.
    RequireApproval,
}

impl DefaultEffect {
    /// Convert to the matching [`ReasonCode`](kavach_core::ReasonCode).
    pub(crate) fn reason_code(self) -> kavach_core::ReasonCode {
        match self {
            Self::Deny => kavach_core::ReasonCode::KavachDenyDefault,
            Self::RequireApproval => kavach_core::ReasonCode::KavachApprovalRequired,
        }
    }

    /// Convert to a core [`DecisionEffect`](kavach_core::DecisionEffect).
    pub fn to_decision_effect(self) -> kavach_core::DecisionEffect {
        match self {
            Self::Deny => kavach_core::DecisionEffect::Deny,
            Self::RequireApproval => kavach_core::DecisionEffect::RequireApproval,
        }
    }
}

/// Errors that can arise during policy validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyValidationError {
    /// A rule ID appears more than once.
    #[error("duplicate rule id: {0}")]
    DuplicateRuleId(RuleId),
    /// An ordinary rule has no active matchers (all condition fields empty).
    #[error("rule {0} has no active conditions; empty conditions are not allowed")]
    EmptyConditions(RuleId),
    /// `path_globs` was explicitly set to an empty list.
    #[error("rule {0}: path_globs present but empty; either set patterns or omit path_globs")]
    EmptyPathGlobs(RuleId),
    /// More than [`MAX_PATH_GLOB_PATTERNS`] patterns.
    #[error("rule {rule}: too many path_glob patterns ({count}); maximum is {max}", rule = .0, count = .1, max = MAX_PATH_GLOB_PATTERNS)]
    TooManyPathGlobs(RuleId, usize),
    /// A glob pattern string is empty.
    #[error("rule {0}: empty glob pattern at index {1}")]
    EmptyGlobPattern(RuleId, usize),
    /// A glob pattern exceeds [`MAX_PATH_GLOB_LENGTH`].
    #[error("rule {rule}: glob pattern at index {idx} is {len} bytes; maximum is {max}", rule = .0, idx = .1, len = .2, max = MAX_PATH_GLOB_LENGTH)]
    GlobPatternTooLong(RuleId, usize, usize),
    /// Duplicate glob pattern string.
    #[error("rule {0}: duplicate glob pattern")]
    DuplicateGlobPattern(RuleId),
    /// Null byte, control character, or invalid glob syntax.
    #[error("rule {0}: invalid glob pattern at index {1}")]
    InvalidGlobPattern(RuleId, usize),
    /// Compilation of validated glob patterns into a GlobSet failed (e.g. pattern conflict).
    #[error("rule {0}: glob patterns cannot be compiled into a single matcher")]
    GlobCompileConflict(RuleId),
    /// `executables` was explicitly set to an empty list.
    #[error("rule {0}: executables present but empty; either list executables or omit")]
    EmptyExecutables(RuleId),
    /// More than [`MAX_EXECUTABLE_PATTERNS`] patterns.
    #[error(
        "rule {rule}: too many executables ({count}); maximum is {max}",
        rule = .0,
        count = .1,
        max = MAX_EXECUTABLE_PATTERNS
    )]
    TooManyExecutables(RuleId, usize),
    /// An executable string is empty.
    #[error("rule {0}: empty executable at index {1}")]
    EmptyExecutable(RuleId, usize),
    /// An executable exceeds [`MAX_EXECUTABLE_LENGTH`].
    #[error(
        "rule {rule}: executable at index {idx} is {len} bytes; maximum is {max}",
        rule = .0,
        idx = .1,
        len = .2,
        max = MAX_EXECUTABLE_LENGTH
    )]
    ExecutableTooLong(RuleId, usize, usize),
    /// Duplicate executable string.
    #[error("rule {0}: duplicate executable")]
    DuplicateExecutable(RuleId),
    /// An executable contains null bytes or control characters.
    #[error("rule {0}: invalid executable at index {1}")]
    InvalidExecutable(RuleId, usize),
}

/// Conditions that must all be satisfied for a rule to match a request.
///
/// Each field is optional; when left at its default (empty or `None`) that
/// dimension is not checked, meaning the condition matches any value.
///
/// At least one field must be non-default, otherwise [`RuleConditions::is_empty`]
/// returns `true` and the rule will be rejected by validation.
#[derive(Debug, Clone, Default)]
pub struct RuleConditions {
    /// If non-empty, only matches when the operation discriminant appears in
    /// this set (e.g., `"file_read"`, `"command_execute"`).
    pub operations: Vec<String>,
    /// If non-empty, only matches when the resource kind appears in this set.
    pub resource_kinds: Vec<ResourceKind>,
    /// If non-empty, only matches when the agent ID appears in this set.
    pub agent_ids: Vec<String>,
    /// If set, only matches when the subject's trust level ranks at or above
    /// this value.
    pub min_trust_level: Option<TrustLevel>,
    /// If non-empty, the subject must declare all of these capabilities.
    pub required_capabilities: Vec<String>,
    /// If set, the declared intent must start with this prefix.
    pub intent_prefix: Option<String>,
    /// Glob patterns for the resource path (e.g. `"src/**/*.rs"`).
    ///
    /// Only meaningful for file and directory resources. `None` means no path
    /// restriction. `Some(vec![])` is rejected during validation as
    /// [`EmptyPathGlobs`](PolicyValidationError::EmptyPathGlobs).
    pub path_globs: Option<Vec<String>>,
    /// Executable names or paths that this rule applies to.
    ///
    /// Only meaningful for command resources. `None` means no executable
    /// restriction. `Some(vec![])` is rejected during validation as
    /// [`EmptyExecutables`](PolicyValidationError::EmptyExecutables).
    pub executables: Option<Vec<String>>,
}

impl RuleConditions {
    /// Returns `true` when every condition field is at its default (empty or
    /// `None`), meaning the rule would match any request — which is rejected.
    ///
    /// Note: `path_globs = Some(vec![])` is **not** considered empty here
    /// (it is non-default); it is instead rejected separately by
    /// [`validate_path_globs`](Self::validate_path_globs).
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
            && self.resource_kinds.is_empty()
            && self.agent_ids.is_empty()
            && self.min_trust_level.is_none()
            && self.required_capabilities.is_empty()
            && self.intent_prefix.is_none()
            && self.path_globs.is_none()
            && self.executables.is_none()
    }

    /// Validate `path_globs` patterns for this rule.
    ///
    /// Checks, in order:
    /// 1. `Some(vec![])` → [`EmptyPathGlobs`](PolicyValidationError::EmptyPathGlobs)
    /// 2. more than [`MAX_PATH_GLOB_PATTERNS`] → [`TooManyPathGlobs`](PolicyValidationError::TooManyPathGlobs)
    /// 3. empty pattern string → [`EmptyGlobPattern`](PolicyValidationError::EmptyGlobPattern)
    /// 4. pattern exceeds [`MAX_PATH_GLOB_LENGTH`] → [`GlobPatternTooLong`](PolicyValidationError::GlobPatternTooLong)
    /// 5. null byte or control character → [`InvalidGlobPattern`](PolicyValidationError::InvalidGlobPattern)
    /// 6. duplicate pattern → [`DuplicateGlobPattern`](PolicyValidationError::DuplicateGlobPattern)
    /// 7. invalid glob syntax → [`InvalidGlobPattern`](PolicyValidationError::InvalidGlobPattern)
    pub fn validate_path_globs(&self, rule_id: &RuleId) -> Result<(), PolicyValidationError> {
        let globs = match &self.path_globs {
            None => return Ok(()),
            Some(v) => v,
        };
        if globs.is_empty() {
            return Err(PolicyValidationError::EmptyPathGlobs(rule_id.clone()));
        }
        if globs.len() > MAX_PATH_GLOB_PATTERNS {
            return Err(PolicyValidationError::TooManyPathGlobs(
                rule_id.clone(),
                globs.len(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, pat) in globs.iter().enumerate() {
            if pat.is_empty() {
                return Err(PolicyValidationError::EmptyGlobPattern(rule_id.clone(), i));
            }
            if pat.len() > MAX_PATH_GLOB_LENGTH {
                return Err(PolicyValidationError::GlobPatternTooLong(
                    rule_id.clone(),
                    i,
                    pat.len(),
                ));
            }
            if pat.contains('\u{0}') || pat.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
                return Err(PolicyValidationError::InvalidGlobPattern(
                    rule_id.clone(),
                    i,
                ));
            }
            if !seen.insert(pat.clone()) {
                return Err(PolicyValidationError::DuplicateGlobPattern(rule_id.clone()));
            }
            globset::Glob::new(pat)
                .map_err(|_| PolicyValidationError::InvalidGlobPattern(rule_id.clone(), i))?;
        }
        Ok(())
    }

    /// Validate `executables` patterns for this rule.
    ///
    /// Checks, in order:
    /// 1. `Some(vec![])` → [`EmptyExecutables`](PolicyValidationError::EmptyExecutables)
    /// 2. more than [`MAX_EXECUTABLE_PATTERNS`] → [`TooManyExecutables`](PolicyValidationError::TooManyExecutables)
    /// 3. empty string → [`EmptyExecutable`](PolicyValidationError::EmptyExecutable)
    /// 4. exceeds [`MAX_EXECUTABLE_LENGTH`] → [`ExecutableTooLong`](PolicyValidationError::ExecutableTooLong)
    /// 5. null byte or control character → [`InvalidExecutable`](PolicyValidationError::InvalidExecutable)
    /// 6. duplicate → [`DuplicateExecutable`](PolicyValidationError::DuplicateExecutable)
    pub fn validate_executables(&self, rule_id: &RuleId) -> Result<(), PolicyValidationError> {
        let exes = match &self.executables {
            None => return Ok(()),
            Some(v) => v,
        };
        if exes.is_empty() {
            return Err(PolicyValidationError::EmptyExecutables(rule_id.clone()));
        }
        if exes.len() > MAX_EXECUTABLE_PATTERNS {
            return Err(PolicyValidationError::TooManyExecutables(
                rule_id.clone(),
                exes.len(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, exe) in exes.iter().enumerate() {
            if exe.is_empty() {
                return Err(PolicyValidationError::EmptyExecutable(rule_id.clone(), i));
            }
            if exe.len() > MAX_EXECUTABLE_LENGTH {
                return Err(PolicyValidationError::ExecutableTooLong(
                    rule_id.clone(),
                    i,
                    exe.len(),
                ));
            }
            if exe.contains('\u{0}') || exe.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
                return Err(PolicyValidationError::InvalidExecutable(rule_id.clone(), i));
            }
            if !seen.insert(exe.clone()) {
                return Err(PolicyValidationError::DuplicateExecutable(rule_id.clone()));
            }
        }
        Ok(())
    }
}

/// A single policy rule with deterministic matching conditions.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Unique identifier for this rule (must be stable across restarts).
    pub id: RuleId,
    /// Human-readable description of what this rule does.
    pub description: String,
    /// Effect when all conditions match.
    pub effect: Effect,
    /// Conditions that must all be satisfied.
    pub conditions: RuleConditions,
}

/// A complete policy document containing an ordered list of rules.
///
/// Rules are evaluated in declaration order; the highest-precedence matching
/// effect wins (Deny > RequireApproval > Allow > default).
///
/// The [`default_effect`](Policy::default_effect) field uses [`DefaultEffect`],
/// which explicitly forbids [`Allow`](Effect::Allow), ensuring a fail-closed
/// posture when no rule matches.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Unique identifier for this policy document.
    pub id: PolicyId,
    /// Human-readable name.
    pub name: String,
    /// Description of this policy's purpose.
    pub description: String,
    /// Default effect when no rule matches (Deny or RequireApproval only).
    pub default_effect: DefaultEffect,
    /// Rules evaluated in this order (first in list is checked first, but
    /// precedence is determined by effect priority, not position).
    pub rules: Vec<Rule>,
}

impl Policy {
    /// Validate internal consistency: no duplicate rule IDs, no empty
    /// conditions on any ordinary rule, and valid `path_globs`.
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        let mut seen = BTreeSet::new();
        for rule in &self.rules {
            if rule.conditions.is_empty() {
                return Err(PolicyValidationError::EmptyConditions(rule.id.clone()));
            }
            rule.conditions.validate_path_globs(&rule.id)?;
            rule.conditions.validate_executables(&rule.id)?;
            if !seen.insert(rule.id.clone()) {
                return Err(PolicyValidationError::DuplicateRuleId(rule.id.clone()));
            }
        }
        Ok(())
    }
}

/// Convert a trust level to a numeric rank for comparison.
pub(crate) fn trust_level_rank(level: &TrustLevel) -> u8 {
    match level {
        TrustLevel::Untrusted => 0,
        TrustLevel::Restricted => 1,
        TrustLevel::Standard => 2,
        TrustLevel::Trusted => 3,
        TrustLevel::System => 4,
    }
}
