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

/// Maximum number of network host patterns allowed per rule.
pub const MAX_NETWORK_HOST_PATTERNS: usize = 32;
/// Maximum number of network scheme patterns allowed per rule.
pub const MAX_NETWORK_SCHEME_PATTERNS: usize = 16;
/// Maximum number of secret identifier patterns allowed per rule.
pub const MAX_SECRET_IDENTIFIER_PATTERNS: usize = 32;
/// Maximum number of tool identifier patterns allowed per rule.
pub const MAX_TOOL_IDENTIFIER_PATTERNS: usize = 32;
/// Maximum length (in bytes) of a single identifier pattern.
pub const MAX_IDENTIFIER_LENGTH: usize = 256;
/// Maximum number of network port patterns allowed per rule.
pub const MAX_NETWORK_PORT_PATTERNS: usize = 32;

/// Maximum number of argument patterns allowed per `argument_rules` list
/// (`deny_if_matches` / `require_match` each).
pub const MAX_ARGUMENT_PATTERN_COUNT: usize = 64;
/// Maximum length (in bytes) of a single argument pattern.
pub const MAX_ARGUMENT_PATTERN_LENGTH: usize = 256;

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
    /// `network_hosts` was explicitly set to an empty list.
    #[error("rule {0}: network_hosts present but empty; either list hosts or omit")]
    EmptyNetworkHosts(RuleId),
    /// More than [`MAX_NETWORK_HOST_PATTERNS`] patterns.
    #[error(
        "rule {rule}: too many network hosts ({count}); maximum is {max}",
        rule = .0,
        count = .1,
        max = MAX_NETWORK_HOST_PATTERNS
    )]
    TooManyNetworkHosts(RuleId, usize),
    /// A network host string is empty.
    #[error("rule {0}: empty network host at index {1}")]
    EmptyNetworkHost(RuleId, usize),
    /// A network host exceeds [`MAX_IDENTIFIER_LENGTH`].
    #[error(
        "rule {rule}: network host at index {idx} is {len} bytes; maximum is {max}",
        rule = .0,
        idx = .1,
        len = .2,
        max = MAX_IDENTIFIER_LENGTH
    )]
    NetworkHostTooLong(RuleId, usize, usize),
    /// Duplicate network host string.
    #[error("rule {0}: duplicate network host")]
    DuplicateNetworkHost(RuleId),
    /// A network host contains null bytes or control characters.
    #[error("rule {0}: invalid network host at index {1}")]
    InvalidNetworkHost(RuleId, usize),
    /// `network_schemes` was explicitly set to an empty list.
    #[error("rule {0}: network_schemes present but empty; either list schemes or omit")]
    EmptyNetworkSchemes(RuleId),
    /// More than [`MAX_NETWORK_SCHEME_PATTERNS`] patterns.
    #[error(
        "rule {rule}: too many network schemes ({count}); maximum is {max}",
        rule = .0,
        count = .1,
        max = MAX_NETWORK_SCHEME_PATTERNS
    )]
    TooManyNetworkSchemes(RuleId, usize),
    /// A network scheme string is empty.
    #[error("rule {0}: empty network scheme at index {1}")]
    EmptyNetworkScheme(RuleId, usize),
    /// A network scheme exceeds [`MAX_IDENTIFIER_LENGTH`].
    #[error(
        "rule {rule}: network scheme at index {idx} is {len} bytes; maximum is {max}",
        rule = .0,
        idx = .1,
        len = .2,
        max = MAX_IDENTIFIER_LENGTH
    )]
    NetworkSchemeTooLong(RuleId, usize, usize),
    /// Duplicate network scheme string.
    #[error("rule {0}: duplicate network scheme")]
    DuplicateNetworkScheme(RuleId),
    /// A network scheme contains null bytes or control characters.
    #[error("rule {0}: invalid network scheme at index {1}")]
    InvalidNetworkScheme(RuleId, usize),
    /// `secret_identifiers` was explicitly set to an empty list.
    #[error("rule {0}: secret_identifiers present but empty; either list identifiers or omit")]
    EmptySecretIdentifiers(RuleId),
    /// More than [`MAX_SECRET_IDENTIFIER_PATTERNS`] patterns.
    #[error(
        "rule {rule}: too many secret identifiers ({count}); maximum is {max}",
        rule = .0,
        count = .1,
        max = MAX_SECRET_IDENTIFIER_PATTERNS
    )]
    TooManySecretIdentifiers(RuleId, usize),
    /// A secret identifier string is empty.
    #[error("rule {0}: empty secret identifier at index {1}")]
    EmptySecretIdentifier(RuleId, usize),
    /// A secret identifier exceeds [`MAX_IDENTIFIER_LENGTH`].
    #[error(
        "rule {rule}: secret identifier at index {idx} is {len} bytes; maximum is {max}",
        rule = .0,
        idx = .1,
        len = .2,
        max = MAX_IDENTIFIER_LENGTH
    )]
    SecretIdentifierTooLong(RuleId, usize, usize),
    /// Duplicate secret identifier string.
    #[error("rule {0}: duplicate secret identifier")]
    DuplicateSecretIdentifier(RuleId),
    /// A secret identifier contains null bytes or control characters.
    #[error("rule {0}: invalid secret identifier at index {1}")]
    InvalidSecretIdentifier(RuleId, usize),
    /// `tool_identifiers` was explicitly set to an empty list.
    #[error("rule {0}: tool_identifiers present but empty; either list identifiers or omit")]
    EmptyToolIdentifiers(RuleId),
    /// More than [`MAX_TOOL_IDENTIFIER_PATTERNS`] patterns.
    #[error(
        "rule {rule}: too many tool identifiers ({count}); maximum is {max}",
        rule = .0,
        count = .1,
        max = MAX_TOOL_IDENTIFIER_PATTERNS
    )]
    TooManyToolIdentifiers(RuleId, usize),
    /// A tool identifier string is empty.
    #[error("rule {0}: empty tool identifier at index {1}")]
    EmptyToolIdentifier(RuleId, usize),
    /// A tool identifier exceeds [`MAX_IDENTIFIER_LENGTH`].
    #[error(
        "rule {rule}: tool identifier at index {idx} is {len} bytes; maximum is {max}",
        rule = .0,
        idx = .1,
        len = .2,
        max = MAX_IDENTIFIER_LENGTH
    )]
    ToolIdentifierTooLong(RuleId, usize, usize),
    /// Duplicate tool identifier string.
    #[error("rule {0}: duplicate tool identifier")]
    DuplicateToolIdentifier(RuleId),
    /// A tool identifier contains null bytes or control characters.
    #[error("rule {0}: invalid tool identifier at index {1}")]
    InvalidToolIdentifier(RuleId, usize),
    /// `network_ports` was explicitly set to an empty list.
    #[error("rule {0}: network_ports present but empty; either list ports or omit")]
    EmptyNetworkPorts(RuleId),
    /// More than [`MAX_NETWORK_PORT_PATTERNS`] patterns.
    #[error(
        "rule {rule}: too many network ports ({count}); maximum is {max}",
        rule = .0,
        count = .1,
        max = MAX_NETWORK_PORT_PATTERNS
    )]
    TooManyNetworkPorts(RuleId, usize),
    /// Duplicate network port value.
    #[error("rule {0}: duplicate network port")]
    DuplicateNetworkPort(RuleId),
    /// `argument_rules` was present but carries no patterns.
    #[error(
        "rule {0}: argument_rules present but empty; either list patterns or omit argument_rules"
    )]
    EmptyArgumentRules(RuleId),
    /// More than [`MAX_ARGUMENT_PATTERN_COUNT`] patterns in one argument list.
    #[error(
        "rule {rule}: too many argument patterns in {which} ({count}); maximum is {max}",
        rule = .0,
        which = .1,
        count = .2,
        max = MAX_ARGUMENT_PATTERN_COUNT
    )]
    TooManyArgumentPatterns(RuleId, &'static str, usize),
    /// An argument pattern string is empty.
    #[error("rule {rule}: empty argument pattern in {which} at index {idx}", rule = .0, which = .1, idx = .2)]
    EmptyArgumentPattern(RuleId, &'static str, usize),
    /// An argument pattern exceeds [`MAX_ARGUMENT_PATTERN_LENGTH`].
    #[error(
        "rule {rule}: argument pattern in {which} at index {idx} is {len} bytes; maximum is {max}",
        rule = .0,
        which = .1,
        idx = .2,
        len = .3,
        max = MAX_ARGUMENT_PATTERN_LENGTH
    )]
    ArgumentPatternTooLong(RuleId, &'static str, usize, usize),
    /// Duplicate argument pattern string within one list.
    #[error("rule {0}: duplicate argument pattern in {1}")]
    DuplicateArgumentPattern(RuleId, &'static str),
    /// An argument pattern contains null bytes or control characters.
    #[error("rule {rule}: invalid argument pattern in {which} at index {idx}", rule = .0, which = .1, idx = .2)]
    InvalidArgumentPattern(RuleId, &'static str, usize),
}

/// Argument-level conditions for command resources (Tier 1 policy capability).
///
/// Both lists hold glob patterns compiled with the same [`globset::GlobBuilder`]
/// configuration as path globs (case-sensitive, `literal_separator`, backslash
/// escapes). Each argument is matched **individually** — patterns never span
/// argument boundaries, so `*pip*` matches the single argument `-mpip` but a
/// pattern cannot accidentally join `"-m"` and `"pip"` across two arguments.
///
/// Semantics (both must hold when set):
/// - `deny_if_matches`: the rule does **not** apply when **any** pattern
///   matches **any** argument.
/// - `require_match`: the rule applies **only** when **some** pattern matches
///   **some** argument.
#[derive(Debug, Clone, Default)]
pub struct ArgumentRules {
    /// Rule does not apply if any pattern matches any single argument.
    pub deny_if_matches: Option<Vec<String>>,
    /// Rule applies only if some pattern matches some single argument.
    pub require_match: Option<Vec<String>>,
}

impl ArgumentRules {
    /// Returns `true` when neither list carries a pattern.
    pub fn is_empty(&self) -> bool {
        let deny_empty = self
            .deny_if_matches
            .as_ref()
            .map(|v| v.is_empty())
            .unwrap_or(true);
        let require_empty = self
            .require_match
            .as_ref()
            .map(|v| v.is_empty())
            .unwrap_or(true);
        deny_empty && require_empty
    }
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
    /// Network host names that this rule applies to.
    ///
    /// Only meaningful for network endpoint resources. `None` means no host
    /// restriction. `Some(vec![])` is rejected during validation as
    /// [`EmptyNetworkHosts`](PolicyValidationError::EmptyNetworkHosts).
    pub network_hosts: Option<Vec<String>>,
    /// Network schemes that this rule applies to.
    ///
    /// Only meaningful for network endpoint resources. `None` means no scheme
    /// restriction. `Some(vec![])` is rejected during validation as
    /// [`EmptyNetworkSchemes`](PolicyValidationError::EmptyNetworkSchemes).
    pub network_schemes: Option<Vec<String>>,
    /// Secret identifiers that this rule applies to.
    ///
    /// Only meaningful for secret resources. `None` means no identifier
    /// restriction. `Some(vec![])` is rejected during validation as
    /// [`EmptySecretIdentifiers`](PolicyValidationError::EmptySecretIdentifiers).
    pub secret_identifiers: Option<Vec<String>>,
    /// External tool identifiers that this rule applies to.
    ///
    /// Only meaningful for external-tool resources. `None` means no identifier
    /// restriction. `Some(vec![])` is rejected during validation as
    /// [`EmptyToolIdentifiers`](PolicyValidationError::EmptyToolIdentifiers).
    pub tool_identifiers: Option<Vec<String>>,
    /// Network ports that this rule applies to.
    ///
    /// Only meaningful for network endpoint resources. `None` means no port
    /// restriction. `Some(vec![])` is rejected during validation as
    /// [`EmptyNetworkPorts`](PolicyValidationError::EmptyNetworkPorts).
    pub network_ports: Option<Vec<u16>>,
    /// Argument-level conditions for command resources.
    ///
    /// Only meaningful for command resources. `None` means no argument
    /// restriction. `Some` with no patterns is rejected during validation as
    /// [`EmptyArgumentRules`](PolicyValidationError::EmptyArgumentRules).
    /// Non-command resources never match when this is configured.
    pub argument_rules: Option<ArgumentRules>,
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
            && self.network_hosts.is_none()
            && self.network_schemes.is_none()
            && self.secret_identifiers.is_none()
            && self.tool_identifiers.is_none()
            && self.network_ports.is_none()
            && self
                .argument_rules
                .as_ref()
                .map(|r| r.is_empty())
                .unwrap_or(true)
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

    /// Validate `network_hosts` patterns for this rule.
    pub fn validate_network_hosts(&self, rule_id: &RuleId) -> Result<(), PolicyValidationError> {
        let hosts = match &self.network_hosts {
            None => return Ok(()),
            Some(v) => v,
        };
        if hosts.is_empty() {
            return Err(PolicyValidationError::EmptyNetworkHosts(rule_id.clone()));
        }
        if hosts.len() > MAX_NETWORK_HOST_PATTERNS {
            return Err(PolicyValidationError::TooManyNetworkHosts(
                rule_id.clone(),
                hosts.len(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, host) in hosts.iter().enumerate() {
            if host.is_empty() {
                return Err(PolicyValidationError::EmptyNetworkHost(rule_id.clone(), i));
            }
            if host.len() > MAX_IDENTIFIER_LENGTH {
                return Err(PolicyValidationError::NetworkHostTooLong(
                    rule_id.clone(),
                    i,
                    host.len(),
                ));
            }
            if host.contains('\u{0}') || host.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
                return Err(PolicyValidationError::InvalidNetworkHost(
                    rule_id.clone(),
                    i,
                ));
            }
            if !seen.insert(host.clone()) {
                return Err(PolicyValidationError::DuplicateNetworkHost(rule_id.clone()));
            }
        }
        Ok(())
    }

    /// Validate `network_schemes` patterns for this rule.
    pub fn validate_network_schemes(&self, rule_id: &RuleId) -> Result<(), PolicyValidationError> {
        let schemes = match &self.network_schemes {
            None => return Ok(()),
            Some(v) => v,
        };
        if schemes.is_empty() {
            return Err(PolicyValidationError::EmptyNetworkSchemes(rule_id.clone()));
        }
        if schemes.len() > MAX_NETWORK_SCHEME_PATTERNS {
            return Err(PolicyValidationError::TooManyNetworkSchemes(
                rule_id.clone(),
                schemes.len(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, scheme) in schemes.iter().enumerate() {
            if scheme.is_empty() {
                return Err(PolicyValidationError::EmptyNetworkScheme(
                    rule_id.clone(),
                    i,
                ));
            }
            if scheme.len() > MAX_IDENTIFIER_LENGTH {
                return Err(PolicyValidationError::NetworkSchemeTooLong(
                    rule_id.clone(),
                    i,
                    scheme.len(),
                ));
            }
            if scheme.contains('\u{0}')
                || scheme.bytes().any(|b| b.is_ascii_control() && b != b'\t')
            {
                return Err(PolicyValidationError::InvalidNetworkScheme(
                    rule_id.clone(),
                    i,
                ));
            }
            if !seen.insert(scheme.clone()) {
                return Err(PolicyValidationError::DuplicateNetworkScheme(
                    rule_id.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Validate `secret_identifiers` patterns for this rule.
    pub fn validate_secret_identifiers(
        &self,
        rule_id: &RuleId,
    ) -> Result<(), PolicyValidationError> {
        let ids = match &self.secret_identifiers {
            None => return Ok(()),
            Some(v) => v,
        };
        if ids.is_empty() {
            return Err(PolicyValidationError::EmptySecretIdentifiers(
                rule_id.clone(),
            ));
        }
        if ids.len() > MAX_SECRET_IDENTIFIER_PATTERNS {
            return Err(PolicyValidationError::TooManySecretIdentifiers(
                rule_id.clone(),
                ids.len(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, id) in ids.iter().enumerate() {
            if id.is_empty() {
                return Err(PolicyValidationError::EmptySecretIdentifier(
                    rule_id.clone(),
                    i,
                ));
            }
            if id.len() > MAX_IDENTIFIER_LENGTH {
                return Err(PolicyValidationError::SecretIdentifierTooLong(
                    rule_id.clone(),
                    i,
                    id.len(),
                ));
            }
            if id.contains('\u{0}') || id.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
                return Err(PolicyValidationError::InvalidSecretIdentifier(
                    rule_id.clone(),
                    i,
                ));
            }
            if !seen.insert(id.clone()) {
                return Err(PolicyValidationError::DuplicateSecretIdentifier(
                    rule_id.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Validate `tool_identifiers` patterns for this rule.
    pub fn validate_tool_identifiers(&self, rule_id: &RuleId) -> Result<(), PolicyValidationError> {
        let ids = match &self.tool_identifiers {
            None => return Ok(()),
            Some(v) => v,
        };
        if ids.is_empty() {
            return Err(PolicyValidationError::EmptyToolIdentifiers(rule_id.clone()));
        }
        if ids.len() > MAX_TOOL_IDENTIFIER_PATTERNS {
            return Err(PolicyValidationError::TooManyToolIdentifiers(
                rule_id.clone(),
                ids.len(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, id) in ids.iter().enumerate() {
            if id.is_empty() {
                return Err(PolicyValidationError::EmptyToolIdentifier(
                    rule_id.clone(),
                    i,
                ));
            }
            if id.len() > MAX_IDENTIFIER_LENGTH {
                return Err(PolicyValidationError::ToolIdentifierTooLong(
                    rule_id.clone(),
                    i,
                    id.len(),
                ));
            }
            if id.contains('\u{0}') || id.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
                return Err(PolicyValidationError::InvalidToolIdentifier(
                    rule_id.clone(),
                    i,
                ));
            }
            if !seen.insert(id.clone()) {
                return Err(PolicyValidationError::DuplicateToolIdentifier(
                    rule_id.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Validate `argument_rules` patterns for this rule.
    ///
    /// Mirrors [`validate_executables`](Self::validate_executables): length,
    /// null/control-character and duplicate checks per list, plus glob-syntax
    /// validation so a bad pattern fails at load time, not at match time.
    pub fn validate_argument_rules(&self, rule_id: &RuleId) -> Result<(), PolicyValidationError> {
        let rules = match &self.argument_rules {
            None => return Ok(()),
            Some(v) => v,
        };
        if rules.is_empty() {
            return Err(PolicyValidationError::EmptyArgumentRules(rule_id.clone()));
        }
        Self::validate_argument_pattern_list(
            rule_id,
            "deny_if_matches",
            rules.deny_if_matches.as_ref(),
        )?;
        Self::validate_argument_pattern_list(
            rule_id,
            "require_match",
            rules.require_match.as_ref(),
        )?;
        Ok(())
    }

    /// Validate one argument-pattern list (`None` and empty-`None` skip).
    ///
    /// An explicitly present-but-empty list (`Some(vec![])`) is rejected as
    /// [`EmptyArgumentRules`](PolicyValidationError::EmptyArgumentRules) to
    /// match the `Some(vec![])`-is-an-error convention of the other matchers.
    fn validate_argument_pattern_list(
        rule_id: &RuleId,
        which: &'static str,
        patterns: Option<&Vec<String>>,
    ) -> Result<(), PolicyValidationError> {
        let patterns = match patterns {
            None => return Ok(()),
            Some(v) => v,
        };
        if patterns.is_empty() {
            return Err(PolicyValidationError::EmptyArgumentRules(rule_id.clone()));
        }
        if patterns.len() > MAX_ARGUMENT_PATTERN_COUNT {
            return Err(PolicyValidationError::TooManyArgumentPatterns(
                rule_id.clone(),
                which,
                patterns.len(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, pat) in patterns.iter().enumerate() {
            if pat.is_empty() {
                return Err(PolicyValidationError::EmptyArgumentPattern(
                    rule_id.clone(),
                    which,
                    i,
                ));
            }
            if pat.len() > MAX_ARGUMENT_PATTERN_LENGTH {
                return Err(PolicyValidationError::ArgumentPatternTooLong(
                    rule_id.clone(),
                    which,
                    i,
                    pat.len(),
                ));
            }
            if pat.contains('\u{0}') || pat.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
                return Err(PolicyValidationError::InvalidArgumentPattern(
                    rule_id.clone(),
                    which,
                    i,
                ));
            }
            if !seen.insert(pat.clone()) {
                return Err(PolicyValidationError::DuplicateArgumentPattern(
                    rule_id.clone(),
                    which,
                ));
            }
            globset::Glob::new(pat).map_err(|_| {
                PolicyValidationError::InvalidArgumentPattern(rule_id.clone(), which, i)
            })?;
        }
        Ok(())
    }

    /// Validate `network_ports` patterns for this rule.
    ///
    /// Checks, in order:
    /// 1. `Some(vec![])` → [`EmptyNetworkPorts`](PolicyValidationError::EmptyNetworkPorts)
    /// 2. more than [`MAX_NETWORK_PORT_PATTERNS`] → [`TooManyNetworkPorts`](PolicyValidationError::TooManyNetworkPorts)
    /// 3. duplicate → [`DuplicateNetworkPort`](PolicyValidationError::DuplicateNetworkPort)
    pub fn validate_network_ports(&self, rule_id: &RuleId) -> Result<(), PolicyValidationError> {
        let ports = match &self.network_ports {
            None => return Ok(()),
            Some(v) => v,
        };
        if ports.is_empty() {
            return Err(PolicyValidationError::EmptyNetworkPorts(rule_id.clone()));
        }
        if ports.len() > MAX_NETWORK_PORT_PATTERNS {
            return Err(PolicyValidationError::TooManyNetworkPorts(
                rule_id.clone(),
                ports.len(),
            ));
        }
        let mut seen = BTreeSet::new();
        for &port in ports.iter() {
            if !seen.insert(port) {
                return Err(PolicyValidationError::DuplicateNetworkPort(rule_id.clone()));
            }
        }
        Ok(())
    }
}

/// Returns `true` when a path-glob pattern is relative: no leading `/` or
/// `\`, no Windows drive prefix (`C:`), no UNC/verbatim prefix.
///
/// Relative patterns can only match relative resource paths directly; for
/// absolute resource paths the engine falls back to matching the
/// `working_directory`-relative remainder (see `PolicyEngine` path logic).
pub fn is_relative_glob_pattern(pat: &str) -> bool {
    if pat.starts_with('/') || pat.starts_with('\\') {
        return false;
    }
    let bytes = pat.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return false;
    }
    let lower = pat.to_ascii_lowercase();
    if lower.starts_with("\\\\?\\") {
        return false;
    }
    true
}

/// A non-fatal policy-load-time warning.
///
/// Warnings never reject a policy; they flag configurations that may not
/// match as the author expects (e.g. a relative `path_globs` pattern with no
/// guaranteed `working_directory` context at match time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWarning {
    /// Rule the warning applies to.
    pub rule_id: RuleId,
    /// Human-readable, non-secret description.
    pub message: String,
}

impl PolicyWarning {
    /// Warning for a relative path pattern whose match depends on the
    /// per-request `working_directory` (unavailable at load time).
    pub fn relative_path_pattern(rule_id: RuleId, pattern: &str) -> Self {
        Self {
            rule_id,
            message: format!(
                "relative path pattern '{pattern}' has no guaranteed working_directory context and may not match absolute resource paths as expected"
            ),
        }
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
            rule.conditions.validate_network_hosts(&rule.id)?;
            rule.conditions.validate_network_schemes(&rule.id)?;
            rule.conditions.validate_secret_identifiers(&rule.id)?;
            rule.conditions.validate_tool_identifiers(&rule.id)?;
            rule.conditions.validate_network_ports(&rule.id)?;
            rule.conditions.validate_argument_rules(&rule.id)?;
            if !seen.insert(rule.id.clone()) {
                return Err(PolicyValidationError::DuplicateRuleId(rule.id.clone()));
            }
        }
        Ok(())
    }

    /// Non-fatal warnings for this policy (relative path patterns, etc.).
    ///
    /// Call after [`validate`](Self::validate) succeeds; warnings never
    /// reject a policy.
    pub fn warnings(&self) -> Vec<PolicyWarning> {
        let mut out = Vec::new();
        for rule in &self.rules {
            if let Some(globs) = &rule.conditions.path_globs {
                for pat in globs {
                    if is_relative_glob_pattern(pat) {
                        out.push(PolicyWarning::relative_path_pattern(rule.id.clone(), pat));
                    }
                }
            }
        }
        out
    }

    /// Validate and also collect non-fatal warnings.
    ///
    /// Errors fail the load; warnings are returned alongside success for the
    /// caller to log or surface.
    pub fn validate_with_warnings(&self) -> Result<Vec<PolicyWarning>, PolicyValidationError> {
        self.validate()?;
        Ok(self.warnings())
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
