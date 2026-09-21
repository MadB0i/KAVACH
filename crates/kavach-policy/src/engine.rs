use std::collections::BTreeSet;
use std::time::SystemTime;

use kavach_core::ids::RuleId;
use kavach_core::request::ToolRequest;
use kavach_core::{AuthorizationDecision, DecisionEffect, ReasonCode};

use crate::model::{
    DefaultEffect, Effect, Policy, PolicyValidationError, RuleConditions, trust_level_rank,
};

// ---------------------------------------------------------------------------
// Compiled types — private; pre-compile glob patterns once at construction.
// ---------------------------------------------------------------------------

/// A rule with pre-compiled glob matchers.
#[derive(Debug, Clone)]
struct CompiledRule {
    rule: crate::model::Rule,
    /// Compiled `GlobSet` when `path_globs` is `Some(non_empty)`, else `None`.
    path_matcher: Option<globset::GlobSet>,
    /// Whether any configured path pattern is relative (no leading `/` or
    /// drive prefix). Enables the `working_directory`-relative fallback.
    has_relative_patterns: bool,
    /// Compiled `GlobSet` for `argument_rules.deny_if_matches`, else `None`.
    arg_deny_matcher: Option<globset::GlobSet>,
    /// Compiled `GlobSet` for `argument_rules.require_match`, else `None`.
    arg_require_matcher: Option<globset::GlobSet>,
}

/// Compile one glob pattern with the single shared configuration used by
/// every matcher in this engine (path globs and argument patterns alike).
fn compile_shared_glob(
    pat: &str,
    rule_id: &RuleId,
    index: usize,
) -> Result<globset::Glob, PolicyValidationError> {
    globset::GlobBuilder::new(pat)
        .literal_separator(true)
        .case_insensitive(false)
        .backslash_escape(true)
        .build()
        .map_err(|_| PolicyValidationError::InvalidGlobPattern(rule_id.clone(), index))
}

/// A policy whose rules have been validated and whose path globs are compiled.
#[derive(Debug, Clone)]
struct CompiledPolicy {
    id: String,
    name: String,
    default_effect: DefaultEffect,
    rules: Vec<CompiledRule>,
}

/// Read-only policy metadata suitable for status and management APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySummary {
    /// Stable policy identifier.
    pub id: String,
    /// Human-readable policy name.
    pub name: String,
    /// Fail-closed default effect.
    pub default_effect: DefaultEffect,
    /// Number of rules in the policy.
    pub rule_count: usize,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// In-memory policy evaluator with deterministic precedence.
///
/// Precedence (highest to lowest):
///   1. Explicit Deny
///   2. Require Approval
///   3. Explicit Allow
///   4. Policy default (Deny or RequireApproval only)
///
/// Only rule IDs from the winning precedence group appear in the output
/// [`AuthorizationDecision`], sorted lexicographically.
///
/// Path-glob patterns are compiled during [`PolicyEngine::new`]; evaluation
/// never calls `Glob::new`, `GlobSetBuilder::build`, or any compilation
/// function.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    compiled: Vec<CompiledPolicy>,
}

impl PolicyEngine {
    /// Create a new engine from an ordered list of policies.
    ///
    /// Returns an error if any policy contains duplicate rule IDs, a rule
    /// with empty conditions, or invalid path-glob patterns.
    ///
    /// Policies are evaluated in the order given; rules within each policy are
    /// evaluated in their declaration order.
    ///
    /// Path-glob patterns are validated and compiled into a [`globset::GlobSet`]
    /// once at construction time.
    pub fn new(policies: Vec<Policy>) -> Result<Self, PolicyValidationError> {
        // Validate within each policy.
        for policy in &policies {
            policy.validate()?;
        }
        // Validate cross-policy duplicates.
        let mut seen: BTreeSet<RuleId> = BTreeSet::new();
        for policy in &policies {
            for rule in &policy.rules {
                if !seen.insert(rule.id.clone()) {
                    return Err(PolicyValidationError::DuplicateRuleId(rule.id.clone()));
                }
            }
        }
        // Compile.
        let mut compiled = Vec::with_capacity(policies.len());
        for policy in &policies {
            let mut rules = Vec::with_capacity(policy.rules.len());
            for rule in &policy.rules {
                let path_matcher = build_path_matcher(&rule.conditions, &rule.id)?;
                let has_relative_patterns = rule
                    .conditions
                    .path_globs
                    .as_ref()
                    .map(|globs| {
                        globs
                            .iter()
                            .any(|p| crate::model::is_relative_glob_pattern(p))
                    })
                    .unwrap_or(false);
                let (arg_deny_matcher, arg_require_matcher) =
                    build_argument_matchers(&rule.conditions, &rule.id)?;
                rules.push(CompiledRule {
                    rule: rule.clone(),
                    path_matcher,
                    has_relative_patterns,
                    arg_deny_matcher,
                    arg_require_matcher,
                });
            }
            compiled.push(CompiledPolicy {
                id: policy.id.to_string(),
                name: policy.name.clone(),
                default_effect: policy.default_effect,
                rules,
            });
        }
        Ok(Self { compiled })
    }

    /// Non-fatal load-time warnings for the currently loaded policies.
    ///
    /// Currently reports relative `path_globs` patterns, which depend on the
    /// per-request `working_directory` and therefore have no guaranteed match
    /// context. Callers should log or surface these; they never fail the load.
    pub fn warnings(&self) -> Vec<crate::model::PolicyWarning> {
        let mut out = Vec::new();
        for cp in &self.compiled {
            for cr in &cp.rules {
                if let Some(globs) = &cr.rule.conditions.path_globs {
                    for pat in globs {
                        if crate::model::is_relative_glob_pattern(pat) {
                            out.push(crate::model::PolicyWarning::relative_path_pattern(
                                cr.rule.id.clone(),
                                pat,
                            ));
                        }
                    }
                }
            }
        }
        out
    }

    /// Return metadata for the currently loaded policy snapshot.
    pub fn summaries(&self) -> Vec<PolicySummary> {
        self.compiled
            .iter()
            .map(|policy| PolicySummary {
                id: policy.id.clone(),
                name: policy.name.clone(),
                default_effect: policy.default_effect,
                rule_count: policy.rules.len(),
            })
            .collect()
    }

    /// Evaluate a [`ToolRequest`] against all loaded policies.
    ///
    /// # Flow
    ///
    /// 1. **Validate** the request via [`ToolRequest::validate()`]. If
    ///    validation fails, return [`DecisionEffect::Deny`] with
    ///    [`ReasonCode::KavachDenyInvalidRequest`].
    /// 2. **Match** every rule across all policies, collecting IDs grouped
    ///    by effect.
    /// 3. **Resolve** the highest-precedence group and return only those IDs,
    ///    sorted lexicographically.
    /// 4. If no rule matched, apply the first policy's default effect (or
    ///    [`DefaultEffect::Deny`] if no policies are configured).
    pub fn evaluate(&self, request: &ToolRequest) -> AuthorizationDecision {
        let evaluated_at = SystemTime::now();
        let request_id = request.request_id.clone();

        // Step 1: Validate request; fail closed.
        if let Err(err) = request.validate() {
            return AuthorizationDecision::new(
                DecisionEffect::Deny,
                ReasonCode::KavachDenyInvalidRequest,
                format!("request validation failed: {}", err),
                BTreeSet::new(),
                evaluated_at,
                request_id,
                None,
                None,
            );
        }

        // Step 1b: Built-in dangerous-invocation baseline. Always on and
        // evaluated before any policy-authored rule, so an allow-listed
        // interpreter name cannot smuggle `python -c`, `python -m pip`,
        // `perl -e` etc. past the engine. Deny wins by construction.
        if let kavach_core::resource::Resource::Command(cmd) = &request.resource {
            if let Some(reason) = dangerous_invocation_reason(cmd) {
                let mut ids: BTreeSet<RuleId> = BTreeSet::new();
                if let Ok(baseline_id) = RuleId::new(BASELINE_DANGEROUS_INTERPRETER_RULE_ID) {
                    ids.insert(baseline_id);
                }
                return AuthorizationDecision::new_with_trace(
                    DecisionEffect::Deny,
                    ReasonCode::KavachDenyExplicitRule,
                    format!(
                        "denied by built-in baseline ({}): refusing {} invocation",
                        reason,
                        executable_basename(cmd.executable())
                    ),
                    ids,
                    evaluated_at,
                    request_id,
                    None,
                    None,
                    kavach_core::DecisionTrace {
                        baseline_triggered: Some(reason.to_string()),
                        failed_conditions: Vec::new(),
                    },
                );
            }
        }

        // Step 2: Evaluate all rules, collecting IDs by effect group.
        // Failed condition dimensions are gathered (bounded, distinct) for
        // the additive decision trace.
        let mut deny_ids: BTreeSet<RuleId> = BTreeSet::new();
        let mut approval_ids: BTreeSet<RuleId> = BTreeSet::new();
        let mut allow_ids: BTreeSet<RuleId> = BTreeSet::new();
        let mut failed_conditions: Vec<String> = Vec::new();

        for cp in &self.compiled {
            for cr in &cp.rules {
                let (matched, failed) = rule_match_outcome(cr, request);
                if matched {
                    match cr.rule.effect {
                        Effect::Deny => deny_ids.insert(cr.rule.id.clone()),
                        Effect::RequireApproval => approval_ids.insert(cr.rule.id.clone()),
                        Effect::Allow => allow_ids.insert(cr.rule.id.clone()),
                    };
                } else {
                    for name in failed {
                        if failed_conditions.len() >= MAX_TRACE_FAILED_CONDITIONS {
                            break;
                        }
                        let name = name.to_string();
                        if !failed_conditions.contains(&name) {
                            failed_conditions.push(name);
                        }
                    }
                }
            }
        }

        let trace = kavach_core::DecisionTrace {
            baseline_triggered: None,
            failed_conditions,
        };

        // Step 3: Resolve precedence — highest-priority group with at least
        // one match wins.
        if !deny_ids.is_empty() {
            let ids: Vec<RuleId> = deny_ids.into_iter().collect();
            AuthorizationDecision::new_with_trace(
                DecisionEffect::Deny,
                ReasonCode::KavachDenyExplicitRule,
                format!("denied by explicit rules: {}", join_ids(&ids)),
                ids.into_iter().collect(),
                evaluated_at,
                request_id,
                None,
                None,
                trace,
            )
        } else if !approval_ids.is_empty() {
            let ids: Vec<RuleId> = approval_ids.into_iter().collect();
            AuthorizationDecision::new_with_trace(
                DecisionEffect::RequireApproval,
                ReasonCode::KavachApprovalRequired,
                format!("approval required by rules: {}", join_ids(&ids)),
                ids.into_iter().collect(),
                evaluated_at,
                request_id,
                None,
                None,
                trace,
            )
        } else if !allow_ids.is_empty() {
            let ids: Vec<RuleId> = allow_ids.into_iter().collect();
            AuthorizationDecision::new_with_trace(
                DecisionEffect::Allow,
                ReasonCode::KavachAllowPolicyMatch,
                format!("allowed by rules: {}", join_ids(&ids)),
                ids.into_iter().collect(),
                evaluated_at,
                request_id,
                None,
                None,
                trace,
            )
        } else {
            // No rule matched — policy default (Allow is impossible at type level).
            let default = self
                .compiled
                .first()
                .map(|p| p.default_effect)
                .unwrap_or(DefaultEffect::Deny);
            AuthorizationDecision::new_with_trace(
                default.to_decision_effect(),
                default.reason_code(),
                format!(
                    "no rule matched; policy default applied ({})",
                    default.to_decision_effect()
                ),
                BTreeSet::new(),
                evaluated_at,
                request_id,
                None,
                None,
                trace,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Helper — compile path matcher
// ---------------------------------------------------------------------------

/// Build a compiled [`globset::GlobSet`] from validated path-glob patterns.
///
/// Returns `None` when no path restriction is configured.
///
/// Configuration (per requirement):
/// - `/` is the internal separator
/// - `*` must not cross path separators (via `literal_separator(true)`)
/// - `**` may cross separators
/// - matching is case-sensitive
/// - literal separators are required
/// - complete normalized path matching
/// - no filesystem access, canonicalization, or symlink resolution
fn build_path_matcher(
    cond: &RuleConditions,
    rule_id: &RuleId,
) -> Result<Option<globset::GlobSet>, PolicyValidationError> {
    let globs = match &cond.path_globs {
        None => return Ok(None),
        Some(v) => v,
    };
    if globs.is_empty() {
        return Ok(None);
    }
    let mut builder = globset::GlobSetBuilder::new();
    for (i, pat) in globs.iter().enumerate() {
        builder.add(compile_shared_glob(pat, rule_id, i)?);
    }
    builder
        .build()
        .map(Some)
        .map_err(|_| PolicyValidationError::GlobCompileConflict(rule_id.clone()))
}

/// Build compiled [`globset::GlobSet`]s for `argument_rules` patterns.
///
/// Returns `(deny_matcher, require_matcher)`. Each list is matched per
/// argument (never across argument boundaries). Validation has already
/// rejected malformed patterns; a build failure here maps to
/// [`PolicyValidationError::GlobCompileConflict`].
fn build_argument_matchers(
    cond: &RuleConditions,
    rule_id: &RuleId,
) -> Result<(Option<globset::GlobSet>, Option<globset::GlobSet>), PolicyValidationError> {
    let rules = match &cond.argument_rules {
        None => return Ok((None, None)),
        Some(v) => v,
    };
    let compile_list = |patterns: Option<&Vec<String>>| -> Result<Option<globset::GlobSet>, PolicyValidationError> {
        let patterns = match patterns {
            None => return Ok(None),
            Some(v) => v,
        };
        if patterns.is_empty() {
            return Ok(None);
        }
        let mut builder = globset::GlobSetBuilder::new();
        for (i, pat) in patterns.iter().enumerate() {
            let glob = compile_shared_glob(pat, rule_id, i).map_err(|_| {
                PolicyValidationError::InvalidArgumentPattern(rule_id.clone(), "argument_rules", i)
            })?;
            builder.add(glob);
        }
        builder
            .build()
            .map(Some)
            .map_err(|_| PolicyValidationError::GlobCompileConflict(rule_id.clone()))
    };
    Ok((
        compile_list(rules.deny_if_matches.as_ref())?,
        compile_list(rules.require_match.as_ref())?,
    ))
}

/// Synthetic rule ID attributed when the built-in dangerous-invocation
/// baseline fires. It is not a policy-authored rule; it exists so the denial
/// shows up in `matched_rule_ids` like any other explicit deny.
pub const BASELINE_DANGEROUS_INTERPRETER_RULE_ID: &str = "baseline-dangerous-interpreter";

/// Basename (lower-cased, `.exe` stripped) of an executable path.
fn executable_basename(exe: &str) -> String {
    let base = exe.rsplit(['/', '\\']).next().unwrap_or(exe).to_lowercase();
    base.strip_suffix(".exe").unwrap_or(&base).to_string()
}

/// Returns `true` when the executable is a known script interpreter whose
/// very first flags turn it into arbitrary-code execution.
fn is_known_interpreter(base: &str) -> bool {
    base == "python"
        || base.starts_with("python3")
        || base.starts_with("python2")
        || base == "perl"
        || base == "ruby"
        || base == "node"
        || base == "nodejs"
}

/// Hardcoded, always-on baseline: known-dangerous interpreter eval flags.
///
/// This is Tier 2 — deliberately NOT policy-author-configurable, so an
/// under-specified policy file cannot silently disable it. It fires for:
/// - `python`/`python3` with `-c` as the first argument (inline code)
/// - `python`/`python3 -m pip` or `-m easy_install` (supply-chain install)
/// - `perl`/`ruby`/`node` with `-e` as the first argument (inline code)
/// - any `-c`/`-e` immediately following a known interpreter executable
/// - any argument carrying a substitution/expansion hazard (`$(...)`,
///   backticks, `$VAR`/`${VAR}`), via the shared
///   [`kavach_core::scan_dangerous_shell_constructs`] scanner
///
/// The check is intentionally narrow (first-argument flags, exact module
/// names) so legitimate interpreter uses (`python script.py`,
/// `node server.js`) are unaffected.
pub fn is_known_dangerous_invocation(cmd: &kavach_core::resource::CommandResource) -> bool {
    dangerous_invocation_reason(cmd).is_some()
}

/// Machine-readable reason why [`is_known_dangerous_invocation`] fired.
/// Returns `None` when the invocation is not a known-dangerous one. The
/// reason never echoes argument payloads (they may carry secrets).
pub(crate) fn dangerous_invocation_reason(
    cmd: &kavach_core::resource::CommandResource,
) -> Option<&'static str> {
    let base = executable_basename(cmd.executable());
    let args = cmd.arguments();
    if is_known_interpreter(&base) {
        if let Some(first) = args.first() {
            if first == "-c" || first == "-e" {
                return Some("interpreter eval flag");
            }
            if first == "-m" {
                if let Some(module) = args.get(1) {
                    let module_lower = module.to_lowercase();
                    if module_lower == "pip" || module_lower == "easy_install" {
                        return Some("interpreter package-manager module");
                    }
                }
            }
        }
    }
    if args
        .iter()
        .any(|a| kavach_core::shell::has_substitution_hazard(a))
    {
        return Some("shell substitution or expansion in arguments");
    }
    None
}

/// Join rule IDs into a comma-separated string for human explanation.
fn join_ids(ids: &[RuleId]) -> String {
    ids.iter()
        .map(|id| id.as_str().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Maximum distinct failed-condition names retained in a [`DecisionTrace`].
const MAX_TRACE_FAILED_CONDITIONS: usize = 16;

/// Check whether a compiled rule's conditions match the given request.
///
/// Returns `(matched, failed_conditions)`: the dimension names that failed,
/// in evaluation order (first failure short-circuits, so at most one name per
/// rule). Path glob checking uses the already-compiled [`globset::GlobSet`]
/// stored in [`CompiledRule::path_matcher`]; no new compilation occurs.
fn rule_match_outcome(cr: &CompiledRule, request: &ToolRequest) -> (bool, Vec<&'static str>) {
    let cond = &cr.rule.conditions;
    let mut failed: Vec<&'static str> = Vec::new();
    // Record one failure and return. Only the first failing dimension per
    // rule is reported to keep traces bounded and deterministic.
    macro_rules! fail {
        ($name:literal) => {{
            failed.push($name);
            return (false, failed);
        }};
    }

    // --- Operation check ---
    if !cond.operations.is_empty() {
        let op = request.operation.discriminant();
        if !cond.operations.iter().any(|o| o == op) {
            fail!("operations");
        }
    }

    // --- Resource kind check ---
    if !cond.resource_kinds.is_empty() {
        let kind = request.resource.kind();
        if !cond.resource_kinds.contains(&kind) {
            fail!("resource_kinds");
        }
    }

    // --- Agent ID check ---
    if !cond.agent_ids.is_empty() {
        let agent = request.subject.agent_id.as_str();
        if !cond.agent_ids.iter().any(|a| a == agent) {
            fail!("agent_ids");
        }
    }

    // --- Trust level check ---
    if let Some(min_trust) = cond.min_trust_level {
        let subject_rank = trust_level_rank(&request.subject.trust_level);
        let min_rank = trust_level_rank(&min_trust);
        if subject_rank < min_rank {
            fail!("min_trust_level");
        }
    }

    // --- Capability check ---
    if !cond.required_capabilities.is_empty() {
        let declared: Vec<&str> = request
            .subject
            .declared_capabilities
            .iter()
            .map(|c| c.as_str())
            .collect();
        for required in &cond.required_capabilities {
            if !declared.contains(&required.as_str()) {
                fail!("required_capabilities");
            }
        }
    }

    // --- Declared intent prefix check ---
    if let Some(prefix) = &cond.intent_prefix {
        match &request.context.declared_intent {
            Some(intent) => {
                if !intent.starts_with(prefix) {
                    fail!("intent_prefix");
                }
            }
            None => fail!("intent_prefix"),
        }
    }

    // --- Executable check — exact string match ---
    if let Some(ref exes) = cond.executables {
        match &request.resource {
            kavach_core::resource::Resource::Command(cmd) => {
                if !exes.iter().any(|e| e == cmd.executable()) {
                    fail!("executables");
                }
            }
            // Non-command resources never match when executables is configured.
            _ => fail!("executables"),
        }
    }

    // --- Argument rules check — per-argument glob match ---
    // Runs right after the executable check: `deny_if_matches` vetoes the
    // rule when any pattern hits any single argument; `require_match`
    // keeps the rule only when some pattern hits some single argument.
    if cond.argument_rules.is_some() {
        match &request.resource {
            kavach_core::resource::Resource::Command(cmd) => {
                if let Some(ref deny_matcher) = cr.arg_deny_matcher {
                    if cmd.arguments().iter().any(|a| deny_matcher.is_match(a)) {
                        fail!("argument_rules");
                    }
                }
                if let Some(ref require_matcher) = cr.arg_require_matcher {
                    if !cmd.arguments().iter().any(|a| require_matcher.is_match(a)) {
                        fail!("argument_rules");
                    }
                }
            }
            // Non-command resources never match when argument rules configured.
            _ => fail!("argument_rules"),
        }
    }

    // --- Network host check — exact string match ---
    if let Some(ref hosts) = cond.network_hosts {
        match &request.resource {
            kavach_core::resource::Resource::NetworkEndpoint(nr) => {
                if !hosts.iter().any(|h| h == nr.host().as_str()) {
                    fail!("network_hosts");
                }
            }
            _ => fail!("network_hosts"),
        }
    }

    // --- Network scheme check — exact string match ---
    if let Some(ref schemes) = cond.network_schemes {
        match &request.resource {
            kavach_core::resource::Resource::NetworkEndpoint(nr) => {
                if !schemes.iter().any(|s| s == nr.scheme().as_str()) {
                    fail!("network_schemes");
                }
            }
            _ => fail!("network_schemes"),
        }
    }

    // --- Network port check — exact numeric match ---
    if let Some(ref ports) = cond.network_ports {
        match &request.resource {
            kavach_core::resource::Resource::NetworkEndpoint(nr) => {
                let matches = ports.iter().any(|&p| {
                    if p == 0 {
                        return true;
                    }
                    match nr.port() {
                        Some(net_port) => net_port.value() == p,
                        None => false,
                    }
                });
                if !matches {
                    fail!("network_ports");
                }
            }
            _ => fail!("network_ports"),
        }
    }

    // --- Secret identifier check — exact string match ---
    if let Some(ref ids) = cond.secret_identifiers {
        match &request.resource {
            kavach_core::resource::Resource::Secret { identifier } => {
                if !ids.iter().any(|i| i == identifier) {
                    fail!("secret_identifiers");
                }
            }
            _ => fail!("secret_identifiers"),
        }
    }

    // --- Tool identifier check — exact string match ---
    if let Some(ref ids) = cond.tool_identifiers {
        match &request.resource {
            kavach_core::resource::Resource::ExternalTool { identifier } => {
                if !ids.iter().any(|i| i == identifier) {
                    fail!("tool_identifiers");
                }
            }
            _ => fail!("tool_identifiers"),
        }
    }

    // --- Path glob check — uses pre-compiled GlobSet ---
    if let Some(ref matcher) = cr.path_matcher {
        let resource_path = match request.resource.path() {
            Some(p) => p,
            // Non-file/directory resources never match when a path matcher is configured.
            None => fail!("path_globs"),
        };
        if !path_matches_with_cwd(
            matcher,
            cr.has_relative_patterns,
            resource_path,
            request.context.working_directory.as_ref(),
        ) {
            fail!("path_globs");
        }
    }

    (true, failed)
}

/// Match a resource path against a compiled glob set, with a
/// `working_directory`-relative fallback for relative patterns.
///
/// 1. Try the normalized resource path directly (preserves all existing
///    absolute-pattern behavior).
/// 2. If that misses, the rule has relative patterns, and the resource path
///    is absolute: strip the request `working_directory` prefix and match the
///    remainder against the same set. A relative `sympy/**/*.py` pattern then
///    matches `/workspace/sympy/core/x.py` when the request ran with
///    `working_directory="/workspace"`.
/// 3. With no `working_directory` context the fallback cannot run — the
///    caller should have surfaced a [`crate::model::PolicyWarning`] at load
///    time instead of silently relying on this path.
fn path_matches_with_cwd(
    matcher: &globset::GlobSet,
    has_relative_patterns: bool,
    resource_path: &kavach_core::resource::NormalizedPath,
    working_directory: Option<&kavach_core::resource::NormalizedPath>,
) -> bool {
    let normalized = resource_path.normalized();
    if matcher.is_match(normalized) {
        return true;
    }
    if !has_relative_patterns || !resource_path.is_absolute() {
        return false;
    }
    let wd = match working_directory {
        Some(w) => w.normalized(),
        None => return false,
    };
    match strip_workspace_prefix(normalized, wd) {
        Some(remainder) => matcher.is_match(remainder),
        None => false,
    }
}

/// Strip a workspace prefix from an absolute normalized path, returning the
/// relative remainder. Comparison is component-aware (prefix must end on a
/// `/` boundary), so `/workspace2/x` is not treated as under `/workspace`.
fn strip_workspace_prefix<'a>(absolute: &'a str, workspace: &str) -> Option<&'a str> {
    if workspace == "/" {
        return absolute.strip_prefix('/');
    }
    let rest = absolute.strip_prefix(workspace)?;
    rest.strip_prefix('/')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use kavach_core::DecisionEffect;
    use kavach_core::ids::{AgentId, RequestId, RuleId, SessionId};
    use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
    use kavach_core::resource::Resource;
    use kavach_core::subject::Capability;

    use crate::model::{
        DefaultEffect, Effect as PolicyEffect, MAX_EXECUTABLE_LENGTH, MAX_EXECUTABLE_PATTERNS,
        MAX_IDENTIFIER_LENGTH, MAX_NETWORK_HOST_PATTERNS, MAX_NETWORK_PORT_PATTERNS,
        MAX_PATH_GLOB_LENGTH, MAX_PATH_GLOB_PATTERNS, Policy, Rule, RuleConditions,
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_subject() -> kavach_core::subject::AgentSubject {
        AgentSubjectBuilder::new(
            AgentId::new("agent-1").unwrap(),
            SessionId::new("sess-1").unwrap(),
        )
        .trust_level(kavach_core::subject::TrustLevel::Standard)
        .build()
    }

    fn make_subject_with_caps(caps: &[&str]) -> kavach_core::subject::AgentSubject {
        let mut builder = AgentSubjectBuilder::new(
            AgentId::new("agent-1").unwrap(),
            SessionId::new("sess-1").unwrap(),
        )
        .trust_level(kavach_core::subject::TrustLevel::Standard);
        for c in caps {
            builder = builder.capability(Capability::new(c).unwrap());
        }
        builder.build()
    }

    fn make_context() -> RequestContext {
        RequestContext::new(None, None, None, None, false).unwrap()
    }

    fn make_context_with_intent(intent: &str) -> RequestContext {
        RequestContext::new(None, Some(intent), None, None, false).unwrap()
    }

    fn make_request(subject: kavach_core::subject::AgentSubject) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            subject,
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/foo.txt").unwrap(),
            make_context(),
        )
    }

    fn make_request_with(
        subject: kavach_core::subject::AgentSubject,
        operation: Operation,
        resource: Resource,
        context: RequestContext,
    ) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            subject,
            operation,
            resource,
            context,
        )
    }

    fn policy(default_effect: DefaultEffect, rules: Vec<Rule>) -> Policy {
        Policy {
            id: kavach_core::ids::PolicyId::new("pol-1").unwrap(),
            name: "test".into(),
            description: "".into(),
            default_effect,
            rules,
        }
    }

    fn policy_with_id(id: &str, default_effect: DefaultEffect, rules: Vec<Rule>) -> Policy {
        Policy {
            id: kavach_core::ids::PolicyId::new(id).unwrap(),
            name: "test".into(),
            description: "".into(),
            default_effect,
            rules,
        }
    }

    fn make_network_request(scheme: &str, host: &str) -> ToolRequest {
        make_network_request_with_port(scheme, host, None)
    }

    fn make_network_request_with_port(scheme: &str, host: &str, port: Option<u16>) -> ToolRequest {
        use kavach_core::resource::{NetworkHost, NetworkPort, NetworkResource, NetworkScheme};
        let net = Resource::NetworkEndpoint(
            NetworkResource::new(
                NetworkScheme::new(scheme).unwrap(),
                NetworkHost::new(host).unwrap(),
                port.map(NetworkPort::new),
                "/",
            )
            .unwrap(),
        );
        make_request_with(
            make_subject(),
            Operation::NetworkRequest,
            net,
            make_context(),
        )
    }

    // -----------------------------------------------------------------------
    // Precedence tests — winning IDs only
    // -----------------------------------------------------------------------

    #[test]
    fn deny_decision_contains_deny_ids_only() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("approve-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::RequireApproval,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("deny-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(
            decision.matched_rule_ids,
            vec![RuleId::new("deny-rule").unwrap()]
        );
    }

    #[test]
    fn approval_decision_contains_approval_ids_only() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("approve-rule").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::RequireApproval,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::RequireApproval);
        assert_eq!(
            decision.matched_rule_ids,
            vec![RuleId::new("approve-rule").unwrap()]
        );
    }

    #[test]
    fn allow_decision_contains_allow_ids_only() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-rule-a").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("allow-rule-b").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        resource_kinds: vec![kavach_core::resource::ResourceKind::File],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Allow);
        let mut expected: Vec<RuleId> = vec![
            RuleId::new("allow-rule-a").unwrap(),
            RuleId::new("allow-rule-b").unwrap(),
        ];
        expected.sort();
        assert_eq!(decision.matched_rule_ids, expected);
    }

    #[test]
    fn default_deny_has_empty_matched_ids() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("write-only").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_write".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyDefault);
        assert!(decision.matched_rule_ids.is_empty());
    }

    #[test]
    fn default_approval_has_empty_matched_ids() {
        let engine =
            PolicyEngine::new(vec![policy(DefaultEffect::RequireApproval, vec![])]).unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::RequireApproval);
        assert_eq!(decision.reason, ReasonCode::KavachApprovalRequired);
        assert!(decision.matched_rule_ids.is_empty());
    }

    #[test]
    fn winning_ids_are_sorted() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("z-deny").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("a-deny").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        resource_kinds: vec![kavach_core::resource::ResourceKind::File],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("m-deny").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        agent_ids: vec!["agent-1".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        let ids = decision.matched_rule_ids;
        assert_eq!(ids.len(), 3);
        assert!(ids.windows(2).all(|w| w[0] <= w[1]), "not sorted");
    }

    // -----------------------------------------------------------------------
    // Duplicate rule ID validation
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_ids_within_one_policy_are_rejected() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("dup").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("dup").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_write".into()],
                        ..Default::default()
                    },
                },
            ],
        )]);

        match result {
            Err(PolicyValidationError::DuplicateRuleId(id)) => {
                assert_eq!(id.as_str(), "dup");
            }
            _ => panic!("expected DuplicateRuleId error"),
        }
    }

    #[test]
    fn duplicate_ids_across_policies_are_rejected() {
        let result = PolicyEngine::new(vec![
            policy_with_id(
                "pol-1",
                DefaultEffect::Deny,
                vec![Rule {
                    id: RuleId::new("shared").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                }],
            ),
            policy_with_id(
                "pol-2",
                DefaultEffect::Deny,
                vec![Rule {
                    id: RuleId::new("shared").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_write".into()],
                        ..Default::default()
                    },
                }],
            ),
        ]);

        match result {
            Err(PolicyValidationError::DuplicateRuleId(id)) => {
                assert_eq!(id.as_str(), "shared");
            }
            _ => panic!("expected DuplicateRuleId error"),
        }
    }

    // -----------------------------------------------------------------------
    // Empty conditions validation
    // -----------------------------------------------------------------------

    #[test]
    fn empty_conditions_are_rejected() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("catch-all").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions::default(),
            }],
        )]);

        match result {
            Err(PolicyValidationError::EmptyConditions(id)) => {
                assert_eq!(id.as_str(), "catch-all");
            }
            _ => panic!("expected EmptyConditions error"),
        }
    }

    // -----------------------------------------------------------------------
    // Precedence tests (existing)
    // -----------------------------------------------------------------------

    #[test]
    fn deny_precedence_over_allow() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("deny-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        // Only deny IDs survive.
        assert!(
            !decision
                .matched_rule_ids
                .contains(&RuleId::new("allow-all").unwrap())
        );
        assert!(
            decision
                .matched_rule_ids
                .contains(&RuleId::new("deny-all").unwrap())
        );
    }

    #[test]
    fn deny_precedence_over_approval() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("approve-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::RequireApproval,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("deny-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
    }

    #[test]
    fn approval_precedence_over_allow() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("approve-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::RequireApproval,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::RequireApproval);
    }

    #[test]
    fn allow_when_only_allow_rules_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-read").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Allow);
        assert_eq!(decision.reason, ReasonCode::KavachAllowPolicyMatch);
    }

    #[test]
    fn no_match_falls_to_policy_default_deny() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("only-write").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_write".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyDefault);
        assert!(decision.matched_rule_ids.is_empty());
    }

    #[test]
    fn invalid_request_fails_closed() {
        let ctx = RequestContext {
            timestamp: std::time::SystemTime::now(),
            working_directory: None,
            declared_intent: Some("read\x00source".into()),
            parent_request_id: None,
            metadata: kavach_core::resource::RequestMetadata::new(),
            dry_run: false,
        };
        let request = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/safe.txt").unwrap(),
            ctx,
        );

        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::RequireApproval,
            vec![Rule {
                id: RuleId::new("allow-all").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&request);
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyInvalidRequest);
        assert!(decision.matched_rule_ids.is_empty());
    }

    // -----------------------------------------------------------------------
    // Dimension matching tests
    // -----------------------------------------------------------------------

    #[test]
    fn matches_by_operation() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-read").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("deny-write").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_write".into()],
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        assert_eq!(
            engine.evaluate(&make_request(make_subject())).effect,
            DecisionEffect::Allow
        );

        let write_req = make_request_with(
            make_subject(),
            Operation::FileWrite,
            Resource::file("/workspace/bar.txt").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&write_req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn matches_by_resource_kind() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-command").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    resource_kinds: vec![kavach_core::resource::ResourceKind::Command],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyDefault);
    }

    #[test]
    fn matches_by_agent_id() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-agent-1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    agent_ids: vec!["agent-1".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Allow);
    }

    #[test]
    fn matches_by_trust_level() {
        let trusted_subject = {
            let b = AgentSubjectBuilder::new(
                AgentId::new("agent-trusted").unwrap(),
                SessionId::new("sess-1").unwrap(),
            )
            .trust_level(kavach_core::subject::TrustLevel::Trusted);
            b.build()
        };

        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-trusted").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    min_trust_level: Some(kavach_core::subject::TrustLevel::Trusted),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        assert_eq!(
            engine.evaluate(&make_request(trusted_subject)).effect,
            DecisionEffect::Allow
        );

        let standard_decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(standard_decision.effect, DecisionEffect::Deny);
        assert_eq!(standard_decision.reason, ReasonCode::KavachDenyDefault);
    }

    #[test]
    fn matches_by_capability() {
        let capped_subject = make_subject_with_caps(&["read_secrets"]);
        let uncapped_subject = make_subject();

        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-secret-readers").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    required_capabilities: vec!["read_secrets".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        assert_eq!(
            engine.evaluate(&make_request(capped_subject)).effect,
            DecisionEffect::Allow
        );
        assert_eq!(
            engine.evaluate(&make_request(uncapped_subject)).effect,
            DecisionEffect::Deny
        );
    }

    #[test]
    fn matches_by_intent_prefix() {
        let reading_ctx = make_context_with_intent("read source");
        let writing_ctx = make_context_with_intent("write output");

        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-read-intent").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    intent_prefix: Some("read".into()),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let base_subject = make_subject();
        assert_eq!(
            engine
                .evaluate(&make_request_with(
                    base_subject.clone(),
                    Operation::FileRead { max_bytes: None },
                    Resource::file("/workspace/foo.txt").unwrap(),
                    reading_ctx,
                ))
                .effect,
            DecisionEffect::Allow
        );
        assert_eq!(
            engine
                .evaluate(&make_request_with(
                    base_subject,
                    Operation::FileWrite,
                    Resource::file("/workspace/bar.txt").unwrap(),
                    writing_ctx,
                ))
                .effect,
            DecisionEffect::Deny
        );
    }

    // -----------------------------------------------------------------------
    // Path glob matching
    // -----------------------------------------------------------------------

    #[test]
    fn matches_by_path_glob() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-src-rs").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["**/src/**/*.rs".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // Matching path.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/src/foo/bar.rs").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        // Non-matching path.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/README.md").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
        assert_eq!(engine.evaluate(&req).reason, ReasonCode::KavachDenyDefault);
    }

    #[test]
    fn path_glob_matches_any_pattern_in_list() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-known").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["**/Cargo.toml".into(), "**/src/**/*.rs".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/Cargo.toml").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/src/lib.rs").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/README.md").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn path_glob_non_file_resource_no_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-any-file").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["*".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // Command resources have no path → no match.
        let req = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::CommandExecute,
            kavach_core::resource::Resource::Command(
                kavach_core::resource::CommandResource::new("cat", vec![]).unwrap(),
            ),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn path_glob_empty_skips_check() {
        // When path_globs is empty, it should not restrict matching.
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-all-read").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request(make_subject());
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    // -----------------------------------------------------------------------
    // Explicit glob semantic tests
    // -----------------------------------------------------------------------

    #[test]
    fn glob_star_matches_one_segment() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-txt").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["/*.txt".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // `*` matches one segment at root level.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/foo.txt").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        // `*` does not match nested — /sub/foo.txt won't match /*.txt.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/sub/foo.txt").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn glob_star_does_not_cross_separators() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-src").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["/src/*.rs".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // `*` matches only within /src/.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/src/lib.rs").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        // `*` does not match nested: /src/sub/lib.rs.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/src/sub/lib.rs").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn glob_starstar_matches_nested() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-all-rs").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["/src/**/*.rs".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // `**` matches zero or more directories — direct child.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/src/lib.rs").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        // `**` matches deep nesting.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/src/a/b/c/lib.rs").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        // Does not match outside /src/.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/other/lib.rs").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn glob_windows_backslash_normalized() {
        // NormalizedPath converts backslashes to forward slashes.
        // The normalized form of `C:\workspace\foo.txt` is `C:/workspace/foo.txt`.
        let path = kavach_core::resource::NormalizedPath::new("C:\\workspace\\foo.txt").unwrap();
        let normalized = path.normalized();
        assert_eq!(normalized, "C:/workspace/foo.txt");

        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-fs").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["C:/workspace/*".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            kavach_core::resource::Resource::File { path },
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    // -----------------------------------------------------------------------
    // Resource-type tests for path globs
    // -----------------------------------------------------------------------

    #[test]
    fn glob_directory_resource_matches() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-dir").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["/workspace/project/*".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::DirectoryList,
            Resource::directory("/workspace/project/subdir").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    #[test]
    fn glob_network_resource_never_matches() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-net").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["*".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        use kavach_core::resource::{NetworkHost, NetworkResource, NetworkScheme};
        let net = Resource::NetworkEndpoint(
            NetworkResource::new(
                NetworkScheme::new("https").unwrap(),
                NetworkHost::new("example.com").unwrap(),
                None,
                "/",
            )
            .unwrap(),
        );
        let req = make_request_with(
            make_subject(),
            Operation::NetworkRequest,
            net,
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn glob_secret_external_unknown_never_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-any").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["*".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // Secret resource.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::Secret {
                identifier: "my-key".into(),
            },
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);

        // ExternalTool resource.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::ExternalTool {
                identifier: "kubectl".into(),
            },
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);

        // Unknown resource.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::Unknown,
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn glob_and_operation_use_and_semantics() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("and-rule").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_write".into()],
                    path_globs: Some(vec!["**/Cargo.toml".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // Both match: file_write + Cargo.toml → allow.
        let req = make_request_with(
            make_subject(),
            Operation::FileWrite,
            Resource::file("/workspace/Cargo.toml").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        // Operation matches but path does not → deny.
        let req = make_request_with(
            make_subject(),
            Operation::FileWrite,
            Resource::file("/workspace/README.md").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);

        // Path matches but operation does not → deny.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/Cargo.toml").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn glob_precedence_deny_over_allow_with_paths() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![
                Rule {
                    id: RuleId::new("allow-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        path_globs: Some(vec!["**".into()]),
                        ..Default::default()
                    },
                },
                Rule {
                    id: RuleId::new("deny-toml").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        path_globs: Some(vec!["**/Cargo.toml".into()]),
                        ..Default::default()
                    },
                },
            ],
        )])
        .unwrap();

        // Deny takes precedence over Allow.
        let req = make_request_with(
            make_subject(),
            Operation::FileWrite,
            Resource::file("/workspace/Cargo.toml").unwrap(),
            make_context(),
        );
        let decision = engine.evaluate(&req);
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert!(
            decision
                .matched_rule_ids
                .contains(&RuleId::new("deny-toml").unwrap())
        );
        assert!(
            !decision
                .matched_rule_ids
                .contains(&RuleId::new("allow-all").unwrap())
        );

        // Allow still works for non-deny paths.
        let req = make_request_with(
            make_subject(),
            Operation::FileWrite,
            Resource::file("/workspace/src/lib.rs").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    // -----------------------------------------------------------------------
    // Path glob validation — programmatic construction
    // -----------------------------------------------------------------------

    #[test]
    fn reject_empty_path_globs_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec![]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::EmptyPathGlobs(id)) => {
                assert_eq!(id.as_str(), "r1");
            }
            _ => panic!("expected EmptyPathGlobs"),
        }
    }

    #[test]
    fn reject_too_many_path_globs_programmatic() {
        let globs: Vec<String> = (0..=MAX_PATH_GLOB_PATTERNS)
            .map(|i| format!("pat-{}", i))
            .collect();
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(globs),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::TooManyPathGlobs(id, count)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(count, MAX_PATH_GLOB_PATTERNS + 1);
            }
            _ => panic!("expected TooManyPathGlobs"),
        }
    }

    #[test]
    fn reject_empty_glob_pattern_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::EmptyGlobPattern(id, idx)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            _ => panic!("expected EmptyGlobPattern"),
        }
    }

    #[test]
    fn reject_glob_pattern_too_long_programmatic() {
        let long = "a".repeat(MAX_PATH_GLOB_LENGTH + 1);
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec![long]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::GlobPatternTooLong(id, idx, len)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
                assert_eq!(len, MAX_PATH_GLOB_LENGTH + 1);
            }
            _ => panic!("expected GlobPatternTooLong"),
        }
    }

    #[test]
    fn reject_duplicate_glob_pattern_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["src/**/*.rs".into(), "src/**/*.rs".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::DuplicateGlobPattern(id)) => {
                assert_eq!(id.as_str(), "r1");
            }
            _ => panic!("expected DuplicateGlobPattern"),
        }
    }

    #[test]
    fn reject_glob_pattern_null_byte() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["src/**/*.rs\0".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::InvalidGlobPattern(id, idx)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            _ => panic!("expected InvalidGlobPattern"),
        }
    }

    #[test]
    fn reject_glob_pattern_control_char() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["src/**/*.rs\n".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::InvalidGlobPattern(id, idx)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            _ => panic!("expected InvalidGlobPattern"),
        }
    }

    #[test]
    fn reject_invalid_glob_syntax_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["[invalid".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::InvalidGlobPattern(id, idx)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            _ => panic!("expected InvalidGlobPattern"),
        }
    }

    // -----------------------------------------------------------------------
    // AND semantics — multiple matchers required
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_matchers_use_and_semantics() {
        // Rule matches only when ALL of: operation == file_read AND
        // resource_kind == File AND agent_id == agent-1.
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("strict").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    resource_kinds: vec![kavach_core::resource::ResourceKind::File],
                    agent_ids: vec!["agent-1".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // All three match → allow.
        assert_eq!(
            engine.evaluate(&make_request(make_subject())).effect,
            DecisionEffect::Allow
        );

        // Same operation but wrong resource kind  → deny.
        let cmd_req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::directory("/workspace").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&cmd_req).effect, DecisionEffect::Deny);

        // Wrong operation → deny.
        let write_req = make_request_with(
            make_subject(),
            Operation::FileWrite,
            Resource::file("/workspace/bar.txt").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&write_req).effect, DecisionEffect::Deny);
    }

    // -----------------------------------------------------------------------
    // Command executable matching
    // -----------------------------------------------------------------------

    #[test]
    fn command_matches_by_executable() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-kubectl").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    executables: Some(vec!["kubectl".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new(
                    "kubectl",
                    vec!["get".into(), "pods".into()],
                )
                .unwrap(),
            ),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
        assert_eq!(
            engine.evaluate(&req).reason,
            ReasonCode::KavachAllowPolicyMatch
        );
    }

    #[test]
    fn command_non_matching_executable_denies() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-kubectl").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    executables: Some(vec!["kubectl".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new("docker", vec!["ps".into()]).unwrap(),
            ),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn command_executable_list_any_match_works() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-safe").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    executables: Some(vec!["cat".into(), "ls".into(), "echo".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let cat_req = make_request_with(
            make_subject(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new("cat", vec!["/etc/hosts".into()])
                    .unwrap(),
            ),
            make_context(),
        );
        assert_eq!(engine.evaluate(&cat_req).effect, DecisionEffect::Allow);

        let ls_req = make_request_with(
            make_subject(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new("ls", vec!["-la".into()]).unwrap(),
            ),
            make_context(),
        );
        assert_eq!(engine.evaluate(&ls_req).effect, DecisionEffect::Allow);

        // kubectl is not in the list.
        let kubectl_req = make_request_with(
            make_subject(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new(
                    "kubectl",
                    vec!["get".into(), "pods".into()],
                )
                .unwrap(),
            ),
            make_context(),
        );
        assert_eq!(engine.evaluate(&kubectl_req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn executables_non_command_resource_no_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-cat").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    executables: Some(vec!["cat".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // File resource — should not match.
        let req = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/foo.txt").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn executables_empty_skips_check() {
        // When executables is None (default), it should not restrict matching.
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-cmd").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new("any-tool", vec![]).unwrap(),
            ),
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    // -----------------------------------------------------------------------
    // Executable validation — programmatic construction
    // -----------------------------------------------------------------------

    #[test]
    fn reject_empty_executables_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec![]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::EmptyExecutables(id)) => {
                assert_eq!(id.as_str(), "r1");
            }
            _ => panic!("expected EmptyExecutables"),
        }
    }

    #[test]
    fn reject_too_many_executables_programmatic() {
        let exes: Vec<String> = (0..=MAX_EXECUTABLE_PATTERNS)
            .map(|i| format!("exe-{}", i))
            .collect();
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(exes),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::TooManyExecutables(id, count)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(count, MAX_EXECUTABLE_PATTERNS + 1);
            }
            _ => panic!("expected TooManyExecutables"),
        }
    }

    #[test]
    fn reject_empty_executable_pattern_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec!["".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::EmptyExecutable(id, idx)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            _ => panic!("expected EmptyExecutable"),
        }
    }

    #[test]
    fn reject_executable_too_long_programmatic() {
        let long = "a".repeat(MAX_EXECUTABLE_LENGTH + 1);
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec![long]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::ExecutableTooLong(id, idx, len)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
                assert_eq!(len, MAX_EXECUTABLE_LENGTH + 1);
            }
            _ => panic!("expected ExecutableTooLong"),
        }
    }

    #[test]
    fn reject_duplicate_executable_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec!["kubectl".into(), "kubectl".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::DuplicateExecutable(id)) => {
                assert_eq!(id.as_str(), "r1");
            }
            _ => panic!("expected DuplicateExecutable"),
        }
    }

    #[test]
    fn reject_executable_null_byte() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec!["kubectl\0".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::InvalidExecutable(id, idx)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            _ => panic!("expected InvalidExecutable"),
        }
    }

    #[test]
    fn reject_executable_control_char() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    executables: Some(vec!["kubectl\n".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::InvalidExecutable(id, idx)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            _ => panic!("expected InvalidExecutable"),
        }
    }

    // -----------------------------------------------------------------------
    // Network host matching
    // -----------------------------------------------------------------------

    #[test]
    fn network_matches_by_host() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-example").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_hosts: Some(vec!["example.com".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_network_request("https", "example.com");
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
        assert_eq!(
            engine.evaluate(&req).reason,
            ReasonCode::KavachAllowPolicyMatch
        );
    }

    #[test]
    fn network_non_matching_host_denies() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-example").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_hosts: Some(vec!["example.com".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_network_request("https", "other.com");
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn network_host_non_network_resource_no_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-example").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_hosts: Some(vec!["example.com".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request(make_subject());
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    // -----------------------------------------------------------------------
    // Network scheme matching
    // -----------------------------------------------------------------------

    #[test]
    fn network_matches_by_scheme() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-https").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_schemes: Some(vec!["https".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_network_request("https", "example.com");
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    #[test]
    fn network_non_matching_scheme_denies() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-https").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_schemes: Some(vec!["https".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_network_request("http", "example.com");
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn network_scheme_non_network_resource_no_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-https").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_schemes: Some(vec!["https".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request(make_subject());
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn network_host_and_scheme_and_operation() {
        // All three must match for the rule to apply.
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("net-rule").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_hosts: Some(vec!["example.com".into()]),
                    network_schemes: Some(vec!["https".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // All three match → allow.
        let req = make_network_request("https", "example.com");
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        // Wrong host → deny.
        let req = make_network_request("https", "other.com");
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);

        // Wrong scheme → deny.
        let req = make_network_request("http", "example.com");
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    // -----------------------------------------------------------------------
    // Network port matching
    // -----------------------------------------------------------------------

    #[test]
    fn network_matches_by_port() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-443").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_ports: Some(vec![443]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_network_request_with_port("https", "example.com", Some(443));
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    #[test]
    fn network_non_matching_port_denies() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-443").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_ports: Some(vec![443]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_network_request_with_port("https", "example.com", Some(80));
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn network_port_wildcard_zero_matches_any() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-any-port").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_ports: Some(vec![0]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_network_request_with_port("https", "example.com", Some(443));
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        let req = make_network_request_with_port("https", "example.com", Some(8080));
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);

        // No port resource also matches wildcard.
        let req = make_network_request("https", "example.com");
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    #[test]
    fn network_port_no_port_resource_denies_when_ports_set() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-443").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_ports: Some(vec![443]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // Network request without a port → deny (unless 0 is in ports).
        let req = make_network_request("https", "example.com");
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn network_port_non_network_resource_no_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-443").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    network_ports: Some(vec![443]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request(make_subject());
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    // -----------------------------------------------------------------------
    // Secret identifier matching
    // -----------------------------------------------------------------------

    #[test]
    fn secret_matches_by_identifier() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-db-pass").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    secret_identifiers: Some(vec!["db_password".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::SecretAccess,
            Resource::Secret {
                identifier: "db_password".into(),
            },
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    #[test]
    fn secret_non_matching_identifier_denies() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-db-pass").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    secret_identifiers: Some(vec!["db_password".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::SecretAccess,
            Resource::Secret {
                identifier: "api_key".into(),
            },
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn secret_identifier_non_secret_resource_no_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-db-pass").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    secret_identifiers: Some(vec!["db_password".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request(make_subject());
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    // -----------------------------------------------------------------------
    // Tool identifier matching
    // -----------------------------------------------------------------------

    #[test]
    fn tool_matches_by_identifier() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-kubectl").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    tool_identifiers: Some(vec!["kubectl".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::ToolInvoke {
                tool_id: "kubectl".into(),
            },
            Resource::ExternalTool {
                identifier: "kubectl".into(),
            },
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    #[test]
    fn tool_non_matching_identifier_denies() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-kubectl").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    tool_identifiers: Some(vec!["kubectl".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::ToolInvoke {
                tool_id: "docker".into(),
            },
            Resource::ExternalTool {
                identifier: "docker".into(),
            },
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn tool_identifier_non_tool_resource_no_match() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-kubectl").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    tool_identifiers: Some(vec!["kubectl".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request(make_subject());
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    #[test]
    fn tool_identifier_empty_skips_check() {
        // When tool_identifiers is None (default), it does not restrict matching.
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-tool").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["tool_invoke".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request_with(
            make_subject(),
            Operation::ToolInvoke {
                tool_id: "any-tool".into(),
            },
            Resource::ExternalTool {
                identifier: "any-tool".into(),
            },
            make_context(),
        );
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    // -----------------------------------------------------------------------
    // Network host, network scheme, secret, tool — validation (programmatic)
    // -----------------------------------------------------------------------

    #[test]
    fn reject_empty_network_hosts_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_hosts: Some(vec![]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::EmptyNetworkHosts(id)) => {
                assert_eq!(id.as_str(), "r1");
            }
            _ => panic!("expected EmptyNetworkHosts"),
        }
    }

    #[test]
    fn reject_too_many_network_hosts_programmatic() {
        let hosts: Vec<String> = (0..=MAX_NETWORK_HOST_PATTERNS)
            .map(|i| format!("host-{}.com", i))
            .collect();
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_hosts: Some(hosts),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::TooManyNetworkHosts(id, count)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(count, MAX_NETWORK_HOST_PATTERNS + 1);
            }
            _ => panic!("expected TooManyNetworkHosts"),
        }
    }

    #[test]
    fn reject_empty_network_host_pattern_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_hosts: Some(vec!["".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::EmptyNetworkHost(id, idx)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            _ => panic!("expected EmptyNetworkHost"),
        }
    }

    #[test]
    fn reject_network_host_too_long_programmatic() {
        let long = "a".repeat(MAX_IDENTIFIER_LENGTH + 1);
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_hosts: Some(vec![long]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::NetworkHostTooLong(id, idx, len)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
                assert_eq!(len, MAX_IDENTIFIER_LENGTH + 1);
            }
            _ => panic!("expected NetworkHostTooLong"),
        }
    }

    #[test]
    fn reject_duplicate_network_host_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_hosts: Some(vec!["example.com".into(), "example.com".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::DuplicateNetworkHost(id)) => {
                assert_eq!(id.as_str(), "r1");
            }
            _ => panic!("expected DuplicateNetworkHost"),
        }
    }

    #[test]
    fn reject_network_host_null_byte() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_hosts: Some(vec!["example.com\0".into()]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::InvalidNetworkHost(id, idx)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(idx, 0);
            }
            _ => panic!("expected InvalidNetworkHost"),
        }
    }

    // -----------------------------------------------------------------------
    // Network port validation (programmatic)
    // -----------------------------------------------------------------------

    #[test]
    fn reject_empty_network_ports_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_ports: Some(vec![]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::EmptyNetworkPorts(id)) => {
                assert_eq!(id.as_str(), "r1");
            }
            _ => panic!("expected EmptyNetworkPorts"),
        }
    }

    #[test]
    fn reject_too_many_network_ports_programmatic() {
        let ports: Vec<u16> = (0..=MAX_NETWORK_PORT_PATTERNS).map(|i| i as u16).collect();
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_ports: Some(ports),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::TooManyNetworkPorts(id, count)) => {
                assert_eq!(id.as_str(), "r1");
                assert_eq!(count, MAX_NETWORK_PORT_PATTERNS + 1);
            }
            _ => panic!("expected TooManyNetworkPorts"),
        }
    }

    #[test]
    fn reject_duplicate_network_port_programmatic() {
        let result = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("r1").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    network_ports: Some(vec![443, 443]),
                    ..Default::default()
                },
            }],
        )]);
        match result {
            Err(PolicyValidationError::DuplicateNetworkPort(id)) => {
                assert_eq!(id.as_str(), "r1");
            }
            _ => panic!("expected DuplicateNetworkPort"),
        }
    }

    // -----------------------------------------------------------------------
    // Multiple policies
    // -----------------------------------------------------------------------

    #[test]
    fn rules_from_multiple_policies_are_evaluated() {
        let engine = PolicyEngine::new(vec![
            policy_with_id(
                "base",
                DefaultEffect::Deny,
                vec![Rule {
                    id: RuleId::new("base-allow-all").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Allow,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                }],
            ),
            policy_with_id(
                "override",
                DefaultEffect::Deny,
                vec![Rule {
                    id: RuleId::new("override-deny").unwrap(),
                    description: "".into(),
                    effect: PolicyEffect::Deny,
                    conditions: RuleConditions {
                        operations: vec!["file_read".into()],
                        ..Default::default()
                    },
                }],
            ),
        ])
        .unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        // Only deny-group IDs.
        assert!(
            !decision
                .matched_rule_ids
                .contains(&RuleId::new("base-allow-all").unwrap())
        );
        assert!(
            decision
                .matched_rule_ids
                .contains(&RuleId::new("override-deny").unwrap())
        );
    }

    #[test]
    fn empty_policies_default_to_deny() {
        let engine = PolicyEngine::new(vec![]).unwrap();
        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyDefault);
    }

    #[test]
    fn default_effect_cannot_be_allow() {
        match crate::model::DefaultEffect::Deny {
            crate::model::DefaultEffect::Deny => {}
            crate::model::DefaultEffect::RequireApproval => {}
        }
    }

    #[test]
    fn no_match_falls_to_default_require_approval() {
        let engine =
            PolicyEngine::new(vec![policy(DefaultEffect::RequireApproval, vec![])]).unwrap();

        let decision = engine.evaluate(&make_request(make_subject()));
        assert_eq!(decision.effect, DecisionEffect::RequireApproval);
        assert_eq!(decision.reason, ReasonCode::KavachApprovalRequired);
    }

    // -----------------------------------------------------------------------
    // Determinism — repeated evaluation gives same result
    // -----------------------------------------------------------------------

    #[test]
    fn repeated_evaluation_identical_decision() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("read-ok").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let req = make_request(make_subject());
        let d1 = engine.evaluate(&req);
        let d2 = engine.evaluate(&req);
        // Compare everything except evaluated_at (SystemTime changes).
        assert_eq!(d1.effect, d2.effect);
        assert_eq!(d1.reason, d2.reason);
        assert_eq!(d1.matched_rule_ids, d2.matched_rule_ids);
        assert_eq!(d1.request_id, d2.request_id);
    }

    // -----------------------------------------------------------------------
    // Phase 1 regression tests (audit fixes)
    // -----------------------------------------------------------------------

    fn allow_python_policy() -> Policy {
        policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-python").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    executables: Some(vec!["python".into()]),
                    ..Default::default()
                },
            }],
        )
    }

    fn cmd_request_with(exe: &str, args: &[&str], context: RequestContext) -> ToolRequest {
        make_request_with(
            make_subject(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new(
                    exe,
                    args.iter().map(|s| s.to_string()).collect(),
                )
                .unwrap(),
            ),
            context,
        )
    }

    // (a) `python -m pip install evil` is denied by the baseline even though
    // the allow-rule lists bare `python`.
    #[test]
    fn baseline_denies_python_m_pip() {
        let engine = PolicyEngine::new(vec![allow_python_policy()]).unwrap();
        let req = cmd_request_with("python", &["-m", "pip", "install", "evil"], make_context());
        let decision = engine.evaluate(&req);
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyExplicitRule);
        assert!(
            decision
                .matched_rule_ids
                .contains(&RuleId::new(BASELINE_DANGEROUS_INTERPRETER_RULE_ID).unwrap())
        );
        let trace = match decision.trace {
            Some(t) => t,
            None => panic!("baseline denial carries a trace"),
        };
        assert!(trace.baseline_triggered.is_some());
    }

    // (b) `python -c "..."` is denied by the baseline.
    #[test]
    fn baseline_denies_python_c_payload() {
        let engine = PolicyEngine::new(vec![allow_python_policy()]).unwrap();
        let req = cmd_request_with(
            "python",
            &["-c", "import os; os.system('id')"],
            make_context(),
        );
        let decision = engine.evaluate(&req);
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyExplicitRule);
    }

    #[test]
    fn baseline_denies_perl_ruby_node_eval_flags() {
        for (exe, flag) in [
            ("perl", "-e"),
            ("ruby", "-e"),
            ("node", "-e"),
            ("python3", "-c"),
        ] {
            assert!(
                is_known_dangerous_invocation(
                    &kavach_core::resource::CommandResource::new(
                        exe,
                        vec![flag.to_string(), "payload".to_string()]
                    )
                    .unwrap()
                ),
                "{exe} {flag} should be baseline-dangerous"
            );
        }
    }

    #[test]
    fn baseline_leaves_benign_interpreter_use_alone() {
        // `python script.py` / `node server.js` are NOT baseline hits; the
        // allow-rule still decides.
        let engine = PolicyEngine::new(vec![allow_python_policy()]).unwrap();
        let req = cmd_request_with("python", &["script.py"], make_context());
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Allow);
    }

    #[test]
    fn baseline_denies_substitution_hazard_in_args() {
        let engine = PolicyEngine::new(vec![allow_python_policy()]).unwrap();
        let req = cmd_request_with("python", &["script.py", "$(id)"], make_context());
        assert_eq!(engine.evaluate(&req).effect, DecisionEffect::Deny);
    }

    // (c) `argument_rules`: deny_if_matches and require_match.
    #[test]
    fn argument_rules_deny_if_matches_vetoes_rule() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-git-safe").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    executables: Some(vec!["git".into()]),
                    argument_rules: Some(crate::model::ArgumentRules {
                        deny_if_matches: Some(vec!["--hard".into()]),
                        require_match: None,
                    }),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let safe = cmd_request_with("git", &["status"], make_context());
        assert_eq!(engine.evaluate(&safe).effect, DecisionEffect::Allow);

        let hard = cmd_request_with("git", &["reset", "--hard"], make_context());
        let decision = engine.evaluate(&hard);
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.reason, ReasonCode::KavachDenyDefault);
    }

    #[test]
    fn argument_rules_require_match_gates_rule() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-kubectl-get").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    executables: Some(vec!["kubectl".into()]),
                    argument_rules: Some(crate::model::ArgumentRules {
                        deny_if_matches: None,
                        require_match: Some(vec!["get".into()]),
                    }),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        let get = cmd_request_with("kubectl", &["get", "pods"], make_context());
        assert_eq!(engine.evaluate(&get).effect, DecisionEffect::Allow);

        let delete = cmd_request_with("kubectl", &["delete", "pods"], make_context());
        assert_eq!(engine.evaluate(&delete).effect, DecisionEffect::Deny);
    }

    #[test]
    fn argument_rules_match_per_argument_not_joined() {
        // Pattern `*pip*` hits the single argument `-mpip` but must NOT
        // bridge two separate arguments `-m` + `pip`.
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-py").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    executables: Some(vec!["python".into()]),
                    argument_rules: Some(crate::model::ArgumentRules {
                        deny_if_matches: Some(vec!["pip".into()]),
                        require_match: None,
                    }),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // Exact single-argument `pip` vetoes...
        let exact = cmd_request_with("python", &["pip"], make_context());
        // ...but the baseline does not fire here (no -c/-m/substitution),
        // and the rule veto applies only to the exact arg.
        assert_eq!(engine.evaluate(&exact).effect, DecisionEffect::Deny);

        // Separate `-m`, `pip` args: `pip` arg still vetoes (per-arg match).
        let split = cmd_request_with("python", &["-m", "pip"], make_context());
        // Baseline fires first for `-m pip` (package-manager module).
        assert_eq!(engine.evaluate(&split).effect, DecisionEffect::Deny);
    }

    // (d) Relative pattern matches both relative and absolute (with cwd).
    #[test]
    fn relative_pattern_matches_absolute_with_working_directory() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-sympy").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    path_globs: Some(vec!["sympy/**/*.py".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();

        // Relative resource matches directly.
        let rel = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("sympy/core/x.py").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&rel).effect, DecisionEffect::Allow);

        // Absolute resource matches via working_directory fallback.
        let wd_ctx = RequestContext::new(Some("/workspace"), None, None, None, false).unwrap();
        let abs_wd = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/sympy/core/x.py").unwrap(),
            wd_ctx,
        );
        assert_eq!(engine.evaluate(&abs_wd).effect, DecisionEffect::Allow);

        // Same absolute path WITHOUT cwd context still misses (and the
        // load-time warning covers the surprise — see test (e)).
        let abs_no_wd = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/sympy/core/x.py").unwrap(),
            make_context(),
        );
        assert_eq!(engine.evaluate(&abs_no_wd).effect, DecisionEffect::Deny);

        // Component-aware: `/workspace2/...` must NOT match wd `/workspace`.
        let wd_ctx2 = RequestContext::new(Some("/workspace"), None, None, None, false).unwrap();
        let outside = make_request_with(
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace2/sympy/core/x.py").unwrap(),
            wd_ctx2,
        );
        assert_eq!(engine.evaluate(&outside).effect, DecisionEffect::Deny);
    }

    // (e) Relative pattern with no cwd context emits a validation warning.
    #[test]
    fn relative_pattern_emits_load_time_warning() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-rel").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["sympy/**/*.py".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();
        let warnings = engine.warnings();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].rule_id.as_str(), "allow-rel");
        assert!(warnings[0].message.contains("working_directory"));

        // Absolute patterns produce no warnings.
        let engine_abs = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-abs").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    path_globs: Some(vec!["/workspace/**/*.py".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();
        assert!(engine_abs.warnings().is_empty());
    }

    // (f) Empty-string working_directory is None (regression guard).
    #[test]
    fn empty_working_directory_is_none() {
        let ctx = RequestContext::new(Some(""), None, None, None, false).unwrap();
        assert!(ctx.working_directory.is_none());
    }

    // (g) Backslash normalization matrix (regression guard).
    #[test]
    fn backslash_normalization_matrix() {
        use kavach_core::resource::NormalizedPath;
        let cases = [
            ("C:\\a/b\\c.txt", "C:/a/b/c.txt"),
            ("a\\..\\b", "b"),
            ("trailing\\", "trailing"),
            ("mixed//a\\\\b", "mixed/a/b"),
        ];
        for (raw, expected) in cases {
            let path = NormalizedPath::new(raw).unwrap();
            assert_eq!(path.normalized(), expected, "raw: {raw}");
        }
        let unc = NormalizedPath::new("\\\\server\\share\\x").unwrap();
        assert!(unc.normalized().contains("server"));
        assert!(unc.normalized().contains("share"));
        assert!(!unc.normalized().contains('\\'));
    }

    // Trace sanity: failed conditions are reported, additive fields survive.
    #[test]
    fn decision_trace_reports_failed_conditions() {
        let engine = PolicyEngine::new(vec![policy(
            DefaultEffect::Deny,
            vec![Rule {
                id: RuleId::new("allow-kubectl").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    executables: Some(vec!["kubectl".into()]),
                    ..Default::default()
                },
            }],
        )])
        .unwrap();
        let req = cmd_request_with("docker", &["ps"], make_context());
        let decision = engine.evaluate(&req);
        assert_eq!(decision.effect, DecisionEffect::Deny);
        let trace = match decision.trace {
            Some(t) => t,
            None => panic!("decision carries a trace"),
        };
        assert!(trace.baseline_triggered.is_none());
        assert!(trace.failed_conditions.contains(&"executables".to_string()));
    }
}
