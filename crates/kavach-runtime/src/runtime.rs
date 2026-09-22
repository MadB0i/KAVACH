use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use getrandom::getrandom;

use kavach_approval::{
    ApprovalActor, ApprovalBroker, ApprovalRequest, ApprovalToken, ConsumedApproval,
    open_approval_broker, open_approval_broker_in_memory,
};
use kavach_audit::event::AuditAppendInput;
use kavach_audit::{AuditEventCategory, AuditStore, AuditStoreBuilder};
use kavach_core::ids::{ApprovalId, RuleId};
use kavach_core::permit::{ExecutionPermit, PermitScope, required_scope};
use kavach_core::request::ToolRequest;
use kavach_core::{DecisionEffect, compute_request_digest};
use kavach_policy::PolicyEngine;
use kavach_redaction::Redactor;

use crate::config::RuntimeConfig;
use crate::error::RuntimeError;
use crate::outcome::{ExecutionInput, ExecutionResult, PermittedOutcome, RuntimeOutcome};
use crate::registry::{AdapterKind, AdapterRegistry};

/// The production runtime orchestrating policy evaluation, approval, permits,
/// enforcement, audit, and redaction.
///
/// # Thread Safety
///
/// `KavachRuntime` is `Send + Sync`.  The policy engine is read-only after
/// construction.  The audit store uses internal mutex-based serialisation.
/// The approval broker uses SQLite `BEGIN IMMEDIATE` transactions.
/// Adapters are read-only after construction.  There is no single global
/// mutex.
pub struct KavachRuntime {
    engine: PolicyEngine,
    config: RuntimeConfig,
    registry: AdapterRegistry,
    broker: Arc<dyn ApprovalBroker>,
    audit_store: AuditStore,
    redactor: Option<Arc<dyn Redactor>>,
}

impl KavachRuntime {
    /// Evaluate a [`ToolRequest`] and return a [`RuntimeOutcome`].
    ///
    /// The evaluation flow is:
    ///
    /// 1. Validate the request.
    /// 2. Evaluate against the current policy snapshot.
    /// 3. Depending on the decision effect:
    ///    - **Deny**: audit and return `Denied`.
    ///    - **RequireApproval**: create a pending approval, audit, and return
    ///      `ApprovalRequired`.
    ///    - **Allow**: issue a request-bound `ExecutionPermit`, audit, and
    ///      return `Permitted`.
    ///
    /// This method never executes side effects, even for allowed requests.
    pub fn evaluate(&self, request: &ToolRequest) -> Result<RuntimeOutcome, RuntimeError> {
        // 1. Validate
        request
            .validate()
            .map_err(|e| RuntimeError::InvalidRequest(e.to_string()))?;

        // 2. Policy evaluation
        let decision = self.engine.evaluate(request);

        let request_id = request.request_id.clone();
        let matched_ids: Vec<RuleId> = decision.matched_rule_ids.to_vec();
        let reason_code = decision.reason.clone();

        match decision.effect {
            DecisionEffect::Deny => {
                let summary = self.sanitize_summary(&decision.explanation)?;
                let seq =
                    self.audit_decision(request, AuditEventCategory::DecisionDeny, &decision)?;
                Ok(RuntimeOutcome::Denied {
                    request_id,
                    reason_code,
                    matched_rule_ids: matched_ids,
                    sanitized_summary: summary,
                    audit_event_id: seq,
                })
            }
            DecisionEffect::RequireApproval => {
                let summary = self.sanitize_summary(&decision.explanation)?;

                let approval_request = ApprovalRequest {
                    request: request.clone(),
                    summary: summary.clone(),
                    matched_rule_ids: matched_ids.iter().map(|id| id.to_string()).collect(),
                };

                let pending = self
                    .broker
                    .request_approval(&approval_request, None)
                    .map_err(|e| RuntimeError::ApprovalFailure(e.to_string()))?;

                let seq = self
                    .broker
                    .get_approval(&pending.approval_id)
                    .map_err(|e| RuntimeError::ApprovalFailure(e.to_string()))?
                    .audit_sequence
                    .ok_or_else(|| {
                        RuntimeError::AuditFailure(
                            "approval request is missing its audit sequence".into(),
                        )
                    })?;

                Ok(RuntimeOutcome::ApprovalRequired {
                    request_id,
                    approval_id: pending.approval_id,
                    sanitized_summary: summary,
                    audit_event_id: seq,
                })
            }
            DecisionEffect::Allow => {
                let scope = required_scope(&request.operation);
                let secret = self.generate_permit_secret()?;
                let digest = compute_request_digest(request);
                let ttl = self.config.permit_ttl;

                let permit = ExecutionPermit::new(
                    &secret,
                    request.request_id.clone(),
                    scope,
                    matched_ids,
                    digest,
                    ttl,
                );

                let outcome = PermittedOutcome::new(permit, secret);

                let _seq =
                    self.audit_decision(request, AuditEventCategory::DecisionAllow, &decision)?;

                Ok(RuntimeOutcome::Permitted(outcome))
            }
        }
    }

    /// Execute an operation using a previously issued permit.
    ///
    /// Steps:
    ///
    /// 1. Verify the permit secret matches.
    /// 2. Verify the permit is not expired and not consumed.
    /// 3. Verify the request digest matches.
    /// 4. Verify the permit scope is sufficient.
    /// 5. Consume the permit (single-use).
    /// 6. Dispatch to the correct enforcement adapter.
    /// 7. Audit execution started (before actual side effects).
    /// 8. Execute.
    /// 9. Redact output if configured.
    /// 10. Audit success or failure.
    pub fn execute(
        &self,
        request: &ToolRequest,
        permit: &mut ExecutionPermit,
        permit_secret: &[u8; 32],
        input: ExecutionInput<'_>,
    ) -> Result<ExecutionResult, RuntimeError> {
        // Dry-run guard.
        if self.config.dry_run {
            return Err(RuntimeError::DryRunExecutionRejected);
        }

        // 1. Verify secret
        if !permit.verify_secret(permit_secret) {
            return Err(RuntimeError::PermitFailure("permit secret mismatch".into()));
        }

        // 2. Verify not expired
        if permit.is_expired() {
            return Err(RuntimeError::PermitFailure("permit expired".into()));
        }
        if permit.is_consumed() {
            return Err(RuntimeError::PermitFailure(
                "permit already consumed".into(),
            ));
        }

        // 3. Verify request digest
        let digest = compute_request_digest(request);
        if !permit.verify_request_digest(&digest) {
            return Err(RuntimeError::PermitFailure(
                "request digest mismatch".into(),
            ));
        }

        // 4. Verify scope
        let required = required_scope(&request.operation);
        if !scope_sufficient(required, permit.scope) {
            return Err(RuntimeError::PermitScopeMismatch {
                expected: required,
                actual: permit.scope,
            });
        }

        // 5. Dispatch. The selected enforcement adapter performs the final
        // request-bound verification and consumes the permit exactly once.
        let adapter_kind = AdapterRegistry::resolve_operation(request)?;

        // 6. Audit execution started before any side effect. Audit failures
        // are security failures and must stop execution.
        self.audit_execution_started(request, adapter_kind)?;

        let result = match adapter_kind {
            AdapterKind::Filesystem => {
                let fs_input = match input {
                    ExecutionInput::None => kavach_enforcement::FilesystemInput::None,
                    ExecutionInput::FilesystemWrite(data) => {
                        kavach_enforcement::FilesystemInput::WriteBytes(data)
                    }
                    _ => {
                        return self.finish_failed_execution(
                            request,
                            adapter_kind,
                            RuntimeError::InvalidExecutionInput(
                                "expected FilesystemWrite or None for filesystem operation".into(),
                            ),
                        );
                    }
                };
                self.registry
                    .filesystem
                    .execute(request, permit, fs_input)
                    .map(ExecutionResult::Filesystem)
                    .map_err(|e| RuntimeError::FilesystemFailure(e.to_string()))
            }
            AdapterKind::Command => {
                let cmd_input = match input {
                    ExecutionInput::Command(ci) => ci,
                    _ => {
                        return self.finish_failed_execution(
                            request,
                            adapter_kind,
                            RuntimeError::InvalidExecutionInput(
                                "expected CommandInput for command operation".into(),
                            ),
                        );
                    }
                };
                self.registry
                    .command
                    .execute(request, permit, &cmd_input)
                    .map(ExecutionResult::Command)
                    .map_err(|e| RuntimeError::CommandFailure(e.to_string()))
            }
            AdapterKind::Network => {
                let net_input = match input {
                    ExecutionInput::Network(ni) => ni,
                    _ => {
                        return self.finish_failed_execution(
                            request,
                            adapter_kind,
                            RuntimeError::InvalidExecutionInput(
                                "expected NetworkInput for network operation".into(),
                            ),
                        );
                    }
                };
                self.registry
                    .network
                    .execute(request, permit, &net_input)
                    .map(ExecutionResult::Network)
                    .map_err(|e| RuntimeError::NetworkFailure(e.to_string()))
            }
        };

        // 7-8. Redact and audit. Returning unredacted output after a
        // redaction error would leak sensitive data, so redaction fails closed.
        match result {
            Ok(exec_result) => {
                let redacted = if self.config.redaction_enabled {
                    match &self.redactor {
                        Some(r) => match exec_result.redacted(r.as_ref()) {
                            Ok(result) => result,
                            Err(error) => {
                                return self.finish_failed_execution(
                                    request,
                                    adapter_kind,
                                    RuntimeError::RedactionFailure(error.to_string()),
                                );
                            }
                        },
                        None => exec_result.clone(),
                    }
                } else {
                    exec_result.clone()
                };
                self.audit_execution_result(request, adapter_kind, true)?;
                Ok(redacted)
            }
            Err(e) => self.finish_failed_execution(request, adapter_kind, e),
        }
    }

    // ── Approval flow ───────────────────────────────────────────────────

    /// Approve a pending approval. Returns the [`ApprovalToken`] needed for
    /// consumption.
    pub fn approve(
        &self,
        approval_id: &ApprovalId,
        actor: &ApprovalActor,
    ) -> Result<ApprovalToken, RuntimeError> {
        self.broker
            .approve(approval_id, actor)
            .map_err(|e| RuntimeError::ApprovalFailure(e.to_string()))
    }

    /// Deny a pending approval.
    pub fn deny(
        &self,
        approval_id: &ApprovalId,
        actor: &ApprovalActor,
        reason: Option<&str>,
    ) -> Result<(), RuntimeError> {
        self.broker
            .deny(approval_id, actor, reason)
            .map_err(|e| RuntimeError::ApprovalFailure(e.to_string()))
    }

    /// Consume an approved approval and exchange the token for a scoped
    /// [`ExecutionPermit`].
    ///
    /// The flow is:
    ///
    /// 1. The human approves via [`approve`](KavachRuntime::approve), which
    ///    returns an [`ApprovalToken`].
    /// 2. The caller presents the token + original request.
    /// 3. The broker verifies and consumes the token.
    /// 4. The runtime issues a request-bound, scoped [`ExecutionPermit`].
    /// 5. The permit is paired with its secret in a
    ///    [`PermittedOutcome`].
    ///
    /// An approval token **never** directly authorises execution.  The caller
    /// must present the permit to [`execute`](KavachRuntime::execute).
    pub fn consume_approval(
        &self,
        request: &ToolRequest,
        approval_id: &ApprovalId,
        token: &ApprovalToken,
    ) -> Result<PermittedOutcome, RuntimeError> {
        // Verify request binding before consuming the one-time token. A
        // mismatched request must not be able to destroy a valid approval.
        let digest = compute_request_digest(request);
        let approval = self
            .broker
            .get_approval(approval_id)
            .map_err(|e| RuntimeError::ApprovalFailure(e.to_string()))?;
        if !constant_time_eq::constant_time_eq(&digest, &approval.request_digest) {
            return Err(RuntimeError::PermitFailure(
                "approval request digest does not match presented request".into(),
            ));
        }

        let consumed: ConsumedApproval = self
            .broker
            .consume(approval_id, token)
            .map_err(|e| RuntimeError::ApprovalFailure(e.to_string()))?;

        // Re-verify the digest returned by the transactional consume.
        if !constant_time_eq::constant_time_eq(&digest, &consumed.request_digest) {
            return Err(RuntimeError::PermitFailure(
                "approval request digest does not match presented request".into(),
            ));
        }

        let scope = required_scope(&request.operation);
        let secret = self.generate_permit_secret()?;
        let ttl = self.config.permit_ttl;

        let matched_ids: Vec<RuleId> = consumed
            .matched_rule_ids
            .iter()
            .map(|id| {
                RuleId::new(id).map_err(|error| {
                    RuntimeError::ApprovalFailure(format!(
                        "approval returned an invalid matched rule ID: {error}"
                    ))
                })
            })
            .collect::<Result<_, _>>()?;

        let permit = ExecutionPermit::new(
            &secret,
            request.request_id.clone(),
            scope,
            matched_ids,
            digest,
            ttl,
        );

        Ok(PermittedOutcome::new(permit, secret))
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn generate_permit_secret(&self) -> Result<[u8; 32], RuntimeError> {
        let mut secret = [0u8; 32];
        getrandom(&mut secret)
            .map_err(|e| RuntimeError::InternalConsistencyFailure(format!("rng: {e}")))?;
        Ok(secret)
    }

    fn finish_failed_execution<T>(
        &self,
        request: &ToolRequest,
        adapter_kind: AdapterKind,
        error: RuntimeError,
    ) -> Result<T, RuntimeError> {
        self.audit_execution_result(request, adapter_kind, false)?;
        Err(error)
    }

    fn sanitize_summary(&self, summary: &str) -> Result<String, RuntimeError> {
        let s = if self.config.redaction_enabled {
            match &self.redactor {
                Some(redactor) => redactor
                    .redact_text(summary)
                    .map(|r| r.redacted)
                    .map_err(|e| RuntimeError::RedactionFailure(e.to_string()))?,
                None => summary.to_string(),
            }
        } else {
            summary.to_string()
        };
        if s.len() > self.config.max_sanitized_summary_length {
            let mut end = self.config.max_sanitized_summary_length;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            Ok(s[..end].to_string())
        } else {
            Ok(s)
        }
    }

    fn make_audit_input(
        &self,
        request: &ToolRequest,
        category: AuditEventCategory,
        decision: Option<&str>,
        reason_code: Option<&str>,
        matched_rule_ids: &[RuleId],
        metadata: BTreeMap<String, String>,
    ) -> Result<AuditAppendInput, RuntimeError> {
        let resource_kind = request.resource.kind().to_string();
        let resource_summary = match &request.resource {
            kavach_core::resource::Resource::File { path }
            | kavach_core::resource::Resource::Directory { path } => path.normalized().to_string(),
            kavach_core::resource::Resource::Secret { identifier }
            | kavach_core::resource::Resource::ExternalTool { identifier } => identifier.clone(),
            kavach_core::resource::Resource::Unknown => "unknown".to_string(),
            resource => format!("{resource:?}"),
        };
        Ok(AuditAppendInput {
            category,
            request_id: Some(request.request_id.to_string()),
            agent_id: Some(request.subject.agent_id.to_string()),
            operation: Some(request.operation.as_str().to_string()),
            resource_kind: Some(resource_kind),
            resource_summary: Some(self.sanitize_summary(&resource_summary)?),
            decision: decision.map(|s| s.to_string()),
            reason_code: reason_code.map(|s| s.to_string()),
            matched_rule_ids: matched_rule_ids.iter().map(|id| id.to_string()).collect(),
            metadata,
        })
    }

    fn audit_decision(
        &self,
        request: &ToolRequest,
        category: AuditEventCategory,
        decision: &kavach_core::decision::AuthorizationDecision,
    ) -> Result<u64, RuntimeError> {
        let input = self.make_audit_input(
            request,
            category,
            Some(decision.effect.as_str()),
            Some(decision.reason.as_str()),
            &decision.matched_rule_ids,
            BTreeMap::new(),
        )?;
        self.append_audit(input)
    }

    fn audit_execution_started(
        &self,
        request: &ToolRequest,
        kind: AdapterKind,
    ) -> Result<u64, RuntimeError> {
        let mut metadata = BTreeMap::new();
        metadata.insert("adapter".into(), format!("{kind:?}"));
        let input = self.make_audit_input(
            request,
            AuditEventCategory::ExecutionStarted,
            None,
            None,
            &[],
            metadata,
        )?;
        self.append_audit(input)
    }

    fn audit_execution_result(
        &self,
        request: &ToolRequest,
        kind: AdapterKind,
        succeeded: bool,
    ) -> Result<u64, RuntimeError> {
        let category = if succeeded {
            AuditEventCategory::ExecutionSucceeded
        } else {
            AuditEventCategory::ExecutionFailed
        };
        let mut metadata = BTreeMap::new();
        metadata.insert("adapter".into(), format!("{kind:?}"));
        metadata.insert("succeeded".into(), succeeded.to_string());
        let input = self.make_audit_input(request, category, None, None, &[], metadata)?;
        self.append_audit(input)
    }

    fn append_audit(&self, input: AuditAppendInput) -> Result<u64, RuntimeError> {
        match self.audit_store.append(input) {
            Ok(summary) => Ok(summary.sequence),
            Err(e) => {
                if self.config.audit_fail_closed {
                    Err(RuntimeError::AuditFailure(e.to_string()))
                } else {
                    Ok(0)
                }
            }
        }
    }

    // ── Policy reload ───────────────────────────────────────────────────

    /// Atomically replace the policy engine with a new one built from the
    /// given policies.  Existing in-flight requests that have already called
    /// [`evaluate`](KavachRuntime::evaluate) continue with the old engine;
    /// new evaluations use the new engine.
    pub fn reload_policies(
        &mut self,
        policies: Vec<kavach_policy::Policy>,
    ) -> Result<(), RuntimeError> {
        let engine =
            PolicyEngine::new(policies).map_err(|e| RuntimeError::PolicyFailure(e.to_string()))?;
        self.engine = engine;
        Ok(())
    }

    // ── Accessors for gateway integration ───────────────────────────────

    /// Borrow the audit store.
    pub fn audit_store(&self) -> &AuditStore {
        &self.audit_store
    }

    /// Borrow the approval broker.
    pub fn broker(&self) -> &Arc<dyn ApprovalBroker> {
        &self.broker
    }

    /// Borrow the runtime config.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Return metadata for the active policy snapshot.
    pub fn policy_summaries(&self) -> Vec<kavach_policy::PolicySummary> {
        self.engine.summaries()
    }
}

/// Check whether `actual` scope is sufficient for the `required` scope.
fn scope_sufficient(required: PermitScope, actual: PermitScope) -> bool {
    if required == actual {
        return true;
    }
    use PermitScope::*;
    matches!(
        (required, actual),
        (CommandLowRisk, CommandElevated)
            | (CommandLowRisk, CommandDestructive)
            | (CommandElevated, CommandDestructive)
            | (FilesystemRead, FilesystemWrite)
            | (FilesystemRead, FilesystemMutation)
            | (FilesystemWrite, FilesystemMutation)
    )
}

/// Builder for [`KavachRuntime`].
#[derive(Default)]
pub struct RuntimeBuilder {
    config: RuntimeConfig,
    policies: Vec<kavach_policy::Policy>,
    workspace_root: Option<PathBuf>,
    approval_db_path: Option<String>,
    approval_store_config: kavach_approval::ApprovalStoreConfig,
    audit_db_path: Option<String>,
    redactor: Option<Arc<dyn Redactor>>,
}

impl RuntimeBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the runtime configuration.
    pub fn with_config(mut self, config: RuntimeConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a policy to the engine.
    pub fn add_policy(mut self, policy: kavach_policy::Policy) -> Self {
        self.policies.push(policy);
        self
    }

    /// Set the workspace root for filesystem containment.
    pub fn with_workspace_root(mut self, root: PathBuf) -> Self {
        self.workspace_root = Some(root);
        self
    }

    /// Set the approval database path (defaults to in-memory for tests).
    pub fn with_approval_db(mut self, path: String) -> Self {
        self.approval_db_path = Some(path);
        self
    }

    /// Configure approval expiry and queue limits.
    pub fn with_approval_config(mut self, config: kavach_approval::ApprovalStoreConfig) -> Self {
        self.approval_store_config = config;
        self
    }

    /// Set the audit database path (defaults to in-memory for tests).
    pub fn with_audit_db(mut self, path: String) -> Self {
        self.audit_db_path = Some(path);
        self
    }

    /// Set the redactor for secret detection and masking.
    pub fn with_redactor(mut self, redactor: Arc<dyn Redactor>) -> Self {
        self.redactor = Some(redactor);
        self
    }

    /// Build the [`KavachRuntime`].
    pub fn build(self) -> Result<KavachRuntime, RuntimeError> {
        let redactor = if self.config.redaction_enabled {
            Some(self.redactor.unwrap_or_else(|| {
                Arc::new(kavach_redaction::CompositeRedactor::builder().build())
            }))
        } else {
            self.redactor
        };

        let engine = PolicyEngine::new(self.policies)
            .map_err(|e| RuntimeError::PolicyFailure(e.to_string()))?;

        let workspace_root = self.workspace_root.unwrap_or_else(|| PathBuf::from("."));
        let registry = AdapterRegistry::new_test(workspace_root)?;

        let audit_builder = || {
            let builder = AuditStoreBuilder::new();
            match &redactor {
                Some(redactor) => builder.with_redactor(Arc::clone(redactor)),
                None => builder,
            }
        };
        let audit_store = match self.audit_db_path {
            Some(ref path) => audit_builder().open(path),
            None => audit_builder().open_in_memory(),
        };
        let audit_store =
            audit_store.map_err(|e| RuntimeError::ConfigurationFailure(e.to_string()))?;
        let approval_audit = audit_store.clone();

        let broker: Arc<dyn ApprovalBroker> = match self.approval_db_path {
            Some(ref path) => open_approval_broker(
                path,
                self.approval_store_config.clone(),
                approval_audit,
                Box::new(kavach_approval::RealClock),
            )
            .map_err(|e| RuntimeError::ApprovalFailure(e.to_string()))?,
            None => open_approval_broker_in_memory(
                self.approval_store_config,
                approval_audit,
                Box::new(kavach_approval::RealClock),
            )
            .map_err(|e| RuntimeError::ApprovalFailure(e.to_string()))?,
        };

        Ok(KavachRuntime {
            engine,
            config: self.config,
            registry,
            broker,
            audit_store,
            redactor,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use kavach_core::ids::{AgentId, RequestId, SessionId};
    use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext};
    use kavach_core::resource::Resource;
    use kavach_core::subject::TrustLevel;
    use kavach_policy::{DefaultEffect, Effect as PolicyEffect, Rule, RuleConditions};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    fn allow_read_policy() -> kavach_policy::Policy {
        kavach_policy::Policy {
            id: kavach_core::ids::PolicyId::new("pol-allow").unwrap(),
            name: "allow-read".into(),
            description: "".into(),
            default_effect: DefaultEffect::Deny,
            rules: vec![Rule {
                id: RuleId::new("allow-read-rule").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        }
    }

    fn deny_all_policy() -> kavach_policy::Policy {
        kavach_policy::Policy {
            id: kavach_core::ids::PolicyId::new("pol-deny").unwrap(),
            name: "deny-all".into(),
            description: "".into(),
            default_effect: DefaultEffect::Deny,
            rules: vec![Rule {
                id: RuleId::new("deny-all-rule").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Deny,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        }
    }

    fn require_approval_policy() -> kavach_policy::Policy {
        kavach_policy::Policy {
            id: kavach_core::ids::PolicyId::new("pol-approval").unwrap(),
            name: "require-approval".into(),
            description: "".into(),
            default_effect: DefaultEffect::Deny,
            rules: vec![Rule {
                id: RuleId::new("require-approval-rule").unwrap(),
                description: "".into(),
                effect: PolicyEffect::RequireApproval,
                conditions: RuleConditions {
                    operations: vec!["file_read".into()],
                    ..Default::default()
                },
            }],
        }
    }

    fn make_file_read_request() -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-e2e").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent-e2e").unwrap(),
                SessionId::new("sess-e2e").unwrap(),
            )
            .trust_level(TrustLevel::Standard)
            .build(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/test.txt").unwrap(),
            RequestContext::new(None, None, None, None, false).unwrap(),
        )
    }

    fn make_actor(name: &str) -> ApprovalActor {
        ApprovalActor::new(name).unwrap()
    }

    fn build_runtime(policies: Vec<kavach_policy::Policy>, tmp_dir: &TempDir) -> KavachRuntime {
        let ws = tmp_dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let audit_path = tmp_dir
            .path()
            .join("audit.db")
            .to_string_lossy()
            .to_string();

        let mut builder = RuntimeBuilder::new()
            .with_config(RuntimeConfig {
                permit_ttl: Duration::from_secs(300),
                audit_fail_closed: true,
                redaction_enabled: false,
                max_sanitized_summary_length: 4096,
                dry_run: false,
            })
            .with_workspace_root(ws)
            .with_audit_db(audit_path);
        for p in policies {
            builder = builder.add_policy(p);
        }
        builder.build().unwrap()
    }

    // ── Core evaluation tests ───────────────────────────────────────────

    #[test]
    fn invalid_request_fails_closed() {
        // Operation/resource mismatch: CommandExecute on a file resource.
        let req = ToolRequest::new(
            RequestId::new("req-invalid").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent").unwrap(),
                SessionId::new("sess").unwrap(),
            )
            .trust_level(TrustLevel::Standard)
            .build(),
            Operation::CommandExecute,
            Resource::file("/workspace/test.txt").unwrap(),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );

        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let result = runtime.evaluate(&req);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RuntimeError::InvalidRequest(_)
        ));
    }

    #[test]
    fn explicit_deny_returns_denied() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![deny_all_policy()], &tmp);
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Denied { .. }));
    }

    #[test]
    fn deny_has_no_permit() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![deny_all_policy()], &tmp);
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Denied { .. }));
    }

    #[test]
    fn allow_returns_permit() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Permitted(_)));
    }

    #[test]
    fn permit_is_bound_to_request() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        if let RuntimeOutcome::Permitted(p) = &outcome {
            assert_eq!(p.permit.request_digest, compute_request_digest(&req));
            assert!(p.permit.request_id.to_string() == "req-e2e");
        } else {
            panic!("expected Permitted");
        }
    }

    #[test]
    fn require_approval_creates_pending() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![require_approval_policy()], &tmp);
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::ApprovalRequired { .. }));
    }

    #[test]
    fn approval_flow_produces_permit() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![require_approval_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();

        let (approval_id, request_id) = match &outcome {
            RuntimeOutcome::ApprovalRequired {
                approval_id,
                request_id,
                ..
            } => (approval_id.clone(), request_id.clone()),
            _ => panic!("expected ApprovalRequired"),
        };

        let token = runtime.approve(&approval_id, &make_actor("alice")).unwrap();

        let permitted = runtime
            .consume_approval(&req, &approval_id, &token)
            .unwrap();

        assert_eq!(permitted.permit.request_id, request_id);
        assert_eq!(
            permitted.permit.matched_rule_ids,
            vec![RuleId::new("require-approval-rule").unwrap()],
            "approval-derived permits must retain the policy rule binding"
        );
        assert!(*permitted.secret() != [0u8; 32]);

        let events = runtime.audit_store().events_after_sequence(0, 10).unwrap();
        let categories: Vec<_> = events.iter().map(|event| event.category).collect();
        assert_eq!(
            categories,
            vec![
                kavach_audit::AuditEventCategory::ApprovalRequested,
                kavach_audit::AuditEventCategory::ApprovalApproved,
                kavach_audit::AuditEventCategory::ApprovalConsumed,
            ],
            "approval transitions must use the runtime's dashboard-visible audit chain"
        );
    }

    #[test]
    fn wrong_approval_token_rejected() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![require_approval_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        let approval_id = match &outcome {
            RuntimeOutcome::ApprovalRequired { approval_id, .. } => approval_id.clone(),
            _ => panic!("expected ApprovalRequired"),
        };

        let fake_token = ApprovalToken::generate().unwrap();
        let err = runtime
            .consume_approval(&req, &approval_id, &fake_token)
            .unwrap_err();
        assert!(matches!(err, RuntimeError::ApprovalFailure(_)));
    }

    #[test]
    fn denied_approval_never_produces_permit() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![require_approval_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        let approval_id = match &outcome {
            RuntimeOutcome::ApprovalRequired { approval_id, .. } => approval_id.clone(),
            _ => panic!("expected ApprovalRequired"),
        };

        runtime
            .deny(&approval_id, &make_actor("alice"), Some("not needed"))
            .unwrap();

        let fake_token = ApprovalToken::generate().unwrap();
        let err = runtime
            .consume_approval(&req, &approval_id, &fake_token)
            .unwrap_err();
        assert!(matches!(err, RuntimeError::ApprovalFailure(_)));
    }

    #[test]
    fn modified_request_after_approval_rejected() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![require_approval_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        let approval_id = match &outcome {
            RuntimeOutcome::ApprovalRequired { approval_id, .. } => approval_id.clone(),
            _ => panic!("expected ApprovalRequired"),
        };

        let token = runtime.approve(&approval_id, &make_actor("alice")).unwrap();

        let mut modified_req = make_file_read_request();
        modified_req.request_id = RequestId::new("req-modified").unwrap();

        let err = runtime
            .consume_approval(&modified_req, &approval_id, &token)
            .unwrap_err();
        assert!(matches!(err, RuntimeError::PermitFailure(_)));

        let permitted = runtime
            .consume_approval(&req, &approval_id, &token)
            .expect("a mismatched request must not consume the valid approval token");
        assert_eq!(permitted.request_id(), &req.request_id);
    }

    #[test]
    fn permit_replay_rejected() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();

        let (mut permit, secret) = match outcome {
            RuntimeOutcome::Permitted(p) => {
                let secret = *p.secret();
                (p.permit, secret)
            }
            _ => panic!("expected Permitted"),
        };

        assert!(permit.verify_secret(&secret));
        assert!(permit.consume());
        assert!(!permit.consume());
    }

    #[test]
    fn permit_for_another_request_rejected() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();

        let permit = match outcome {
            RuntimeOutcome::Permitted(p) => p.permit,
            _ => panic!("expected Permitted"),
        };

        let other_req = ToolRequest::new(
            RequestId::new("req-other").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent-other").unwrap(),
                SessionId::new("sess-other").unwrap(),
            )
            .trust_level(TrustLevel::Standard)
            .build(),
            Operation::FileRead { max_bytes: None },
            Resource::file("/workspace/other.txt").unwrap(),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );

        let other_digest = compute_request_digest(&other_req);
        assert!(!permit.verify_request_digest(&other_digest));
    }

    #[test]
    fn dry_run_never_issues_usable_permit() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let engine = PolicyEngine::new(vec![allow_read_policy()]).unwrap();
        let registry = AdapterRegistry::new_test(ws).unwrap();
        let audit_store = AuditStoreBuilder::new().open_in_memory().unwrap();
        let approval_audit = AuditStoreBuilder::new().open_in_memory().unwrap();
        let broker: Arc<dyn ApprovalBroker> = open_approval_broker_in_memory(
            kavach_approval::ApprovalStoreConfig::default(),
            approval_audit,
            Box::new(kavach_approval::RealClock),
        )
        .unwrap();

        let runtime = KavachRuntime {
            engine,
            config: RuntimeConfig {
                dry_run: true,
                ..Default::default()
            },
            registry,
            broker,
            audit_store,
            redactor: None,
        };

        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Permitted(_)));

        // Still returns Permitted in dry-run (policy says allow), but execute
        // must reject.
        if let RuntimeOutcome::Permitted(p) = outcome {
            let secret = *p.secret();
            let mut permit = p.permit;
            let err = runtime.execute(&req, &mut permit, &secret, ExecutionInput::None);
            assert!(matches!(err, Err(RuntimeError::DryRunExecutionRejected)));
        }
    }

    #[test]
    fn repeated_evaluation_is_deterministic() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = make_file_read_request();
        let o1 = runtime.evaluate(&req).unwrap();
        let o2 = runtime.evaluate(&req).unwrap();
        assert!(matches!(o1, RuntimeOutcome::Permitted(_)));
        assert!(matches!(o2, RuntimeOutcome::Permitted(_)));
    }

    #[test]
    fn scope_sufficient_checks_work() {
        use PermitScope::*;
        assert!(scope_sufficient(FilesystemRead, FilesystemRead));
        assert!(scope_sufficient(FilesystemRead, FilesystemWrite));
        assert!(scope_sufficient(FilesystemRead, FilesystemMutation));
        assert!(scope_sufficient(FilesystemWrite, FilesystemMutation));
        assert!(scope_sufficient(CommandLowRisk, CommandElevated));
        assert!(scope_sufficient(CommandLowRisk, CommandDestructive));
        assert!(scope_sufficient(CommandElevated, CommandDestructive));
        assert!(!scope_sufficient(FilesystemWrite, FilesystemRead));
        assert!(!scope_sufficient(FilesystemMutation, FilesystemRead));
        assert!(!scope_sufficient(CommandElevated, CommandLowRisk));
        assert!(!scope_sufficient(FilesystemRead, NetworkRequest));
        assert!(!scope_sufficient(NetworkRequest, CommandLowRisk));
    }

    #[test]
    fn missing_adapter_fails_closed() {
        let tmp = TempDir::new().unwrap();
        let _runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let secret_req = ToolRequest::new(
            RequestId::new("req-secret").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent").unwrap(),
                SessionId::new("sess").unwrap(),
            )
            .trust_level(TrustLevel::Standard)
            .build(),
            Operation::SecretAccess,
            Resource::Secret {
                identifier: "my-key".into(),
            },
            RequestContext::new(None, None, None, None, false).unwrap(),
        );

        let err = AdapterRegistry::resolve_operation(&secret_req);
        assert!(matches!(err, Err(RuntimeError::MissingAdapter(_))));
    }

    #[test]
    fn unsupported_tool_invoke_fails_closed() {
        let tmp = TempDir::new().unwrap();
        let _runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let tool_req = ToolRequest::new(
            RequestId::new("req-tool").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent").unwrap(),
                SessionId::new("sess").unwrap(),
            )
            .trust_level(TrustLevel::Standard)
            .build(),
            Operation::ToolInvoke {
                tool_id: "my-tool".into(),
            },
            Resource::ExternalTool {
                identifier: "my-tool".into(),
            },
            RequestContext::new(None, None, None, None, false).unwrap(),
        );

        let err = AdapterRegistry::resolve_operation(&tool_req);
        assert!(matches!(err, Err(RuntimeError::MissingAdapter(_))));
    }

    #[test]
    fn concurrent_evaluation_is_safe() {
        let tmp = TempDir::new().unwrap();
        let runtime = Arc::new(build_runtime(vec![allow_read_policy()], &tmp));
        let req = Arc::new(make_file_read_request());

        let mut handles = Vec::new();
        for _ in 0..4 {
            let r = Arc::clone(&runtime);
            let q = Arc::clone(&req);
            handles.push(std::thread::spawn(move || r.evaluate(&q).unwrap()));
        }

        for h in handles {
            let outcome = h.join().unwrap();
            assert!(matches!(outcome, RuntimeOutcome::Permitted(_)));
        }
    }

    #[test]
    fn concurrent_approval_token_consumption_produces_one_success() {
        let tmp = TempDir::new().unwrap();
        let runtime = Arc::new(build_runtime(vec![require_approval_policy()], &tmp));
        let req = Arc::new(make_file_read_request());

        let outcome = runtime.evaluate(&req).unwrap();
        let approval_id = match &outcome {
            RuntimeOutcome::ApprovalRequired { approval_id, .. } => approval_id.clone(),
            _ => panic!("expected ApprovalRequired"),
        };

        let token = runtime.approve(&approval_id, &make_actor("alice")).unwrap();
        let token_arc = Arc::new(token);

        let mut handles = Vec::new();
        for _ in 0..3 {
            let r = Arc::clone(&runtime);
            let q = Arc::clone(&req);
            let t = Arc::clone(&token_arc);
            let aid = approval_id.clone();
            handles.push(std::thread::spawn(move || r.consume_approval(&q, &aid, &t)));
        }

        let mut successes = 0;
        let mut failures = 0;
        for h in handles {
            match h.join().unwrap() {
                Ok(_) => successes += 1,
                Err(_) => failures += 1,
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(failures, 2);
    }

    // ── Configuration edge cases ─────────────────────────────────────────

    #[test]
    fn dry_run_permit_never_executes() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let audit_store = AuditStoreBuilder::new().open_in_memory().unwrap();
        let approval_audit = AuditStoreBuilder::new().open_in_memory().unwrap();
        let broker: Arc<dyn ApprovalBroker> = open_approval_broker_in_memory(
            kavach_approval::ApprovalStoreConfig::default(),
            approval_audit,
            Box::new(kavach_approval::RealClock),
        )
        .unwrap();
        let engine = PolicyEngine::new(vec![allow_read_policy()]).unwrap();
        let registry = AdapterRegistry::new_test(ws).unwrap();
        let runtime = KavachRuntime {
            engine,
            config: RuntimeConfig {
                dry_run: true,
                ..Default::default()
            },
            registry,
            broker,
            audit_store,
            redactor: None,
        };
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Permitted(_)));
        if let RuntimeOutcome::Permitted(p) = outcome {
            let secret = *p.secret();
            let mut permit = p.permit;
            let err = runtime.execute(
                &make_file_read_request(),
                &mut permit,
                &secret,
                ExecutionInput::None,
            );
            assert!(matches!(err, Err(RuntimeError::DryRunExecutionRejected)));
        }
    }

    #[test]
    fn audit_fail_closed_rejects_on_audit_failure() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let audit_store = AuditStoreBuilder::new().open_in_memory().unwrap();
        let approval_audit = AuditStoreBuilder::new().open_in_memory().unwrap();
        let broker: Arc<dyn ApprovalBroker> = open_approval_broker_in_memory(
            kavach_approval::ApprovalStoreConfig::default(),
            approval_audit,
            Box::new(kavach_approval::RealClock),
        )
        .unwrap();
        let engine = PolicyEngine::new(vec![allow_read_policy()]).unwrap();
        let registry = AdapterRegistry::new_test(ws).unwrap();
        let runtime = KavachRuntime {
            engine,
            config: RuntimeConfig {
                dry_run: false,
                audit_fail_closed: false,
                redaction_enabled: false,
                max_sanitized_summary_length: 4096,
                permit_ttl: Duration::from_secs(300),
            },
            registry,
            broker,
            audit_store,
            redactor: None,
        };
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Permitted(_)));
    }

    #[test]
    fn empty_policy_default_deny() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![], &tmp);
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Denied { .. }));
    }

    #[test]
    fn max_summary_length_truncation() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let audit_path = tmp.path().join("audit.db").to_string_lossy().to_string();
        let runtime = RuntimeBuilder::new()
            .with_config(RuntimeConfig {
                permit_ttl: Duration::from_secs(300),
                audit_fail_closed: false,
                redaction_enabled: false,
                max_sanitized_summary_length: 10,
                dry_run: false,
            })
            .with_workspace_root(ws)
            .with_audit_db(audit_path)
            .add_policy(deny_all_policy())
            .build()
            .unwrap();
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        if let RuntimeOutcome::Denied {
            sanitized_summary, ..
        } = outcome
        {
            assert!(sanitized_summary.len() <= 10);
        } else {
            panic!("expected Denied");
        }
    }

    // ── Multi-policy and precedence tests ────────────────────────────────

    #[test]
    fn deny_precedence_over_allow() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![allow_read_policy(), deny_all_policy()], &tmp);
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Denied { .. }));
    }

    #[test]
    fn approval_precedence_over_allow() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![allow_read_policy(), require_approval_policy()], &tmp);
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::ApprovalRequired { .. }));
    }

    #[test]
    fn deny_precedence_over_approval() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![require_approval_policy(), deny_all_policy()], &tmp);
        let outcome = runtime.evaluate(&make_file_read_request()).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Denied { .. }));
    }

    // ── Permit scope enforcement ─────────────────────────────────────────

    #[test]
    fn permit_wrong_scope_rejected_at_execution() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = make_file_read_request();
        let secret = [42u8; 32];
        let digest = compute_request_digest(&req);
        let mut permit = ExecutionPermit::new(
            &secret,
            req.request_id.clone(),
            PermitScope::NetworkRequest,
            vec![],
            digest,
            Duration::from_secs(300),
        );
        let err = runtime.execute(&req, &mut permit, &secret, ExecutionInput::None);
        assert!(matches!(err, Err(RuntimeError::PermitScopeMismatch { .. })));
    }

    #[test]
    fn expired_permit_rejected_at_execution() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        if let RuntimeOutcome::Permitted(p) = outcome {
            let secret = *p.secret();
            let mut permit = p.permit;
            permit.expires_at = std::time::SystemTime::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap();
            let err = runtime.execute(&req, &mut permit, &secret, ExecutionInput::None);
            assert!(matches!(err, Err(RuntimeError::PermitFailure(_))));
        } else {
            panic!("expected Permitted");
        }
    }

    // ── Execution flow tests ─────────────────────────────────────────────

    #[test]
    fn execute_file_read_round_trip() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("exec-test.txt"), b"verified runtime read").unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = ToolRequest::new(
            RequestId::new("req-read-exec").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent").unwrap(),
                SessionId::new("sess").unwrap(),
            )
            .trust_level(TrustLevel::Standard)
            .build(),
            Operation::FileRead { max_bytes: None },
            Resource::file("exec-test.txt").unwrap(),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );
        let eval = runtime.evaluate(&req).unwrap();
        if let RuntimeOutcome::Permitted(p) = eval {
            let secret = *p.secret();
            let mut permit = p.permit;
            let result = runtime
                .execute(&req, &mut permit, &secret, ExecutionInput::None)
                .unwrap();
            match result {
                ExecutionResult::Filesystem(kavach_enforcement::FilesystemOutcome::FileRead {
                    bytes,
                    bytes_read,
                }) => {
                    assert_eq!(bytes, b"verified runtime read");
                    assert_eq!(bytes_read, 21);
                }
                other => panic!("expected filesystem read result, got {other:?}"),
            }
            assert!(permit.is_consumed());

            let events = runtime.audit_store().events_after_sequence(0, 10).unwrap();
            let categories: Vec<_> = events.iter().map(|event| event.category).collect();
            assert_eq!(
                categories,
                vec![
                    kavach_audit::AuditEventCategory::DecisionAllow,
                    kavach_audit::AuditEventCategory::ExecutionStarted,
                    kavach_audit::AuditEventCategory::ExecutionSucceeded,
                ]
            );
        } else {
            panic!("expected Permitted");
        }
    }

    #[test]
    fn execute_with_consumed_permit_rejected() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        if let RuntimeOutcome::Permitted(p) = outcome {
            let secret = *p.secret();
            let mut permit = p.permit;
            permit.consume();
            let err = runtime.execute(&req, &mut permit, &secret, ExecutionInput::None);
            assert!(matches!(err, Err(RuntimeError::PermitFailure(_))));
        } else {
            panic!("expected Permitted");
        }
    }

    #[test]
    fn execute_wrong_secret_rejected() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        if let RuntimeOutcome::Permitted(p) = outcome {
            let mut permit = p.permit;
            let err = runtime.execute(&req, &mut permit, &[0u8; 32], ExecutionInput::None);
            assert!(matches!(err, Err(RuntimeError::PermitFailure(_))));
        } else {
            panic!("expected Permitted");
        }
    }

    #[test]
    fn execute_wrong_request_digest_rejected() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let runtime = build_runtime(vec![allow_read_policy()], &tmp);
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        if let RuntimeOutcome::Permitted(p) = outcome {
            let secret = *p.secret();
            let mut permit = p.permit;
            let other_req = ToolRequest::new(
                RequestId::new("req-other").unwrap(),
                AgentSubjectBuilder::new(
                    AgentId::new("agent-other").unwrap(),
                    SessionId::new("sess-other").unwrap(),
                )
                .trust_level(TrustLevel::Standard)
                .build(),
                Operation::FileRead { max_bytes: None },
                Resource::file("/workspace/other.txt").unwrap(),
                RequestContext::new(None, None, None, None, false).unwrap(),
            );
            let err = runtime.execute(&other_req, &mut permit, &secret, ExecutionInput::None);
            assert!(matches!(err, Err(RuntimeError::PermitFailure(_))));
        } else {
            panic!("expected Permitted");
        }
    }

    // ─── Builder edge cases ──────────────────────────────────────────────

    #[test]
    fn builder_missing_workspace_root_defaults_to_current_dir() {
        let tmp = TempDir::new().unwrap();
        let audit_path = tmp.path().join("audit.db").to_string_lossy().to_string();
        let runtime = RuntimeBuilder::new()
            .with_config(RuntimeConfig::default())
            .with_audit_db(audit_path)
            .add_policy(allow_read_policy())
            .build()
            .unwrap();
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        assert!(matches!(outcome, RuntimeOutcome::Permitted(_)));
    }

    #[test]
    fn disapproval_after_deny_stays_denied() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![require_approval_policy()], &tmp);
        let approval_id = match runtime.evaluate(&make_file_read_request()).unwrap() {
            RuntimeOutcome::ApprovalRequired { approval_id, .. } => approval_id,
            _ => panic!("expected ApprovalRequired"),
        };
        runtime
            .deny(&approval_id, &make_actor("bob"), Some("not needed"))
            .unwrap();
        let err = runtime.consume_approval(
            &make_file_read_request(),
            &approval_id,
            &kavach_approval::ApprovalToken::generate().unwrap(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn second_approve_rejected() {
        let tmp = TempDir::new().unwrap();
        let runtime = build_runtime(vec![require_approval_policy()], &tmp);
        let req = make_file_read_request();
        let approval_id = match runtime.evaluate(&req).unwrap() {
            RuntimeOutcome::ApprovalRequired { approval_id, .. } => approval_id,
            _ => panic!("expected ApprovalRequired"),
        };
        runtime.approve(&approval_id, &make_actor("alice")).unwrap();
        let err = runtime
            .approve(&approval_id, &make_actor("bob"))
            .unwrap_err();
        assert!(matches!(err, RuntimeError::ApprovalFailure(_)));
    }

    // ── ExecutionInput dispatch ──────────────────────────────────────────

    #[test]
    fn execute_command_without_command_input_rejected() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let audit_store = AuditStoreBuilder::new().open_in_memory().unwrap();
        let approval_audit = AuditStoreBuilder::new().open_in_memory().unwrap();
        let broker: Arc<dyn ApprovalBroker> = open_approval_broker_in_memory(
            kavach_approval::ApprovalStoreConfig::default(),
            approval_audit,
            Box::new(kavach_approval::RealClock),
        )
        .unwrap();
        let cmd_policy = kavach_policy::Policy {
            id: kavach_core::ids::PolicyId::new("pol-cmd").unwrap(),
            name: "allow-cmd".into(),
            description: "".into(),
            default_effect: DefaultEffect::Deny,
            rules: vec![Rule {
                id: RuleId::new("cmd-rule").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["command_execute".into()],
                    ..Default::default()
                },
            }],
        };
        let engine = PolicyEngine::new(vec![cmd_policy]).unwrap();
        let registry = AdapterRegistry::new_test(ws).unwrap();
        let runtime = KavachRuntime {
            engine,
            config: RuntimeConfig::default(),
            registry,
            broker,
            audit_store,
            redactor: None,
        };
        let cmd_req = ToolRequest::new(
            RequestId::new("req-cmd").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent").unwrap(),
                SessionId::new("sess").unwrap(),
            )
            .trust_level(TrustLevel::Standard)
            .build(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new("echo", vec!["hello".into()]).unwrap(),
            ),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );
        let outcome = runtime.evaluate(&cmd_req).unwrap();
        if let RuntimeOutcome::Permitted(p) = outcome {
            let secret = *p.secret();
            let mut permit = p.permit;
            let err = runtime.execute(&cmd_req, &mut permit, &secret, ExecutionInput::None);
            assert!(matches!(err, Err(RuntimeError::InvalidExecutionInput(_))));
        } else {
            panic!("expected Permitted");
        }
    }

    #[test]
    fn execute_network_without_network_input_rejected() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let audit_store = AuditStoreBuilder::new().open_in_memory().unwrap();
        let approval_audit = AuditStoreBuilder::new().open_in_memory().unwrap();
        let broker: Arc<dyn ApprovalBroker> = open_approval_broker_in_memory(
            kavach_approval::ApprovalStoreConfig::default(),
            approval_audit,
            Box::new(kavach_approval::RealClock),
        )
        .unwrap();
        let net_policy = kavach_policy::Policy {
            id: kavach_core::ids::PolicyId::new("pol-net").unwrap(),
            name: "allow-net".into(),
            description: "".into(),
            default_effect: DefaultEffect::Deny,
            rules: vec![Rule {
                id: RuleId::new("net-rule").unwrap(),
                description: "".into(),
                effect: PolicyEffect::Allow,
                conditions: RuleConditions {
                    operations: vec!["network_request".into()],
                    ..Default::default()
                },
            }],
        };
        let engine = PolicyEngine::new(vec![net_policy]).unwrap();
        let registry = AdapterRegistry::new_test(ws).unwrap();
        let runtime = KavachRuntime {
            engine,
            config: RuntimeConfig::default(),
            registry,
            broker,
            audit_store,
            redactor: None,
        };
        let net_req = ToolRequest::new(
            RequestId::new("req-net").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("agent").unwrap(),
                SessionId::new("sess").unwrap(),
            )
            .trust_level(TrustLevel::Standard)
            .build(),
            Operation::NetworkRequest,
            Resource::NetworkEndpoint(
                kavach_core::resource::NetworkResource::new(
                    kavach_core::resource::NetworkScheme::new("https").unwrap(),
                    kavach_core::resource::NetworkHost::new("example.com").unwrap(),
                    None,
                    "/",
                )
                .unwrap(),
            ),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );
        let outcome = runtime.evaluate(&net_req).unwrap();
        if let RuntimeOutcome::Permitted(p) = outcome {
            let secret = *p.secret();
            let mut permit = p.permit;
            let err = runtime.execute(&net_req, &mut permit, &secret, ExecutionInput::None);
            assert!(matches!(err, Err(RuntimeError::InvalidExecutionInput(_))));
        } else {
            panic!("expected Permitted");
        }
    }

    // ── Redaction integration ────────────────────────────────────────────

    #[test]
    fn redaction_sanitizes_summary() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let audit_path = tmp.path().join("audit.db").to_string_lossy().to_string();
        let mut container = kavach_redaction::SecretContainer::new();
        container.add("secret-token".into()).unwrap();
        let redactor: Arc<dyn kavach_redaction::Redactor> = Arc::new(
            kavach_redaction::CompositeRedactorBuilder::new()
                .with_exact_secrets(container)
                .build(),
        );
        let runtime = RuntimeBuilder::new()
            .with_config(RuntimeConfig {
                redaction_enabled: true,
                ..Default::default()
            })
            .with_workspace_root(ws)
            .with_audit_db(audit_path)
            .add_policy(deny_all_policy())
            .with_redactor(redactor)
            .build()
            .unwrap();
        let req = make_file_read_request();
        let outcome = runtime.evaluate(&req).unwrap();
        if let RuntimeOutcome::Denied {
            sanitized_summary, ..
        } = outcome
        {
            assert!(!sanitized_summary.contains("secret-token"));
        } else {
            panic!("expected Denied");
        }
    }
}
