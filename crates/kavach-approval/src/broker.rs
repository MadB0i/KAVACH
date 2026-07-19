use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kavach_audit::AuditEventCategory;
use kavach_audit::AuditStore;
use kavach_audit::event::AuditAppendInput;
use kavach_core::compute_request_digest;
use kavach_core::ids::ApprovalId;

use crate::clock::Clock;
use crate::error::ApprovalError;
use crate::store::SqliteApprovalStore;
use crate::token::ApprovalToken;
use crate::types::{
    ApprovalActor, ApprovalRecord, ApprovalRequest, ApprovalRow, ApprovalState,
    ApprovalStoreConfig, ConsumedApproval, DEFAULT_APPROVAL_TTL_SECONDS,
    MAX_APPROVAL_SUMMARY_LENGTH, MAX_APPROVAL_TTL_SECONDS, MAX_PENDING_APPROVALS, PendingApproval,
};

const DEFAULT_PAGE_SIZE: u64 = 100;

/// Trait for the human approval broker.
///
/// All methods take `&self` and are safe to call concurrently. The SQLite
/// backend serialises writes via `BEGIN IMMEDIATE`. The audit store and
/// approval store are *separate* SQLite databases — there is no cross-
/// database atomicity.
pub trait ApprovalBroker: Send + Sync {
    /// Requests a new approval for the given tool request.
    fn request_approval(
        &self,
        request: &ApprovalRequest,
        ttl_seconds: Option<u64>,
    ) -> Result<PendingApproval, ApprovalError>;

    /// Lists current pending approvals.
    fn list_pending(&self, limit: Option<u64>) -> Result<Vec<ApprovalRecord>, ApprovalError>;

    /// Approves a pending approval, returning the token needed for consumption.
    fn approve(
        &self,
        approval_id: &ApprovalId,
        actor: &ApprovalActor,
    ) -> Result<ApprovalToken, ApprovalError>;

    /// Denies a pending approval.
    fn deny(
        &self,
        approval_id: &ApprovalId,
        actor: &ApprovalActor,
        reason: Option<&str>,
    ) -> Result<(), ApprovalError>;

    /// Cancels a pending approval.
    fn cancel(&self, approval_id: &ApprovalId) -> Result<(), ApprovalError>;

    /// Consumes an approved approval by verifying the token and executing the operation.
    fn consume(
        &self,
        approval_id: &ApprovalId,
        token: &ApprovalToken,
    ) -> Result<ConsumedApproval, ApprovalError>;

    /// Expires overdue approvals.
    fn expire_overdue(&self) -> Result<Vec<String>, ApprovalError>;

    /// Lists approvals after a given audit sequence (for restart reconciliation).
    fn list_after_sequence(
        &self,
        after_sequence: u64,
        limit: Option<u64>,
    ) -> Result<Vec<ApprovalRecord>, ApprovalError>;

    /// Returns a single approval record by ID, regardless of state.
    fn get_approval(&self, approval_id: &ApprovalId) -> Result<ApprovalRecord, ApprovalError>;
}

/// SQLite-backed implementation of [`ApprovalBroker`].
pub struct SqliteApprovalBroker<S> {
    store: S,
    audit_store: AuditStore,
    clock: Box<dyn Clock>,
    transition_lock: Mutex<()>,
}

impl SqliteApprovalBroker<SqliteApprovalStore> {
    /// Creates a new broker with the given store, audit store, and clock.
    pub fn new(store: SqliteApprovalStore, audit_store: AuditStore, clock: Box<dyn Clock>) -> Self {
        Self {
            store,
            audit_store,
            clock,
            transition_lock: Mutex::new(()),
        }
    }

    /// Opens or creates the approval database at the given path.
    pub fn open(
        db_path: &str,
        config: ApprovalStoreConfig,
        audit_store: AuditStore,
        clock: Box<dyn Clock>,
    ) -> Result<Self, ApprovalError> {
        let store = SqliteApprovalStore::open(db_path, config)?;
        Ok(Self::new(store, audit_store, clock))
    }

    /// Opens an in-memory store (for testing).
    pub fn open_in_memory(
        config: ApprovalStoreConfig,
        audit_store: AuditStore,
        clock: Box<dyn Clock>,
    ) -> Result<Self, ApprovalError> {
        let store = SqliteApprovalStore::open_in_memory(config)?;
        Ok(Self::new(store, audit_store, clock))
    }

    #[allow(clippy::too_many_arguments)]
    fn append_audit_event(
        &self,
        category: AuditEventCategory,
        request_id: Option<&str>,
        operation: Option<&str>,
        resource_kind: Option<&str>,
        resource_summary: Option<&str>,
        decision: Option<&str>,
        reason_code: Option<&str>,
        matched_rule_ids: &[String],
        metadata: BTreeMap<String, String>,
    ) -> Result<u64, ApprovalError> {
        let input = AuditAppendInput {
            category,
            request_id: request_id.map(|s| s.to_string()),
            agent_id: Some("kavach-approval".to_string()),
            operation: operation.map(|s| s.to_string()),
            resource_kind: resource_kind.map(|s| s.to_string()),
            resource_summary: resource_summary.map(|s| s.to_string()),
            decision: decision.map(|s| s.to_string()),
            reason_code: reason_code.map(|s| s.to_string()),
            matched_rule_ids: matched_rule_ids.to_vec(),
            metadata,
        };
        let summary = self
            .audit_store
            .append(input)
            .map_err(|e| ApprovalError::audit_failure(e.to_string()))?;
        Ok(summary.sequence)
    }

    fn ensure_transitionable(
        &self,
        approval_id: &ApprovalId,
        expected_state: &str,
        target_state: &str,
    ) -> Result<ApprovalRow, ApprovalError> {
        let row = self
            .store
            .load(approval_id.as_str())?
            .ok_or_else(ApprovalError::not_found)?;
        if row.state != expected_state {
            return Err(ApprovalError::invalid_transition(&row.state, target_state));
        }

        let expires_at = row
            .expires_at
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map_err(|e| ApprovalError::database_corruption(e.to_string()))?;
        let now = self.clock.now();
        if now >= expires_at {
            let mut metadata = BTreeMap::new();
            metadata.insert("approval_id".into(), approval_id.to_string());
            let seq = self.append_audit_event(
                AuditEventCategory::ApprovalExpired,
                None,
                None,
                None,
                None,
                Some("expired"),
                None,
                &[],
                metadata,
            )?;
            self.store.expire_overdue(&now.to_rfc3339(), seq)?;
            return Err(ApprovalError::invalid_transition("expired", target_state));
        }
        Ok(row)
    }
}

impl ApprovalBroker for SqliteApprovalBroker<SqliteApprovalStore> {
    fn request_approval(
        &self,
        request: &ApprovalRequest,
        ttl_seconds: Option<u64>,
    ) -> Result<PendingApproval, ApprovalError> {
        let now = self.clock.now();

        let ttl = ttl_seconds
            .unwrap_or(DEFAULT_APPROVAL_TTL_SECONDS)
            .min(MAX_APPROVAL_TTL_SECONDS);

        let summary = &request.summary;
        if summary.len() > MAX_APPROVAL_SUMMARY_LENGTH {
            return Err(ApprovalError::summary_too_large(summary.len()));
        }

        let request_digest = compute_request_digest(&request.request);

        let active_count = self.store.count_active_for_digest(&request_digest)?;
        if active_count > 0 {
            return Err(ApprovalError::duplicate_active());
        }

        let pending_count = self.store.count_pending()?;
        if pending_count >= MAX_PENDING_APPROVALS as u64 {
            return Err(ApprovalError::pending_limit());
        }

        let expires_at = now + chrono::Duration::seconds(ttl as i64);
        let mut rule_ids = request.matched_rule_ids.clone();
        rule_ids.sort();
        rule_ids.dedup();

        let approval_id = ApprovalId::new(uuid::Uuid::new_v4().to_string())
            .map_err(|e| ApprovalError::invalid_request(e.to_string()))?;

        let pending = PendingApproval {
            approval_id: approval_id.clone(),
            request_id: request.request.request_id.to_string(),
            request_digest,
            summary: summary.clone(),
            operation: request.request.operation.to_string(),
            resource_kind: request.request.resource.kind().to_string(),
            matched_rule_ids: rule_ids.clone(),
            created_at: now,
            expires_at,
            state: ApprovalState::Pending,
        };

        self.store.insert_pending(&pending)?;

        let mut metadata = BTreeMap::new();
        metadata.insert("approval_id".into(), approval_id.to_string());
        metadata.insert("request_id".into(), request.request.request_id.to_string());
        let seq = self.append_audit_event(
            AuditEventCategory::ApprovalRequested,
            Some(&request.request.request_id.to_string()),
            Some(&request.request.operation.to_string()),
            Some(&request.request.resource.kind().to_string()),
            Some(summary),
            Some("pending"),
            None,
            &rule_ids,
            metadata,
        )?;
        self.store
            .update_audit_sequence(pending.approval_id.as_str(), seq)?;

        Ok(pending)
    }

    fn list_pending(&self, limit: Option<u64>) -> Result<Vec<ApprovalRecord>, ApprovalError> {
        let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE);
        let rows = self.store.list_pending(limit)?;
        Ok(rows.into_iter().map(crate::store::row_to_record).collect())
    }

    fn approve(
        &self,
        approval_id: &ApprovalId,
        actor: &ApprovalActor,
    ) -> Result<ApprovalToken, ApprovalError> {
        let _transition = self
            .transition_lock
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let row = self.ensure_transitionable(approval_id, "pending", "approved")?;
        let matched_rule_ids = split_rule_ids(&row.matched_rule_ids);

        let token = ApprovalToken::generate()?;
        let token_hash = token.hash();
        let decision_at = self.clock.now().to_rfc3339();

        let mut metadata = BTreeMap::new();
        metadata.insert("approval_id".into(), approval_id.to_string());
        metadata.insert("actor".into(), actor.to_string());
        let seq = self.append_audit_event(
            AuditEventCategory::ApprovalApproved,
            Some(&row.request_id),
            Some(&row.operation),
            Some(&row.resource_kind),
            Some(&row.summary),
            Some("approved"),
            None,
            &matched_rule_ids,
            metadata,
        )?;

        self.store.transition_to_approved(
            approval_id.as_str(),
            &token_hash,
            actor.as_str(),
            &decision_at,
            seq,
            &*self.clock,
        )?;

        Ok(token)
    }

    fn deny(
        &self,
        approval_id: &ApprovalId,
        actor: &ApprovalActor,
        reason: Option<&str>,
    ) -> Result<(), ApprovalError> {
        let _transition = self
            .transition_lock
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let row = self.ensure_transitionable(approval_id, "pending", "denied")?;
        let matched_rule_ids = split_rule_ids(&row.matched_rule_ids);

        let decision_at = self.clock.now().to_rfc3339();

        let mut metadata = BTreeMap::new();
        metadata.insert("approval_id".into(), approval_id.to_string());
        metadata.insert("actor".into(), actor.to_string());
        if let Some(r) = reason {
            metadata.insert("reason".into(), r.to_string());
        }
        let seq = self.append_audit_event(
            AuditEventCategory::ApprovalDenied,
            Some(&row.request_id),
            Some(&row.operation),
            Some(&row.resource_kind),
            Some(&row.summary),
            Some("denied"),
            reason,
            &matched_rule_ids,
            metadata,
        )?;

        self.store.transition_to_denied(
            approval_id.as_str(),
            actor.as_str(),
            reason,
            &decision_at,
            seq,
        )
    }

    fn cancel(&self, approval_id: &ApprovalId) -> Result<(), ApprovalError> {
        let _transition = self
            .transition_lock
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let row = self.ensure_transitionable(approval_id, "pending", "cancelled")?;
        let matched_rule_ids = split_rule_ids(&row.matched_rule_ids);

        let decision_at = self.clock.now().to_rfc3339();

        let mut metadata = BTreeMap::new();
        metadata.insert("approval_id".into(), approval_id.to_string());
        let seq = self.append_audit_event(
            AuditEventCategory::DecisionDeny,
            Some(&row.request_id),
            Some(&row.operation),
            Some(&row.resource_kind),
            Some(&row.summary),
            Some("cancelled"),
            Some("cancelled"),
            &matched_rule_ids,
            metadata,
        )?;

        self.store
            .transition_to_cancelled(approval_id.as_str(), &decision_at, seq)
    }

    fn consume(
        &self,
        approval_id: &ApprovalId,
        token: &ApprovalToken,
    ) -> Result<ConsumedApproval, ApprovalError> {
        let _transition = self
            .transition_lock
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let row = self.ensure_transitionable(approval_id, "approved", "consumed")?;
        let matched_rule_ids = split_rule_ids(&row.matched_rule_ids);

        let stored_hash_hex = row
            .token_hash
            .as_ref()
            .ok_or_else(ApprovalError::invalid_token)?;

        let stored_hash =
            hex::decode(stored_hash_hex).map_err(|_| ApprovalError::invalid_token())?;

        if !token.verify_hash(&stored_hash) {
            return Err(ApprovalError::invalid_token());
        }

        let consumed_at = self.clock.now().to_rfc3339();

        let mut metadata = BTreeMap::new();
        metadata.insert("approval_id".into(), approval_id.to_string());
        let seq = self.append_audit_event(
            AuditEventCategory::ApprovalConsumed,
            Some(&row.request_id),
            Some(&row.operation),
            Some(&row.resource_kind),
            Some(&row.summary),
            Some("consumed"),
            None,
            &matched_rule_ids,
            metadata,
        )?;

        self.store
            .consume(approval_id.as_str(), &consumed_at, seq, &*self.clock)?;

        // Decode the stored digest for cross-crate verification.
        let digest_bytes =
            hex::decode(&row.request_digest_hex).map_err(|_| ApprovalError::invalid_token())?;
        let mut request_digest = [0u8; 32];
        if digest_bytes.len() == 32 {
            request_digest.copy_from_slice(&digest_bytes);
        }

        let matched_rule_ids: Vec<String> = if row.matched_rule_ids.is_empty() {
            vec![]
        } else {
            row.matched_rule_ids
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        };

        let consumed_at_dt = self.clock.now();
        Ok(ConsumedApproval {
            approval_id: approval_id.clone(),
            request_digest,
            matched_rule_ids,
            consumed_at: consumed_at_dt,
            audit_sequence: Some(seq),
        })
    }

    fn expire_overdue(&self) -> Result<Vec<String>, ApprovalError> {
        let _transition = self
            .transition_lock
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let now = self.clock.now().to_rfc3339();
        if !self.store.has_overdue(&now)? {
            return Ok(Vec::new());
        }
        let metadata = BTreeMap::new();
        let seq = self.append_audit_event(
            AuditEventCategory::ApprovalExpired,
            None,
            None,
            None,
            None,
            Some("expired"),
            None,
            &[],
            metadata,
        )?;
        self.store.expire_overdue(&now, seq)
    }

    fn list_after_sequence(
        &self,
        after_sequence: u64,
        limit: Option<u64>,
    ) -> Result<Vec<ApprovalRecord>, ApprovalError> {
        let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE);
        let rows = self.store.list_after_sequence(after_sequence, limit)?;
        Ok(rows.into_iter().map(crate::store::row_to_record).collect())
    }

    fn get_approval(&self, approval_id: &ApprovalId) -> Result<ApprovalRecord, ApprovalError> {
        let row = self
            .store
            .load(approval_id.as_str())?
            .ok_or_else(ApprovalError::not_found)?;
        Ok(crate::store::row_to_record(row))
    }
}

fn split_rule_ids(value: &str) -> Vec<String> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split(',').map(|id| id.trim().to_string()).collect()
    }
}

// ── Standalone factory functions ──────────────────────────────────────────

/// Opens or creates the approval database and returns an `Arc<dyn ApprovalBroker>`.
pub fn open_approval_broker(
    db_path: &str,
    config: ApprovalStoreConfig,
    audit_store: AuditStore,
    clock: Box<dyn Clock>,
) -> Result<Arc<dyn ApprovalBroker>, ApprovalError> {
    Ok(Arc::new(SqliteApprovalBroker::open(
        db_path,
        config,
        audit_store,
        clock,
    )?))
}

/// Opens an in-memory approval store and returns an `Arc<dyn ApprovalBroker>`.
pub fn open_approval_broker_in_memory(
    config: ApprovalStoreConfig,
    audit_store: AuditStore,
    clock: Box<dyn Clock>,
) -> Result<Arc<dyn ApprovalBroker>, ApprovalError> {
    Ok(Arc::new(SqliteApprovalBroker::open_in_memory(
        config,
        audit_store,
        clock,
    )?))
}
