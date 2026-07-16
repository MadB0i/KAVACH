use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

use crate::clock::Clock;
use crate::error::{ApprovalError, ApprovalErrorKind};
use crate::types::{
    ApprovalActor, ApprovalRecord, ApprovalRow, ApprovalState, ApprovalStoreConfig,
    MAX_QUERY_LIMIT, PendingApproval,
};

const CURRENT_SCHEMA_VERSION: u64 = 1;

/// SQLite-backed persistent approval store.
pub(crate) struct SqliteApprovalStore {
    conn: Mutex<Connection>,
    #[allow(dead_code)]
    config: ApprovalStoreConfig,
}

impl SqliteApprovalStore {
    /// Opens or creates the approval database at the given path.
    pub fn open(path: &str, config: ApprovalStoreConfig) -> Result<Self, ApprovalError> {
        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(|e| ApprovalError::database_open(e.to_string()))?;

        Self::configure_connection(&mut conn)?;
        Self::run_migrations(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            config,
        })
    }

    /// Opens an in-memory database (for testing).
    pub fn open_in_memory(config: ApprovalStoreConfig) -> Result<Self, ApprovalError> {
        let mut conn = Connection::open_in_memory()
            .map_err(|e| ApprovalError::database_open(e.to_string()))?;

        Self::configure_connection(&mut conn)?;
        Self::run_migrations(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            config,
        })
    }

    fn configure_connection(conn: &mut Connection) -> Result<(), ApprovalError> {
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| ApprovalError::database_open(e.to_string()))?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(|e| ApprovalError::database_open(e.to_string()))?;
        conn.execute_batch("PRAGMA busy_timeout=5000;")
            .map_err(|e| ApprovalError::database_open(e.to_string()))?;
        Ok(())
    }

    fn run_migrations(conn: &Connection) -> Result<(), ApprovalError> {
        let version: u64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if version > CURRENT_SCHEMA_VERSION {
            return Err(ApprovalError::migration_failure(format!(
                "unsupported schema version: {version}"
            )));
        }

        if version < 1 {
            conn.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY NOT NULL,
                    request_id TEXT NOT NULL,
                    request_digest_hex TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    resource_kind TEXT NOT NULL,
                    matched_rule_ids TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    token_hash TEXT,
                    actor_id TEXT,
                    denial_reason TEXT,
                    decision_at TEXT,
                    consumed_at TEXT,
                    audit_sequence INTEGER
                );

                CREATE INDEX idx_approvals_state ON approvals(state);
                CREATE INDEX idx_approvals_request_id ON approvals(request_id);
                CREATE INDEX idx_approvals_digest ON approvals(request_digest_hex);
                CREATE INDEX idx_approvals_expires_at ON approvals(expires_at);

                INSERT INTO schema_version (version, applied_at) VALUES (1, datetime('now'));
                ",
            )
            .map_err(|e| ApprovalError::migration_failure(e.to_string()))?;
        }

        Ok(())
    }

    /// Inserts a new pending approval row.
    pub fn insert_pending(&self, pending: &PendingApproval) -> Result<(), ApprovalError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        let digest_hex = hex::encode(pending.request_digest);
        let rule_ids_json = serde_json::to_string(&pending.matched_rule_ids)
            .map_err(|e| ApprovalError::database_corruption(e.to_string()))?;

        conn.execute(
            "INSERT INTO approvals (approval_id, request_id, request_digest_hex, summary, \
             operation, resource_kind, matched_rule_ids, created_at, expires_at, state) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending')",
            params![
                pending.approval_id.as_str(),
                pending.request_id,
                digest_hex,
                pending.summary,
                pending.operation,
                pending.resource_kind,
                rule_ids_json,
                pending.created_at.to_rfc3339(),
                pending.expires_at.to_rfc3339(),
            ],
        )
        .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        Ok(())
    }

    /// Counts active (pending + approved) approvals for a given request digest.
    pub fn count_active_for_digest(&self, digest: &[u8; 32]) -> Result<u64, ApprovalError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let digest_hex = hex::encode(digest);
        let count: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE request_digest_hex = ?1 AND state IN ('pending', 'approved')",
                params![digest_hex],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(count)
    }

    /// Counts pending approvals.
    pub fn count_pending(&self) -> Result<u64, ApprovalError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let count: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE state = 'pending'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(count)
    }

    /// Loads an approval row by ID.
    pub fn load(&self, approval_id: &str) -> Result<Option<ApprovalRow>, ApprovalError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT approval_id, request_id, request_digest_hex, summary, operation, \
                 resource_kind, matched_rule_ids, created_at, expires_at, state, token_hash, \
                 actor_id, denial_reason, decision_at, consumed_at, audit_sequence \
                 FROM approvals WHERE approval_id = ?1",
            )
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        let result = stmt
            .query_row(params![approval_id], |row| {
                Ok(ApprovalRow {
                    approval_id: row.get(0)?,
                    request_id: row.get(1)?,
                    request_digest_hex: row.get(2)?,
                    summary: row.get(3)?,
                    operation: row.get(4)?,
                    resource_kind: row.get(5)?,
                    matched_rule_ids: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    state: row.get(9)?,
                    token_hash: row.get(10)?,
                    actor_id: row.get(11)?,
                    denial_reason: row.get(12)?,
                    decision_at: row.get(13)?,
                    consumed_at: row.get(14)?,
                    audit_sequence: row.get(15)?,
                })
            })
            .ok();

        Ok(result)
    }

    /// Atomically transitions a Pending approval to Approved and stores the token hash.
    pub fn transition_to_approved(
        &self,
        approval_id: &str,
        token_hash: &[u8],
        actor_id: &str,
        decision_at: &str,
        audit_seq: u64,
        clock: &dyn Clock,
    ) -> Result<(), ApprovalError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        // Verify it is still Pending and not expired.
        let row: Result<(String, String), _> = tx.query_row(
            "SELECT state, expires_at FROM approvals WHERE approval_id = ?1",
            params![approval_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );

        match row {
            Ok((state, expires_at)) => {
                if state != "pending" {
                    return Err(ApprovalError::invalid_transition(&state, "approved"));
                }
                let expires: DateTime<Utc> = expires_at.parse().map_err(|e| {
                    ApprovalError::database_corruption(format!("invalid expires_at: {e}"))
                })?;
                if clock.now() >= expires {
                    // Mark as expired and reject.
                    tx.execute(
                        "UPDATE approvals SET state = 'expired', decision_at = ?1 WHERE approval_id = ?2",
                        params![decision_at, approval_id],
                    )
                    .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
                    tx.commit()
                        .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
                    return Err(ApprovalError::invalid_transition("pending", "approved"));
                }
            }
            Err(_) => return Err(ApprovalError::not_found()),
        }

        let token_hex = hex::encode(token_hash);
        tx.execute(
            "UPDATE approvals SET state = 'approved', token_hash = ?1, actor_id = ?2, \
             decision_at = ?3, audit_sequence = ?4 WHERE approval_id = ?5",
            params![token_hex, actor_id, decision_at, audit_seq, approval_id],
        )
        .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        tx.commit()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        Ok(())
    }

    /// Transitions a Pending approval to Denied.
    pub fn transition_to_denied(
        &self,
        approval_id: &str,
        actor_id: &str,
        denial_reason: Option<&str>,
        decision_at: &str,
        audit_seq: u64,
    ) -> Result<(), ApprovalError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        let state: Result<String, _> = tx.query_row(
            "SELECT state FROM approvals WHERE approval_id = ?1",
            params![approval_id],
            |row| row.get(0),
        );

        match state {
            Ok(s) if s == "pending" => {}
            Ok(s) => return Err(ApprovalError::invalid_transition(&s, "denied")),
            Err(_) => return Err(ApprovalError::not_found()),
        }

        tx.execute(
            "UPDATE approvals SET state = 'denied', actor_id = ?1, denial_reason = ?2, \
             decision_at = ?3, audit_sequence = ?4 WHERE approval_id = ?5",
            params![actor_id, denial_reason, decision_at, audit_seq, approval_id],
        )
        .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        tx.commit()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        Ok(())
    }

    /// Transitions a Pending approval to Cancelled.
    pub fn transition_to_cancelled(
        &self,
        approval_id: &str,
        decision_at: &str,
        audit_seq: u64,
    ) -> Result<(), ApprovalError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        let state: Result<String, _> = tx.query_row(
            "SELECT state FROM approvals WHERE approval_id = ?1",
            params![approval_id],
            |row| row.get(0),
        );

        match state {
            Ok(s) if s == "pending" => {}
            Ok(s) => return Err(ApprovalError::invalid_transition(&s, "cancelled")),
            Err(_) => return Err(ApprovalError::not_found()),
        }

        tx.execute(
            "UPDATE approvals SET state = 'cancelled', decision_at = ?1, audit_sequence = ?2 \
             WHERE approval_id = ?3",
            params![decision_at, audit_seq, approval_id],
        )
        .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        tx.commit()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        Ok(())
    }

    /// Expires overdue Pending or Approved approvals and returns the IDs that were expired.
    pub fn expire_overdue(&self, now: &str, audit_seq: u64) -> Result<Vec<String>, ApprovalError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        // Find overdue approvals that haven't been expired yet.
        let ids: Vec<String> = {
            let mut stmt = tx
                .prepare(
                    "SELECT approval_id FROM approvals WHERE state IN ('pending', 'approved') \
                     AND expires_at < ?1",
                )
                .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

            stmt.query_map(params![now], |row| row.get(0))
                .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?
                .filter_map(|r| r.ok())
                .collect()
        };

        if !ids.is_empty() {
            tx.execute(
                "UPDATE approvals SET state = 'expired', decision_at = ?1, audit_sequence = ?2 \
                 WHERE state IN ('pending', 'approved') AND expires_at < ?3",
                params![now, audit_seq, now],
            )
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        Ok(ids)
    }

    /// Transitions an Approved approval to Consumed.
    pub fn consume(
        &self,
        approval_id: &str,
        consumed_at: &str,
        audit_seq: u64,
        clock: &dyn Clock,
    ) -> Result<(), ApprovalError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        let row: Result<(String, String), _> = tx.query_row(
            "SELECT state, expires_at FROM approvals WHERE approval_id = ?1",
            params![approval_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );

        match row {
            Ok((state, expires_at)) => {
                if state != "approved" {
                    return Err(ApprovalError::invalid_transition(&state, "consumed"));
                }
                let expires: DateTime<Utc> = expires_at.parse().map_err(|e| {
                    ApprovalError::database_corruption(format!("invalid expires_at: {e}"))
                })?;
                if clock.now() >= expires {
                    tx.execute(
                        "UPDATE approvals SET state = 'expired', decision_at = ?1 WHERE approval_id = ?2",
                        params![consumed_at, approval_id],
                    )
                    .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
                    tx.commit()
                        .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
                    return Err(ApprovalError::invalid_transition("approved", "consumed"));
                }
            }
            Err(_) => return Err(ApprovalError::not_found()),
        }

        tx.execute(
            "UPDATE approvals SET state = 'consumed', consumed_at = ?1, token_hash = NULL, \
             audit_sequence = ?2 WHERE approval_id = ?3",
            params![consumed_at, audit_seq, approval_id],
        )
        .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        tx.commit()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        Ok(())
    }

    /// Lists pending approvals, ordered by creation time.
    pub fn list_pending(&self, limit: u64) -> Result<Vec<ApprovalRow>, ApprovalError> {
        if limit > MAX_QUERY_LIMIT {
            return Err(ApprovalError {
                kind: ApprovalErrorKind::QueryLimitExceeded,
            });
        }
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT approval_id, request_id, request_digest_hex, summary, operation, \
                 resource_kind, matched_rule_ids, created_at, expires_at, state, token_hash, \
                 actor_id, denial_reason, decision_at, consumed_at, audit_sequence \
                 FROM approvals WHERE state = 'pending' ORDER BY created_at ASC LIMIT ?1",
            )
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(ApprovalRow {
                    approval_id: row.get(0)?,
                    request_id: row.get(1)?,
                    request_digest_hex: row.get(2)?,
                    summary: row.get(3)?,
                    operation: row.get(4)?,
                    resource_kind: row.get(5)?,
                    matched_rule_ids: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    state: row.get(9)?,
                    token_hash: row.get(10)?,
                    actor_id: row.get(11)?,
                    denial_reason: row.get(12)?,
                    decision_at: row.get(13)?,
                    consumed_at: row.get(14)?,
                    audit_sequence: row.get(15)?,
                })
            })
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rows)
    }

    /// Lists approvals after a given sequence number.
    pub fn list_after_sequence(
        &self,
        after_sequence: u64,
        limit: u64,
    ) -> Result<Vec<ApprovalRow>, ApprovalError> {
        if limit > MAX_QUERY_LIMIT {
            return Err(ApprovalError {
                kind: ApprovalErrorKind::QueryLimitExceeded,
            });
        }
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT approval_id, request_id, request_digest_hex, summary, operation, \
                 resource_kind, matched_rule_ids, created_at, expires_at, state, token_hash, \
                 actor_id, denial_reason, decision_at, consumed_at, audit_sequence \
                 FROM approvals WHERE COALESCE(audit_sequence, 0) > ?1 \
                 ORDER BY created_at ASC LIMIT ?2",
            )
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;

        let rows = stmt
            .query_map(params![after_sequence, limit], |row| {
                Ok(ApprovalRow {
                    approval_id: row.get(0)?,
                    request_id: row.get(1)?,
                    request_digest_hex: row.get(2)?,
                    summary: row.get(3)?,
                    operation: row.get(4)?,
                    resource_kind: row.get(5)?,
                    matched_rule_ids: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    state: row.get(9)?,
                    token_hash: row.get(10)?,
                    actor_id: row.get(11)?,
                    denial_reason: row.get(12)?,
                    decision_at: row.get(13)?,
                    consumed_at: row.get(14)?,
                    audit_sequence: row.get(15)?,
                })
            })
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rows)
    }

    /// Updates the audit sequence for a given approval (used when audit append is deferred).
    pub fn update_audit_sequence(
        &self,
        approval_id: &str,
        audit_seq: u64,
    ) -> Result<(), ApprovalError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        conn.execute(
            "UPDATE approvals SET audit_sequence = ?1 WHERE approval_id = ?2",
            params![audit_seq, approval_id],
        )
        .map_err(|e| ApprovalError::transaction_failure(e.to_string()))?;
        Ok(())
    }
}

fn parse_state(s: &str) -> ApprovalState {
    match s {
        "pending" => ApprovalState::Pending,
        "approved" => ApprovalState::Approved,
        "denied" => ApprovalState::Denied,
        "expired" => ApprovalState::Expired,
        "consumed" => ApprovalState::Consumed,
        "cancelled" => ApprovalState::Cancelled,
        _ => ApprovalState::Pending,
    }
}

pub(crate) fn row_to_record(row: ApprovalRow) -> ApprovalRecord {
    let digest_bytes = hex::decode(&row.request_digest_hex).unwrap_or_default();
    let mut digest = [0u8; 32];
    if digest_bytes.len() == 32 {
        digest.copy_from_slice(&digest_bytes);
    }

    let rule_ids: Vec<String> = serde_json::from_str(&row.matched_rule_ids).unwrap_or_default();
    let created = row.created_at.parse().unwrap_or_else(|_| Utc::now());
    let expires = row.expires_at.parse().unwrap_or_else(|_| Utc::now());

    // Use a guaranteed-valid fallback ID when stored data is corrupted.
    fn fallback_approval_id() -> kavach_core::ids::ApprovalId {
        match kavach_core::ids::ApprovalId::new("unknown") {
            Ok(id) => id,
            Err(_) => {
                panic!("'unknown' is always a valid approval id")
            }
        }
    }

    ApprovalRecord {
        approval_id: kavach_core::ids::ApprovalId::new(&row.approval_id)
            .unwrap_or_else(|_| fallback_approval_id()),
        request_id: row.request_id,
        request_digest: digest,
        summary: row.summary,
        operation: row.operation,
        resource_kind: row.resource_kind,
        matched_rule_ids: rule_ids,
        created_at: created,
        expires_at: expires,
        state: parse_state(&row.state),
        actor: row.actor_id.and_then(|id| ApprovalActor::new(id).ok()),
        denial_reason: row.denial_reason,
        decision_at: row
            .decision_at
            .and_then(|s| s.parse::<DateTime<Utc>>().ok()),
        consumed_at: row
            .consumed_at
            .and_then(|s| s.parse::<DateTime<Utc>>().ok()),
        audit_sequence: row.audit_sequence,
    }
}
