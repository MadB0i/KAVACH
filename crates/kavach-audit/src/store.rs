use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use uuid::Uuid;

use crate::canonical::encode_canonical;
use crate::error::AuditError;
use crate::event::{
    AuditAppendInput, AuditEventCategory, AuditEventRecord, CanonicalEventFields,
    MAX_EVENT_QUERY_COUNT, MAX_VERIFICATION_RANGE, SCHEMA_VERSION,
};
use crate::hash::HashValue;
use crate::query::{ChainStatus, PersistedEventSummary};
use kavach_redaction::Redactor;

const CURRENT_SCHEMA_VERSION: u64 = 1;

/// Builder for an [`AuditStore`].
#[derive(Default)]
pub struct AuditStoreBuilder {
    redactor: Option<Arc<dyn Redactor>>,
    busy_timeout: u64,
}

impl AuditStoreBuilder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self {
            redactor: None,
            busy_timeout: 5000,
        }
    }

    /// Configures a secret redactor for the store.
    pub fn with_redactor(mut self, redactor: Arc<dyn Redactor>) -> Self {
        self.redactor = Some(redactor);
        self
    }

    /// Sets the SQLite busy timeout in milliseconds.
    pub fn with_busy_timeout(mut self, timeout_ms: u64) -> Self {
        self.busy_timeout = timeout_ms;
        self
    }

    /// Opens (or creates) the database at the given path.
    pub fn open(self, path: &str) -> Result<AuditStore, AuditError> {
        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(|e| AuditError::database_open(e.to_string()))?;

        configure_connection(&mut conn, self.busy_timeout)?;
        run_migrations(&conn)?;

        Ok(AuditStore {
            conn: std::sync::Mutex::new(conn),
            redactor: self.redactor,
        })
    }

    /// Opens an in-memory database (for testing).
    pub fn open_in_memory(self) -> Result<AuditStore, AuditError> {
        let mut conn =
            Connection::open_in_memory().map_err(|e| AuditError::database_open(e.to_string()))?;

        configure_connection(&mut conn, self.busy_timeout)?;
        run_migrations(&conn)?;

        Ok(AuditStore {
            conn: std::sync::Mutex::new(conn),
            redactor: self.redactor,
        })
    }
}

fn configure_connection(conn: &mut Connection, busy_timeout: u64) -> Result<(), AuditError> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(|e| AuditError::database_open(e.to_string()))?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .map_err(|e| AuditError::database_open(e.to_string()))?;
    conn.busy_timeout(std::time::Duration::from_millis(busy_timeout))
        .map_err(|e| AuditError::database_open(e.to_string()))?;
    Ok(())
}

fn run_migrations(conn: &Connection) -> Result<(), AuditError> {
    let version: u64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if version > CURRENT_SCHEMA_VERSION {
        return Err(AuditError::unsupported_schema_version(version));
    }

    if version < 1 {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                request_id TEXT,
                agent_id TEXT,
                operation TEXT,
                resource_kind TEXT,
                resource_summary TEXT,
                decision TEXT,
                reason_code TEXT,
                matched_rule_ids TEXT NOT NULL,
                metadata TEXT NOT NULL,
                previous_hash BLOB NOT NULL,
                current_hash BLOB NOT NULL
            );

            INSERT INTO schema_version (version, applied_at) VALUES (1, datetime('now'));
            ",
        )
        .map_err(|e| AuditError::migration_failure(e.to_string()))?;
    }

    Ok(())
}

/// Append-only, tamper-evident audit event store backed by SQLite.
pub struct AuditStore {
    conn: std::sync::Mutex<Connection>,
    redactor: Option<Arc<dyn Redactor>>,
}

impl AuditStore {
    /// Creates a new builder.
    pub fn builder() -> AuditStoreBuilder {
        AuditStoreBuilder::new()
    }

    /// Appends a new audit event.
    ///
    /// Validates input, applies redaction if a redactor is configured,
    /// allocates the next sequence number inside an immediate transaction,
    /// computes the hash chain, inserts the event, and commits.
    pub fn append(&self, input: AuditAppendInput) -> Result<PersistedEventSummary, AuditError> {
        input.validate()?;

        // Redact textual fields.
        let resource_summary = self.redact_opt(input.resource_summary)?;
        let metadata = self.redact_metadata(input.metadata)?;

        let mut conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        // Use IMMEDIATE transaction to prevent concurrent writers.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        // Read latest sequence and hash.
        let (latest_seq, latest_hash_bytes): (Option<u64>, Option<Vec<u8>>) = tx
            .query_row(
                "SELECT MAX(sequence), current_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or((None, None));

        let sequence = latest_seq.map(|s| s + 1).unwrap_or(1);
        let previous_hash = match latest_hash_bytes {
            Some(bytes) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    AuditError::database_corruption("invalid hash length in database")
                })?;
                HashValue::from_bytes(arr)
            }
            None => HashValue::genesis(),
        };

        let event_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let mut matched_rule_ids = input.matched_rule_ids.clone();
        matched_rule_ids.sort();
        matched_rule_ids.dedup();

        let canonical = encode_canonical(&CanonicalEventFields {
            schema_version: SCHEMA_VERSION,
            sequence,
            event_id: event_id.clone(),
            timestamp: timestamp.clone(),
            category: input.category.to_string(),
            request_id: input.request_id.clone(),
            agent_id: input.agent_id.clone(),
            operation: input.operation.clone(),
            resource_kind: input.resource_kind.clone(),
            resource_summary: resource_summary.clone(),
            decision: input.decision.clone(),
            reason_code: input.reason_code.clone(),
            matched_rule_ids: matched_rule_ids.clone(),
            metadata: metadata.clone(),
        });

        let current_hash = HashValue::compute(&previous_hash, &canonical);

        let matched_json = serde_json::to_string(&matched_rule_ids)
            .map_err(|e| AuditError::serialization_failure(e.to_string()))?;
        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| AuditError::serialization_failure(e.to_string()))?;

        tx.execute(
            "INSERT INTO audit_events (sequence, event_id, timestamp, category, \
             request_id, agent_id, operation, resource_kind, resource_summary, \
             decision, reason_code, matched_rule_ids, metadata, previous_hash, current_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                sequence,
                event_id,
                timestamp,
                input.category.to_string(),
                input.request_id,
                input.agent_id,
                input.operation,
                input.resource_kind,
                resource_summary,
                input.decision,
                input.reason_code,
                matched_json,
                metadata_json,
                previous_hash.as_bytes().as_slice(),
                current_hash.as_bytes().as_slice(),
            ],
        )
        .map_err(|e| AuditError::append_failure(e.to_string()))?;

        tx.commit()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        Ok(PersistedEventSummary {
            sequence,
            event_id,
            timestamp,
            category: input.category,
            previous_hash: previous_hash.to_string(),
            current_hash: current_hash.to_string(),
        })
    }

    /// Returns the latest event, if any.
    pub fn latest_event(&self) -> Result<Option<AuditEventRecord>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, event_id, timestamp, category, request_id, agent_id, \
                 operation, resource_kind, resource_summary, decision, reason_code, \
                 matched_rule_ids, metadata, previous_hash, current_hash \
                 FROM audit_events ORDER BY sequence DESC LIMIT 1",
            )
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        let result = stmt.query_row([], row_to_event).map(Some).unwrap_or(None);
        Ok(result)
    }

    /// Returns the event at the given sequence number.
    pub fn event_by_sequence(&self, sequence: u64) -> Result<Option<AuditEventRecord>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, event_id, timestamp, category, request_id, agent_id, \
                 operation, resource_kind, resource_summary, decision, reason_code, \
                 matched_rule_ids, metadata, previous_hash, current_hash \
                 FROM audit_events WHERE sequence = ?1",
            )
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        let result = stmt
            .query_row(params![sequence], row_to_event)
            .map(Some)
            .unwrap_or(None);
        Ok(result)
    }

    /// Returns events after the given sequence, up to `limit`.
    pub fn events_after_sequence(
        &self,
        after: u64,
        limit: u64,
    ) -> Result<Vec<AuditEventRecord>, AuditError> {
        let limit = limit.min(MAX_EVENT_QUERY_COUNT);
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, event_id, timestamp, category, request_id, agent_id, \
                 operation, resource_kind, resource_summary, decision, reason_code, \
                 matched_rule_ids, metadata, previous_hash, current_hash \
                 FROM audit_events WHERE sequence > ?1 ORDER BY sequence ASC LIMIT ?2",
            )
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        let rows = stmt
            .query_map(params![after, limit], row_to_event)
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Returns events matching the given request ID, up to `limit`.
    pub fn events_by_request_id(
        &self,
        request_id: &str,
        limit: u64,
    ) -> Result<Vec<AuditEventRecord>, AuditError> {
        let limit = limit.min(MAX_EVENT_QUERY_COUNT);
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, event_id, timestamp, category, request_id, agent_id, \
                 operation, resource_kind, resource_summary, decision, reason_code, \
                 matched_rule_ids, metadata, previous_hash, current_hash \
                 FROM audit_events WHERE request_id = ?1 ORDER BY sequence ASC LIMIT ?2",
            )
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        let rows = stmt
            .query_map(params![request_id, limit], row_to_event)
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Returns events matching the given category, up to `limit`.
    pub fn events_by_category(
        &self,
        category: AuditEventCategory,
        limit: u64,
    ) -> Result<Vec<AuditEventRecord>, AuditError> {
        let limit = limit.min(MAX_EVENT_QUERY_COUNT);
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, event_id, timestamp, category, request_id, agent_id, \
                 operation, resource_kind, resource_summary, decision, reason_code, \
                 matched_rule_ids, metadata, previous_hash, current_hash \
                 FROM audit_events WHERE category = ?1 ORDER BY sequence ASC LIMIT ?2",
            )
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        let rows = stmt
            .query_map(params![category.to_string(), limit], row_to_event)
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Returns the chain status (event count, latest hash, validity).
    pub fn chain_status(&self) -> Result<ChainStatus, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;
        let count: u64 = conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .unwrap_or(0);

        let latest = self.latest_event_inner(&conn)?;
        let genesis_hash = HashValue::genesis().to_string();

        Ok(ChainStatus {
            event_count: count,
            latest_sequence: latest.as_ref().map(|e| e.sequence),
            latest_hash: latest.map(|e| e.current_hash.to_string()),
            genesis_hash,
            is_valid: true,
        })
    }

    /// Returns the total event count.
    pub fn event_count(&self) -> Result<u64, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;
        conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .map_err(|e| AuditError::transaction_failure(e.to_string()))
    }

    fn latest_event_inner(
        &self,
        conn: &Connection,
    ) -> Result<Option<AuditEventRecord>, AuditError> {
        let mut stmt = conn
            .prepare(
                "SELECT sequence, event_id, timestamp, category, request_id, agent_id, \
                 operation, resource_kind, resource_summary, decision, reason_code, \
                 matched_rule_ids, metadata, previous_hash, current_hash \
                 FROM audit_events ORDER BY sequence DESC LIMIT 1",
            )
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        stmt.query_row([], row_to_event).map(Some).or_else(|e| {
            if e == rusqlite::Error::QueryReturnedNoRows {
                Ok(None)
            } else {
                Err(AuditError::transaction_failure(e.to_string()))
            }
        })
    }

    // ── Redaction helpers ────────────────────────────────────────────────────

    fn redact_opt(&self, value: Option<String>) -> Result<Option<String>, AuditError> {
        match (value, &self.redactor) {
            (Some(v), Some(redactor)) => {
                let result = redactor
                    .redact_text(&v)
                    .map_err(|e| AuditError::redaction_failure(e.to_string()))?;
                Ok(Some(result.redacted))
            }
            (v, _) => Ok(v),
        }
    }

    fn redact_metadata(
        &self,
        metadata: BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, AuditError> {
        if self.redactor.is_none() {
            return Ok(metadata);
        }
        let redactor = self
            .redactor
            .as_ref()
            .ok_or_else(|| AuditError::redaction_failure("redactor not configured".to_string()))?;
        let mut result = BTreeMap::new();
        for (k, v) in metadata {
            let redacted = redactor
                .redact_text(&v)
                .map_err(|e| AuditError::redaction_failure(e.to_string()))?;
            result.insert(k, redacted.redacted);
        }
        Ok(result)
    }

    // ── Verification (delegated to verification module) ───────────────────────
    // Full verification implementation is in crate::verification.

    /// Access the underlying connection (for testing only).
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub(crate) fn test_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("lock poisoned")
    }

    /// Returns all events in the store (for verification purposes).
    pub(crate) fn all_events(&self) -> Result<Vec<AuditEventRecord>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, event_id, timestamp, category, request_id, agent_id, \
                 operation, resource_kind, resource_summary, decision, reason_code, \
                 matched_rule_ids, metadata, previous_hash, current_hash \
                 FROM audit_events ORDER BY sequence ASC",
            )
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        let rows = stmt
            .query_map([], row_to_event)
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Returns events in a range for verification.
    pub(crate) fn events_in_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<AuditEventRecord>, AuditError> {
        if end - start + 1 > MAX_VERIFICATION_RANGE {
            return Err(AuditError::verification_range_too_large(
                end - start + 1,
                MAX_VERIFICATION_RANGE,
            ));
        }
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, event_id, timestamp, category, request_id, agent_id, \
                 operation, resource_kind, resource_summary, decision, reason_code, \
                 matched_rule_ids, metadata, previous_hash, current_hash \
                 FROM audit_events WHERE sequence >= ?1 AND sequence <= ?2 ORDER BY sequence ASC",
            )
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?;

        let rows = stmt
            .query_map(params![start, end], row_to_event)
            .map_err(|e| AuditError::transaction_failure(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<AuditEventRecord> {
    let matched_json: String = row.get(11)?;
    let metadata_json: String = row.get(12)?;
    let prev_hash_bytes: Vec<u8> = row.get(13)?;
    let curr_hash_bytes: Vec<u8> = row.get(14)?;

    let matched_rule_ids: Vec<String> = serde_json::from_str(&matched_json).unwrap_or_default();
    let metadata: BTreeMap<String, String> =
        serde_json::from_str(&metadata_json).unwrap_or_default();

    let cat_str: String = row.get(3)?;
    let category = parse_category(&cat_str).unwrap_or(AuditEventCategory::SecurityWarning);

    let prev_arr: [u8; 32] = prev_hash_bytes.as_slice().try_into().unwrap_or([0u8; 32]);
    let curr_arr: [u8; 32] = curr_hash_bytes.as_slice().try_into().unwrap_or([0u8; 32]);

    Ok(AuditEventRecord {
        sequence: row.get(0)?,
        event_id: row.get(1)?,
        timestamp: row.get(2)?,
        category,
        request_id: row.get(4)?,
        agent_id: row.get(5)?,
        operation: row.get(6)?,
        resource_kind: row.get(7)?,
        resource_summary: row.get(8)?,
        decision: row.get(9)?,
        reason_code: row.get(10)?,
        matched_rule_ids,
        metadata,
        previous_hash: HashValue::from_bytes(prev_arr),
        current_hash: HashValue::from_bytes(curr_arr),
    })
}

fn parse_category(s: &str) -> Option<AuditEventCategory> {
    match s {
        "RequestReceived" => Some(AuditEventCategory::RequestReceived),
        "RequestRejected" => Some(AuditEventCategory::RequestRejected),
        "DecisionAllow" => Some(AuditEventCategory::DecisionAllow),
        "DecisionDeny" => Some(AuditEventCategory::DecisionDeny),
        "ApprovalRequested" => Some(AuditEventCategory::ApprovalRequested),
        "ApprovalApproved" => Some(AuditEventCategory::ApprovalApproved),
        "ApprovalDenied" => Some(AuditEventCategory::ApprovalDenied),
        "ApprovalExpired" => Some(AuditEventCategory::ApprovalExpired),
        "ExecutionStarted" => Some(AuditEventCategory::ExecutionStarted),
        "ExecutionSucceeded" => Some(AuditEventCategory::ExecutionSucceeded),
        "ExecutionFailed" => Some(AuditEventCategory::ExecutionFailed),
        "PolicyLoaded" => Some(AuditEventCategory::PolicyLoaded),
        "PolicyRejected" => Some(AuditEventCategory::PolicyRejected),
        "AuditVerification" => Some(AuditEventCategory::AuditVerification),
        "SecurityWarning" => Some(AuditEventCategory::SecurityWarning),
        _ => None,
    }
}
