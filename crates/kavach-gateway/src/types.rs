use std::borrow::Cow;
use std::time::{Duration, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use kavach_core::ids::{RequestId, RuleId};
use kavach_core::permit::{ExecutionPermit, PermitScope};
use kavach_core::request::ToolRequest;

use crate::error::{GatewayError, KavachErrorCode};

// ── JSON Envelope ────────────────────────────────────────────────────────

/// Stable JSON envelope for all API responses.
#[derive(Serialize)]
pub struct ApiEnvelope<T: Serialize> {
    pub request_id: Option<String>,
    pub status: &'static str,
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiErrorBody>,
}

#[derive(Serialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}

impl<T: Serialize> ApiEnvelope<T> {
    pub fn success(request_id: Option<String>, data: T) -> Self {
        Self {
            request_id,
            status: "success",
            data: Some(data),
            error: None,
        }
    }
}

// ── Error response helper ────────────────────────────────────────────────

pub fn error_response(
    request_id: Option<String>,
    code: KavachErrorCode,
    message: impl Into<Cow<'static, str>>,
) -> Response {
    let body = serde_json::json!({
        "request_id": request_id,
        "status": "error",
        "data": null,
        "error": {
            "code": code.as_str(),
            "message": message.into(),
        },
    });
    (code.http_status(), axum::Json(body)).into_response()
}

pub fn success_response<T: Serialize>(request_id: Option<String>, data: T) -> Response {
    let body = serde_json::json!({
        "request_id": request_id,
        "status": "success",
        "data": data,
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

// ── Evaluate Request / Response ───────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    pub request: ToolRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluateOutcomeDto {
    Denied {
        request_id: String,
        reason_code: String,
        matched_rule_ids: Vec<String>,
        sanitized_summary: String,
        audit_event_id: u64,
    },
    ApprovalRequired {
        request_id: String,
        approval_id: String,
        sanitized_summary: String,
        audit_event_id: u64,
    },
    Permitted {
        request_id: String,
        permit: PermitDto,
        permit_secret_hex: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermitDto {
    pub permit_token_hash: Vec<u8>,
    pub request_id: String,
    pub scope: String,
    pub matched_rule_ids: Vec<String>,
    pub issued_at_secs: u64,
    pub issued_at_nanos: u32,
    pub expires_at_secs: u64,
    pub expires_at_nanos: u32,
    pub request_digest: String,
    pub consumed: bool,
}

impl From<&ExecutionPermit> for PermitDto {
    fn from(p: &ExecutionPermit) -> Self {
        let issued = p.issued_at().duration_since(UNIX_EPOCH).unwrap_or_default();
        let expires = p
            .expires_at()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            permit_token_hash: p.permit_token_hash().to_vec(),
            request_id: p.request_id.to_string(),
            scope: format!("{:?}", p.scope),
            matched_rule_ids: p.matched_rule_ids.iter().map(|r| r.to_string()).collect(),
            issued_at_secs: issued.as_secs(),
            issued_at_nanos: issued.subsec_nanos(),
            expires_at_secs: expires.as_secs(),
            expires_at_nanos: expires.subsec_nanos(),
            request_digest: hex::encode(p.request_digest()),
            consumed: p.consumed,
        }
    }
}

// ── Execute Request / Response ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub request: ToolRequest,
    pub permit: PermitDto,
    pub permit_secret_hex: String,
    pub input: ExecutionInputDto,
}

impl ExecuteRequest {
    pub fn reconstruct_permit(&self) -> Result<ExecutionPermit, GatewayError> {
        let scope: PermitScope = serde_json::from_value(serde_json::Value::String(
            self.permit.scope.clone(),
        ))
        .map_err(|_| {
            GatewayError::bad_request(format!("invalid permit scope: {}", self.permit.scope))
        })?;

        let request_id = RequestId::new(&self.permit.request_id)
            .map_err(|e| GatewayError::bad_request(format!("invalid request_id in permit: {e}")))?;

        let matched_rule_ids: Vec<RuleId> = self
            .permit
            .matched_rule_ids
            .iter()
            .filter_map(|s| RuleId::new(s).ok())
            .collect();

        let request_digest: [u8; 32] = {
            let bytes = hex::decode(&self.permit.request_digest)
                .map_err(|_| GatewayError::bad_request("invalid request_digest hex in permit"))?;
            if bytes.len() != 32 {
                return Err(GatewayError::bad_request("request_digest must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };

        let issued_at =
            UNIX_EPOCH + Duration::new(self.permit.issued_at_secs, self.permit.issued_at_nanos);
        let expires_at =
            UNIX_EPOCH + Duration::new(self.permit.expires_at_secs, self.permit.expires_at_nanos);

        Ok(ExecutionPermit::from_existing(
            self.permit.permit_token_hash.clone(),
            request_id,
            scope,
            matched_rule_ids,
            issued_at,
            expires_at,
            request_digest,
            self.permit.consumed,
        ))
    }

    pub fn parse_secret(&self) -> Result<[u8; 32], GatewayError> {
        let bytes = hex::decode(&self.permit_secret_hex)
            .map_err(|_| GatewayError::bad_request("invalid permit_secret_hex: not valid hex"))?;
        if bytes.len() != 32 {
            return Err(GatewayError::bad_request(
                "permit_secret_hex must be 32 bytes (64 hex chars)",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionInputDto {
    None,
    FilesystemWrite {
        #[serde(with = "hex_serde")]
        data: Vec<u8>,
    },
    Command {
        working_directory: Option<String>,
        env_vars: Vec<Vec<String>>,
        dry_run: Option<bool>,
        timeout_secs: Option<u64>,
    },
    Network {
        method: Option<String>,
        headers: Vec<Vec<String>>,
        body: Option<String>,
        no_redirect: Option<bool>,
        timeout_seconds: Option<u64>,
        response_body_limit: Option<u64>,
    },
}

// ── Approval DTOs ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveBody {
    pub actor: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyBody {
    pub actor: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeApprovalBody {
    pub request: ToolRequest,
}

#[derive(Debug, Serialize)]
pub struct ApprovalRecordDto {
    pub approval_id: String,
    pub request_id: String,
    pub summary: String,
    pub operation: String,
    pub resource_kind: String,
    pub matched_rule_ids: Vec<String>,
    pub state: String,
    pub actor: Option<String>,
    pub denial_reason: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub decision_at: Option<String>,
    pub consumed_at: Option<String>,
    pub audit_sequence: Option<u64>,
}

impl From<kavach_approval::ApprovalRecord> for ApprovalRecordDto {
    fn from(r: kavach_approval::ApprovalRecord) -> Self {
        Self {
            approval_id: r.approval_id.to_string(),
            request_id: r.request_id,
            summary: r.summary,
            operation: r.operation,
            resource_kind: r.resource_kind,
            matched_rule_ids: r.matched_rule_ids,
            state: r.state.to_string(),
            actor: r.actor.map(|a| a.to_string()),
            denial_reason: r.denial_reason,
            created_at: r.created_at.to_rfc3339(),
            expires_at: r.expires_at.to_rfc3339(),
            decision_at: r.decision_at.map(|d| d.to_rfc3339()),
            consumed_at: r.consumed_at.map(|c| c.to_rfc3339()),
            audit_sequence: r.audit_sequence,
        }
    }
}

// ── Audit DTOs ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventsQuery {
    pub after: Option<u64>,
    pub before: Option<u64>,
    pub request_id: Option<String>,
    pub category: Option<String>,
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct AuditEventDto {
    pub sequence: u64,
    pub event_id: String,
    pub timestamp: String,
    pub category: String,
    pub request_id: Option<String>,
    pub agent_id: Option<String>,
    pub operation: Option<String>,
    pub resource_kind: Option<String>,
    pub decision: Option<String>,
    pub reason_code: Option<String>,
    pub summary: Option<String>,
    pub matched_rule_ids: Vec<String>,
    pub previous_hash: String,
    pub current_hash: String,
}

impl From<kavach_audit::AuditEventRecord> for AuditEventDto {
    fn from(e: kavach_audit::AuditEventRecord) -> Self {
        Self {
            sequence: e.sequence,
            event_id: e.event_id,
            timestamp: e.timestamp,
            category: e.category.to_string(),
            request_id: e.request_id,
            agent_id: e.agent_id,
            operation: e.operation,
            resource_kind: e.resource_kind,
            decision: e.decision,
            reason_code: e.reason_code,
            summary: e.resource_summary,
            matched_rule_ids: e.matched_rule_ids,
            previous_hash: e.previous_hash.to_string(),
            current_hash: e.current_hash.to_string(),
        }
    }
}

// ── Policy DTOs ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PolicyDto {
    pub policy_id: String,
    pub policy_name: String,
    pub default_effect: String,
    pub rule_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReloadRequest {
    pub policy_paths: Vec<String>,
}

// ── Hex serde helper ─────────────────────────────────────────────────────

#[allow(dead_code)]
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
