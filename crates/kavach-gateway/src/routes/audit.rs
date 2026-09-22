use axum::{
    Json,
    extract::{Extension, Query, State},
};
use std::sync::Arc;

use kavach_audit::{AuditEventCategory, MAX_EVENT_QUERY_COUNT};

use crate::{
    error::GatewayError,
    middleware::request_id::RequestId,
    state::GatewayState,
    types::{AuditEventDto, AuditEventsQuery},
};

pub async fn list_events(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
    Query(query): Query<AuditEventsQuery>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;

    let limit = query.limit.unwrap_or(100).min(MAX_EVENT_QUERY_COUNT);
    if limit == 0 {
        return Err(GatewayError::bad_request("limit must be greater than 0"));
    }
    if query.after.is_some() && query.before.is_some() {
        return Err(GatewayError::bad_request(
            "after and before cannot be used together",
        ));
    }

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;
    let store = runtime.audit_store();

    let records = if let Some(ref request_id) = query.request_id {
        store.events_by_request_id(request_id, limit)
    } else if let Some(ref cat_str) = query.category {
        let category = parse_category(cat_str)
            .ok_or_else(|| GatewayError::bad_request(format!("unknown category: {cat_str}")))?;
        store.events_by_category(category, limit)
    } else {
        match (query.after, query.before) {
            (Some(after), None) => store.events_after_sequence(after, limit),
            (None, Some(before)) => store.events_before_sequence(before, limit),
            (None, None) => store.events_before_sequence(i64::MAX as u64, limit),
            (Some(_), Some(_)) => {
                return Err(GatewayError::bad_request(
                    "after and before cannot be used together",
                ));
            }
        }
    }
    .map_err(|e| {
        tracing::error!(request_id = ?rid, "audit query failed: {e}");
        GatewayError::internal("audit query failed")
    })?;

    let dtos: Vec<AuditEventDto> = records.into_iter().map(AuditEventDto::from).collect();

    Ok(Json(
        serde_json::json!({ "request_id": rid, "status": "success", "data": dtos }),
    ))
}

pub async fn verify_chain(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;

    let report = runtime.audit_store().verify_full().map_err(|e| {
        tracing::error!(request_id = ?rid, "audit verification failed: {e}");
        GatewayError::internal("audit verification failed")
    })?;

    let error_details: Vec<serde_json::Value> = report
        .errors
        .iter()
        .map(|e| serde_json::json!({ "sequence": e.sequence, "kind": format!("{:?}", e.kind), "detail": e.detail }))
        .collect();

    Ok(Json(serde_json::json!({
        "request_id": rid, "status": "success",
        "data": {
            "chain_valid": report.chain_valid,
            "event_count": report.event_count,
            "verified_to": report.verified_to,
            "errors": error_details,
        },
    })))
}

fn parse_category(s: &str) -> Option<AuditEventCategory> {
    match s.to_ascii_lowercase().as_str() {
        "requestreceived" => Some(AuditEventCategory::RequestReceived),
        "requestrejected" => Some(AuditEventCategory::RequestRejected),
        "decisionallow" | "allow" | "allowed" => Some(AuditEventCategory::DecisionAllow),
        "decisiondeny" | "deny" | "denied" => Some(AuditEventCategory::DecisionDeny),
        "approvalrequested" | "approval" => Some(AuditEventCategory::ApprovalRequested),
        "approvalapproved" | "approve" => Some(AuditEventCategory::ApprovalApproved),
        "approvaldenied" => Some(AuditEventCategory::ApprovalDenied),
        "approvalexpired" => Some(AuditEventCategory::ApprovalExpired),
        "approvalconsumed" => Some(AuditEventCategory::ApprovalConsumed),
        "executionstarted" => Some(AuditEventCategory::ExecutionStarted),
        "executionsucceeded" => Some(AuditEventCategory::ExecutionSucceeded),
        "executionfailed" => Some(AuditEventCategory::ExecutionFailed),
        "policyloaded" => Some(AuditEventCategory::PolicyLoaded),
        "policyrejected" => Some(AuditEventCategory::PolicyRejected),
        "auditverification" => Some(AuditEventCategory::AuditVerification),
        "securitywarning" => Some(AuditEventCategory::SecurityWarning),
        _ => None,
    }
}
