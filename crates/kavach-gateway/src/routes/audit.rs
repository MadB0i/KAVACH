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
        let after = query.after.unwrap_or(0);
        store.events_after_sequence(after, limit)
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
