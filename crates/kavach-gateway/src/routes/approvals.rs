use axum::{
    Json,
    extract::{Extension, Path, State},
};
use std::sync::Arc;

use kavach_approval::ApprovalActor;
use kavach_core::ids::ApprovalId;

use crate::{
    error::GatewayError,
    middleware::request_id::RequestId,
    state::GatewayState,
    types::{ApprovalRecordDto, ApproveBody, DenyBody},
};

pub async fn list_approvals(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;

    let records = runtime.broker().list_pending(None).map_err(|e| {
        tracing::error!(request_id = ?rid, "list approvals failed: {e}");
        GatewayError::internal("failed to list approvals")
    })?;

    let dtos: Vec<ApprovalRecordDto> = records.into_iter().map(ApprovalRecordDto::from).collect();

    Ok(Json(
        serde_json::json!({ "request_id": rid, "status": "success", "data": dtos }),
    ))
}

pub async fn get_approval(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
    Path(approval_id): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;

    let id = ApprovalId::new(&approval_id)
        .map_err(|_| GatewayError::bad_request(format!("invalid approval_id: {approval_id}")))?;

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;

    let record = runtime.broker().get_approval(&id).map_err(|e| {
        tracing::warn!(request_id = ?rid, "approval not found: {e}");
        GatewayError::not_found(format!("approval {approval_id} not found"))
    })?;

    Ok(Json(
        serde_json::json!({ "request_id": rid, "status": "success", "data": ApprovalRecordDto::from(record) }),
    ))
}

pub async fn approve_approval(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
    Path(approval_id): Path<String>,
    Json(body): Json<ApproveBody>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;

    let id = ApprovalId::new(&approval_id)
        .map_err(|_| GatewayError::bad_request(format!("invalid approval_id: {approval_id}")))?;

    let actor = ApprovalActor::new(body.actor.clone())
        .map_err(|e| GatewayError::bad_request(format!("invalid actor: {e}")))?;

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;

    let token = runtime.approve(&id, &actor).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found") {
            GatewayError::not_found(format!("approval {approval_id} not found"))
        } else if msg.contains("state") || msg.contains("transition") {
            GatewayError::conflict(msg)
        } else {
            GatewayError::internal(msg)
        }
    })?;

    let token_hex = hex::encode(token.hash());

    Ok(Json(serde_json::json!({
        "request_id": rid,
        "status": "success",
        "data": {
            "approval_id": approval_id,
            "token": token_hex,
            "token_note": "This token is sensitive. Do not log or share it.",
        },
    })))
}

pub async fn deny_approval(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
    Path(approval_id): Path<String>,
    Json(body): Json<DenyBody>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;

    let id = ApprovalId::new(&approval_id)
        .map_err(|_| GatewayError::bad_request(format!("invalid approval_id: {approval_id}")))?;

    let actor = ApprovalActor::new(body.actor.clone())
        .map_err(|e| GatewayError::bad_request(format!("invalid actor: {e}")))?;

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;

    runtime
        .deny(&id, &actor, body.reason.as_deref())
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                GatewayError::not_found(format!("approval {approval_id} not found"))
            } else if msg.contains("state") || msg.contains("transition") {
                GatewayError::conflict(msg)
            } else {
                GatewayError::internal(msg)
            }
        })?;

    Ok(Json(serde_json::json!({
        "request_id": rid, "status": "success",
        "data": { "approval_id": approval_id, "outcome": "denied" },
    })))
}
