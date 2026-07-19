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
    types::{
        ApprovalRecordDto, ApproveBody, ConsumeApprovalBody, DenyBody, EvaluateOutcomeDto,
        PermitDto,
    },
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
    state
        .approval_tokens
        .insert(approval_id.clone(), token)
        .map_err(GatewayError::internal)?;

    Ok(Json(serde_json::json!({
        "request_id": rid,
        "status": "success",
        "data": {
            "approval_id": approval_id,
            "outcome": "approved",
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

pub async fn consume_approval(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
    Path(approval_id): Path<String>,
    Json(body): Json<ConsumeApprovalBody>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;
    let id = ApprovalId::new(&approval_id)
        .map_err(|_| GatewayError::bad_request(format!("invalid approval_id: {approval_id}")))?;
    body.request
        .validate()
        .map_err(|e| GatewayError::bad_request(format!("invalid request: {e}")))?;

    let token = state
        .approval_tokens
        .get(&approval_id)
        .map_err(GatewayError::internal)?
        .ok_or_else(|| {
            GatewayError::conflict(
                "approval token is unavailable; the approval may predate this gateway process",
            )
        })?;

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;
    let outcome = runtime
        .consume_approval(&body.request, &id, &token)
        .map_err(|e| {
            let message = e.to_string();
            if message.contains("digest") {
                GatewayError::bad_request(message)
            } else {
                GatewayError::conflict(message)
            }
        })?;

    let request_id = outcome.request_id().to_string();
    let permit_secret_hex = hex::encode(outcome.secret());
    let permit = PermitDto::from(&outcome.permit);
    state
        .issued_permits
        .register(outcome.permit)
        .map_err(GatewayError::internal)?;
    state
        .approval_tokens
        .remove(&approval_id)
        .map_err(GatewayError::internal)?;

    let dto = EvaluateOutcomeDto::Permitted {
        request_id,
        permit,
        permit_secret_hex,
    };
    Ok(Json(serde_json::json!({
        "request_id": rid,
        "status": "success",
        "data": dto,
    })))
}
