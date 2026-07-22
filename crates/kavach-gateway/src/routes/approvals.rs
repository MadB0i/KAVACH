use axum::{
    Json,
    extract::{Extension, Path, State},
};
use std::sync::Arc;

use kavach_approval::{ApprovalActor, ApprovalError, error::ApprovalErrorKind};
use kavach_core::ids::ApprovalId;
use kavach_runtime::error::RuntimeError;

use crate::{
    error::GatewayError,
    middleware::request_id::RequestId,
    state::GatewayState,
    types::{
        ApprovalRecordDto, ApproveBody, ConsumeApprovalBody, DenyBody, EvaluateOutcomeDto,
        PermitDto,
    },
};

fn map_approval_error(error: ApprovalError, approval_id: &str, request_id: &str) -> GatewayError {
    match error.kind {
        ApprovalErrorKind::ApprovalNotFound => {
            GatewayError::not_found(format!("approval {approval_id} not found"))
        }
        ApprovalErrorKind::InvalidRequest(_)
        | ApprovalErrorKind::InvalidActor(_)
        | ApprovalErrorKind::InvalidReason(_)
        | ApprovalErrorKind::SummaryTooLarge(_)
        | ApprovalErrorKind::QueryLimitExceeded => {
            GatewayError::bad_request("invalid approval operation")
        }
        ApprovalErrorKind::InvalidStateTransition { .. }
        | ApprovalErrorKind::AlreadyApproved
        | ApprovalErrorKind::AlreadyDenied
        | ApprovalErrorKind::Cancelled
        | ApprovalErrorKind::Expired
        | ApprovalErrorKind::InvalidToken
        | ApprovalErrorKind::TokenBindingMismatch
        | ApprovalErrorKind::TokenAlreadyConsumed
        | ApprovalErrorKind::RequestDigestMismatch
        | ApprovalErrorKind::DuplicateActiveApproval
        | ApprovalErrorKind::PendingLimitReached => {
            GatewayError::conflict("approval is not available for this operation")
        }
        ApprovalErrorKind::InvalidConfiguration(_)
        | ApprovalErrorKind::DatabaseOpen(_)
        | ApprovalErrorKind::MigrationFailure(_)
        | ApprovalErrorKind::DatabaseCorruption(_)
        | ApprovalErrorKind::TransactionFailure(_)
        | ApprovalErrorKind::AuditFailure(_)
        | ApprovalErrorKind::RedactionFailure(_) => {
            tracing::error!(
                request_id,
                approval_id,
                "approval operation failed: {error}"
            );
            GatewayError::internal("approval operation failed")
        }
    }
}

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

    let record = runtime
        .broker()
        .get_approval(&id)
        .map_err(|error| map_approval_error(error, &approval_id, &rid))?;

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

    let record = runtime
        .broker()
        .get_approval(&id)
        .map_err(|error| map_approval_error(error, &approval_id, &rid))?;
    state
        .approval_tokens
        .reserve(approval_id.clone(), record.expires_at)
        .map_err(GatewayError::conflict)?;

    let token = runtime.broker().approve(&id, &actor).map_err(|error| {
        let _ = state.approval_tokens.remove(&approval_id);
        map_approval_error(error, &approval_id, &rid)
    })?;

    state
        .approval_tokens
        .fulfill(&approval_id, token)
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
            match e {
                RuntimeError::InvalidRequest(_)
                | RuntimeError::PermitFailure(_)
                | RuntimeError::PermitScopeMismatch { .. }
                | RuntimeError::InvalidExecutionInput(_) => {
                    GatewayError::bad_request("approval does not match the presented request")
                }
                RuntimeError::ApprovalFailure(_) => {
                    GatewayError::conflict("approval is not available for consumption")
                }
                internal => {
                    tracing::error!(request_id = ?rid, approval_id, "approval consumption failed: {internal}");
                    GatewayError::internal("approval consumption failed")
                }
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
        .broker()
        .deny(&id, &actor, body.reason.as_deref())
        .map_err(|error| map_approval_error(error, &approval_id, &rid))?;

    Ok(Json(serde_json::json!({
        "request_id": rid, "status": "success",
        "data": { "approval_id": approval_id, "outcome": "denied" },
    })))
}
