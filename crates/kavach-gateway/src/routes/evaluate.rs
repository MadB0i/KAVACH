use axum::{
    Json,
    extract::{Extension, State},
};
use std::sync::Arc;

use crate::{
    error::GatewayError,
    middleware::request_id::RequestId,
    state::GatewayState,
    types::{EvaluateOutcomeDto, EvaluateRequest, PermitDto},
};

pub async fn evaluate(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
    Json(body): Json<EvaluateRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;

    body.request.validate().map_err(|e| {
        tracing::warn!(request_id = ?rid, "evaluate: invalid request: {e}");
        GatewayError::bad_request(format!("invalid request: {e}"))
    })?;

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;

    let outcome = runtime.evaluate(&body.request).map_err(|e| {
        tracing::error!(request_id = ?rid, "evaluate failed: {e}");
        GatewayError::internal("evaluation failed")
    })?;

    let dto = match outcome {
        kavach_runtime::outcome::RuntimeOutcome::Denied {
            request_id,
            reason_code,
            matched_rule_ids,
            sanitized_summary,
            audit_event_id,
        } => EvaluateOutcomeDto::Denied {
            request_id: request_id.to_string(),
            reason_code: reason_code.to_string(),
            matched_rule_ids: matched_rule_ids.iter().map(|r| r.to_string()).collect(),
            sanitized_summary,
            audit_event_id,
        },
        kavach_runtime::outcome::RuntimeOutcome::ApprovalRequired {
            request_id,
            approval_id,
            sanitized_summary,
            audit_event_id,
        } => EvaluateOutcomeDto::ApprovalRequired {
            request_id: request_id.to_string(),
            approval_id: approval_id.to_string(),
            sanitized_summary,
            audit_event_id,
        },
        kavach_runtime::outcome::RuntimeOutcome::Permitted(outcome) => {
            EvaluateOutcomeDto::Permitted {
                request_id: outcome.request_id().to_string(),
                permit: PermitDto::from(&outcome.permit),
                permit_secret_hex: hex::encode(outcome.secret()),
            }
        }
    };

    Ok(Json(
        serde_json::json!({ "request_id": rid, "status": "success", "data": dto }),
    ))
}
