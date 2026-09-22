use axum::Json;
use axum::extract::State;
use std::sync::Arc;

use crate::error::{GatewayError, KavachErrorCode};
use crate::state::GatewayState;

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "request_id": null,
        "status": "success",
        "data": { "status": "ok" },
    }))
}

pub async fn ready(
    State(state): State<Arc<GatewayState>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let runtime = state.runtime.read().map_err(|_| {
        GatewayError::new(
            KavachErrorCode::DependencyUnavailable,
            "readiness check failed",
        )
    })?;

    runtime.audit_store().chain_status().map_err(|_| {
        GatewayError::new(
            KavachErrorCode::DependencyUnavailable,
            "readiness check failed",
        )
    })?;

    runtime.broker().list_pending(Some(1)).map_err(|_| {
        GatewayError::new(
            KavachErrorCode::DependencyUnavailable,
            "readiness check failed",
        )
    })?;

    Ok(Json(serde_json::json!({
        "request_id": null,
        "status": "success",
        "data": {
            "ready": true,
            "adapters": {
                "filesystem": "ready",
                "command": "ready",
                "network": "ready",
            },
            "audit_store": "ready",
            "approval_store": "ready",
            "policy_count": runtime.policy_summaries().len(),
        },
    })))
}

pub async fn status(State(state): State<Arc<GatewayState>>) -> Json<serde_json::Value> {
    let version = env!("CARGO_PKG_VERSION");
    Json(serde_json::json!({
        "request_id": null,
        "status": "success",
        "data": {
            "service": "kavach-gateway",
            "version": version,
            "bind": state.config.bind,
            "uptime_seconds": state.started_at.elapsed().as_secs(),
        },
    }))
}
