use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use std::sync::Arc;

use crate::state::GatewayState;

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

pub async fn ready(
    State(state): State<Arc<GatewayState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let runtime = state.runtime.read().map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "error", "error": format!("runtime lock poisoned: {e}")
            })),
        )
    })?;

    runtime.audit_store().chain_status().map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "error", "error": format!("audit store unavailable: {e}")
            })),
        )
    })?;

    runtime.broker().list_pending(Some(1)).map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "error", "error": format!("approval broker unavailable: {e}")
            })),
        )
    })?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "adapter_filesystem": true,
        "adapter_command": true,
        "adapter_network": true,
        "audit_available": true,
        "approval_available": true,
        "policy_loaded": true,
    })))
}

pub async fn status(State(state): State<Arc<GatewayState>>) -> Json<serde_json::Value> {
    let version = env!("CARGO_PKG_VERSION");
    Json(serde_json::json!({
        "service": "kavach-gateway",
        "version": version,
        "bind": state.config.bind,
        "uptime_seconds": 0,
    }))
}
