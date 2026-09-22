use axum::{
    Json,
    extract::{Extension, State},
};
use std::sync::Arc;

use kavach_policy::load_policy_from_file;

use crate::{
    error::GatewayError, middleware::request_id::RequestId, state::GatewayState,
    types::ReloadRequest,
};

pub async fn list_policies(
    State(state): State<Arc<GatewayState>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;
    let policies: Vec<serde_json::Value> = runtime
        .policy_summaries()
        .into_iter()
        .map(|policy| {
            serde_json::json!({
                "policy_id": policy.id,
                "policy_name": policy.name,
                "default_effect": format!("{:?}", policy.default_effect).to_lowercase(),
                "rule_count": policy.rule_count,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "request_id": null, "status": "success",
        "data": policies,
    })))
}

pub async fn reload_policies(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
    Json(body): Json<ReloadRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;

    if body.policy_paths.is_empty() {
        return Err(GatewayError::bad_request("policy_paths must not be empty"));
    }

    let mut policies = Vec::new();
    for path in &body.policy_paths {
        match load_policy_from_file(path) {
            Ok(policy) => policies.push(policy),
            Err(e) => {
                tracing::warn!(request_id = ?rid, path = %path, "policy load failed: {e}");
                return Err(GatewayError::bad_request(format!(
                    "failed to load policy {path}: {e}"
                )));
            }
        }
    }

    {
        let mut runtime = state.runtime.write().map_err(|e| {
            tracing::error!(request_id = ?rid, "runtime lock: {e}");
            GatewayError::internal("internal error")
        })?;

        runtime.reload_policies(policies).map_err(|e| {
            tracing::error!(request_id = ?rid, "policy reload failed: {e}");
            GatewayError::bad_request(format!("policy validation failed: {e}"))
        })?;
    }

    tracing::info!(request_id = ?rid, "policy reloaded successfully");

    Ok(Json(serde_json::json!({
        "request_id": rid, "status": "success",
        "data": { "reloaded": true, "policy_count": body.policy_paths.len() }
    })))
}
