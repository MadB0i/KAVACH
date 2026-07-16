use axum::{
    Json,
    extract::{Extension, State},
};
use std::sync::Arc;

use kavach_enforcement::command::CommandInput;
use kavach_enforcement::network::{NetworkInput, NetworkMethod};
use kavach_runtime::outcome::ExecutionInput;

use crate::{
    error::GatewayError,
    middleware::request_id::RequestId,
    state::GatewayState,
    types::{ExecuteRequest, ExecutionInputDto},
};

pub async fn execute(
    State(state): State<Arc<GatewayState>>,
    Extension(rid): Extension<RequestId>,
    Json(body): Json<ExecuteRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let rid = rid.0;

    body.request.validate().map_err(|e| {
        tracing::warn!(request_id = ?rid, "execute: invalid request: {e}");
        GatewayError::bad_request(format!("invalid request: {e}"))
    })?;

    let mut permit = body.reconstruct_permit()?;
    let permit_secret = body.parse_secret()?;
    let exec_input = convert_input(&body.input)?;

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;

    let result = runtime
        .execute(&body.request, &mut permit, &permit_secret, exec_input)
        .map_err(|e| {
            tracing::warn!(request_id = ?rid, "execute failed: {e}");
            let msg = e.to_string();
            if msg.contains("permit") || msg.contains("digest") || msg.contains("scope") {
                GatewayError::bad_request(msg)
            } else if msg.contains("dry run") {
                GatewayError::forbidden(msg)
            } else {
                GatewayError::internal("execution failed")
            }
        })?;

    let result_debug = format!("{:?}", result);
    let result_json = serde_json::Value::String(result_debug);

    Ok(Json(serde_json::json!({
        "request_id": rid, "status": "success",
        "data": { "result": result_json }
    })))
}

fn convert_input(dto: &ExecutionInputDto) -> Result<ExecutionInput<'static>, GatewayError> {
    match dto {
        ExecutionInputDto::None => Ok(ExecutionInput::None),
        ExecutionInputDto::FilesystemWrite { data } => {
            let owned = data.clone();
            Ok(ExecutionInput::FilesystemWrite(Box::leak(
                owned.into_boxed_slice(),
            )))
        }
        ExecutionInputDto::Command {
            working_directory,
            env_vars,
            dry_run,
            timeout_secs,
        } => {
            let env_pairs: Vec<(String, String)> = env_vars
                .iter()
                .filter_map(|v| {
                    if v.len() == 2 {
                        Some((v[0].clone(), v[1].clone()))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(ExecutionInput::Command(CommandInput {
                working_directory: working_directory.clone().map(std::path::PathBuf::from),
                env_vars: env_pairs,
                dry_run: dry_run.unwrap_or(false),
                timeout_seconds: *timeout_secs,
            }))
        }
        ExecutionInputDto::Network {
            method,
            headers,
            body,
            no_redirect,
            timeout_seconds,
            response_body_limit,
        } => {
            let net_method = method
                .as_ref()
                .and_then(|m| match m.to_uppercase().as_str() {
                    "GET" => Some(NetworkMethod::Get),
                    "HEAD" => Some(NetworkMethod::Head),
                    "POST" => Some(NetworkMethod::Post),
                    "PUT" => Some(NetworkMethod::Put),
                    "PATCH" => Some(NetworkMethod::Patch),
                    "DELETE" => Some(NetworkMethod::Delete),
                    _ => None,
                });
            let hdrs: Vec<(String, String)> = headers
                .iter()
                .filter_map(|v| {
                    if v.len() == 2 {
                        Some((v[0].clone(), v[1].clone()))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(ExecutionInput::Network(NetworkInput {
                method: net_method,
                headers: hdrs,
                body: body.clone().map(|s| s.into_bytes()),
                no_redirect: no_redirect.unwrap_or(false),
                timeout_seconds: *timeout_seconds,
                response_body_limit: *response_body_limit,
            }))
        }
    }
}
