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

    let permit_secret = body.parse_secret()?;
    let exec_input = PreparedExecutionInput::try_from(&body.input)?;
    if body.permit.permit_token_hash.len() != 32 {
        return Err(GatewayError::bad_request(
            "permit_token_hash must be 32 bytes",
        ));
    }
    let permit_entry = state
        .issued_permits
        .get(&body.permit.permit_token_hash)
        .map_err(GatewayError::internal)?
        .ok_or_else(|| {
            GatewayError::bad_request("permit was not issued by this gateway or was already used")
        })?;
    let mut permit = permit_entry
        .lock()
        .map_err(|_| GatewayError::internal("permit lock"))?;

    let runtime = state
        .runtime
        .read()
        .map_err(|_| GatewayError::internal("runtime lock"))?;

    let execution = exec_input.execute(&runtime, &body.request, &mut permit, &permit_secret);
    let discard_permit = permit.is_consumed() || permit.is_expired();
    drop(permit);
    if discard_permit {
        state
            .issued_permits
            .remove(&body.permit.permit_token_hash)
            .map_err(GatewayError::internal)?;
    }

    let result = execution.map_err(|e| {
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

enum PreparedExecutionInput {
    None,
    FilesystemWrite(Vec<u8>),
    Command(CommandInput),
    Network(NetworkInput),
}

impl PreparedExecutionInput {
    fn execute(
        self,
        runtime: &kavach_runtime::runtime::KavachRuntime,
        request: &kavach_core::request::ToolRequest,
        permit: &mut kavach_core::permit::ExecutionPermit,
        permit_secret: &[u8; 32],
    ) -> Result<kavach_runtime::outcome::ExecutionResult, kavach_runtime::error::RuntimeError> {
        match self {
            Self::None => runtime.execute(request, permit, permit_secret, ExecutionInput::None),
            Self::FilesystemWrite(data) => runtime.execute(
                request,
                permit,
                permit_secret,
                ExecutionInput::FilesystemWrite(&data),
            ),
            Self::Command(input) => runtime.execute(
                request,
                permit,
                permit_secret,
                ExecutionInput::Command(input),
            ),
            Self::Network(input) => runtime.execute(
                request,
                permit,
                permit_secret,
                ExecutionInput::Network(input),
            ),
        }
    }
}

impl TryFrom<&ExecutionInputDto> for PreparedExecutionInput {
    type Error = GatewayError;

    fn try_from(dto: &ExecutionInputDto) -> Result<Self, Self::Error> {
        match dto {
            ExecutionInputDto::None => Ok(Self::None),
            ExecutionInputDto::FilesystemWrite { data } => Ok(Self::FilesystemWrite(data.clone())),
            ExecutionInputDto::Command {
                working_directory,
                env_vars,
                dry_run,
                timeout_secs,
            } => {
                if env_vars.iter().any(|pair| pair.len() != 2) {
                    return Err(GatewayError::bad_request(
                        "each env_vars entry must contain exactly two strings",
                    ));
                }
                let env_pairs = env_vars
                    .iter()
                    .map(|pair| (pair[0].clone(), pair[1].clone()))
                    .collect();
                Ok(Self::Command(CommandInput {
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
                let net_method = match method.as_deref() {
                    None => None,
                    Some(value) => Some(match value.to_ascii_uppercase().as_str() {
                        "GET" => NetworkMethod::Get,
                        "HEAD" => NetworkMethod::Head,
                        "POST" => NetworkMethod::Post,
                        "PUT" => NetworkMethod::Put,
                        "PATCH" => NetworkMethod::Patch,
                        "DELETE" => NetworkMethod::Delete,
                        _ => return Err(GatewayError::bad_request("unsupported network method")),
                    }),
                };
                if headers.iter().any(|pair| pair.len() != 2) {
                    return Err(GatewayError::bad_request(
                        "each headers entry must contain exactly two strings",
                    ));
                }
                let hdrs = headers
                    .iter()
                    .map(|pair| (pair[0].clone(), pair[1].clone()))
                    .collect();
                Ok(Self::Network(NetworkInput {
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
}
