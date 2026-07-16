use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::GatewayState;

pub async fn request_timeout(
    State(state): State<Arc<GatewayState>>,
    req: Request,
    next: Next,
) -> Result<Response, crate::error::GatewayError> {
    let timeout = state.config.request_timeout;
    tokio::time::timeout(timeout, next.run(req))
        .await
        .map_err(|_| {
            tracing::warn!("request timed out after {timeout:?}");
            crate::error::GatewayError::new(
                crate::error::KavachErrorCode::Timeout,
                "request timed out",
            )
        })
}
