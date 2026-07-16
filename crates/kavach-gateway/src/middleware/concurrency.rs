use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::GatewayState;

pub async fn concurrency_limit(
    State(state): State<Arc<GatewayState>>,
    req: Request,
    next: Next,
) -> Result<Response, crate::error::GatewayError> {
    let permit = state.concurrency_semaphore.acquire().await.map_err(|_| {
        tracing::warn!("concurrency semaphore closed");
        crate::error::GatewayError::new(
            crate::error::KavachErrorCode::InternalError,
            "internal error",
        )
    })?;
    let res = next.run(req).await;
    drop(permit);
    Ok(res)
}
