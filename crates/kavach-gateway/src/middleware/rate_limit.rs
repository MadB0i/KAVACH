use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::GatewayState;

pub async fn rate_limit(
    State(state): State<Arc<GatewayState>>,
    req: Request,
    next: Next,
) -> Result<Response, crate::error::GatewayError> {
    let allowed = state.rate_limiter.check();
    if !allowed {
        tracing::warn!("rate limit exceeded");
        return Err(crate::error::GatewayError::new(
            crate::error::KavachErrorCode::RateLimited,
            "rate limit exceeded",
        ));
    }
    Ok(next.run(req).await)
}
