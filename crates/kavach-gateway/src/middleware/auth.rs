use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use http::header::AUTHORIZATION;

use crate::error::GatewayError;
use crate::state::GatewayState;

/// Middleware that checks for a valid Bearer token on all `/api/` routes.
pub async fn require_auth(
    State(state): State<std::sync::Arc<GatewayState>>,
    req: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("missing Authorization header");
            GatewayError::unauthorized("missing Authorization header")
        })?;

    let token_hex = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        tracing::warn!("invalid Authorization header format");
        GatewayError::unauthorized("Authorization header must use Bearer scheme")
    })?;

    if !state.token.verify(token_hex) {
        tracing::warn!("invalid API token");
        return Err(GatewayError::unauthorized("invalid API token"));
    }

    // Token is valid — proceed.
    Ok(next.run(req).await)
}
