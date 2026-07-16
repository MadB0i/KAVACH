use axum::{extract::Request, middleware::Next, response::Response};
use http::HeaderValue;
use tracing::Span;

/// Middleware that injects a unique request ID into every request.
///
/// The ID is inserted into the response headers and the tracing span so it
/// appears in structured logs.
pub async fn inject_request_id(mut req: Request, next: Next) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();

    // Attach to the tracing span.
    Span::current().record("request_id", request_id.as_str());

    // Store in request extensions for downstream handlers.
    req.extensions_mut().insert(RequestId(request_id.clone()));

    let mut res = next.run(req).await;

    // Set response header.
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        res.headers_mut().insert("X-Request-Id", val);
    }

    res
}

/// Typed request ID extracted from middleware.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);
