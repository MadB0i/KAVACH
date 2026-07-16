use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::borrow::Cow;

/// Stable machine-readable error codes returned in the JSON envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KavachErrorCode {
    InvalidRequest,
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict,
    PayloadTooLarge,
    RateLimited,
    Timeout,
    InternalError,
    DependencyUnavailable,
}

impl KavachErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            KavachErrorCode::InvalidRequest => "KAVACH_INVALID_REQUEST",
            KavachErrorCode::Unauthenticated => "KAVACH_UNAUTHENTICATED",
            KavachErrorCode::Forbidden => "KAVACH_FORBIDDEN",
            KavachErrorCode::NotFound => "KAVACH_NOT_FOUND",
            KavachErrorCode::Conflict => "KAVACH_CONFLICT",
            KavachErrorCode::PayloadTooLarge => "KAVACH_PAYLOAD_TOO_LARGE",
            KavachErrorCode::RateLimited => "KAVACH_RATE_LIMITED",
            KavachErrorCode::Timeout => "KAVACH_TIMEOUT",
            KavachErrorCode::InternalError => "KAVACH_INTERNAL_ERROR",
            KavachErrorCode::DependencyUnavailable => "KAVACH_DEPENDENCY_UNAVAILABLE",
        }
    }

    pub fn http_status(&self) -> StatusCode {
        match self {
            KavachErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            KavachErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
            KavachErrorCode::Forbidden => StatusCode::FORBIDDEN,
            KavachErrorCode::NotFound => StatusCode::NOT_FOUND,
            KavachErrorCode::Conflict => StatusCode::CONFLICT,
            KavachErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            KavachErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            KavachErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
            KavachErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            KavachErrorCode::DependencyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Gateway error type that maps to HTTP status + JSON envelope.
#[derive(Debug)]
pub struct GatewayError {
    pub code: KavachErrorCode,
    pub message: Cow<'static, str>,
    pub status: StatusCode,
}

impl GatewayError {
    pub fn new(code: KavachErrorCode, message: impl Into<Cow<'static, str>>) -> Self {
        let status = code.http_status();
        Self {
            code,
            message: message.into(),
            status,
        }
    }

    pub fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(KavachErrorCode::InvalidRequest, message)
    }

    pub fn unauthorized(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(KavachErrorCode::Unauthenticated, message)
    }

    pub fn forbidden(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(KavachErrorCode::Forbidden, message)
    }

    pub fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(KavachErrorCode::NotFound, message)
    }

    pub fn conflict(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(KavachErrorCode::Conflict, message)
    }

    pub fn internal(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(KavachErrorCode::InternalError, message)
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "request_id": null,
            "status": "error",
            "data": null,
            "error": {
                "code": self.code.as_str(),
                "message": self.message.as_ref(),
            },
        });
        (self.status, axum::Json(body)).into_response()
    }
}
