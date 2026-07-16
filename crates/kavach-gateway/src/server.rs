use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::routing::{get, post};
use axum::{Router, middleware};
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;

use kavach_runtime::runtime::KavachRuntime;

use crate::auth::GatewayToken;
use crate::middleware::{auth as auth_mw, request_id as rid_mw};
use crate::routes::{approvals, audit, evaluate, execute, health, policies};
use crate::state::{GatewayConfig, GatewayState, RateLimiter};

pub(crate) fn is_loopback(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6 == &Ipv6Addr::LOCALHOST,
    }
}

/// Validate the bind address: non-loopback requires `allow_non_loopback`.
pub(crate) fn validate_bind(bind: &str, allow_non_loopback: bool) -> Result<(), String> {
    let addr: std::net::SocketAddr = bind
        .parse()
        .map_err(|e| format!("invalid bind address: {e}"))?;
    if !is_loopback(&addr.ip()) && !allow_non_loopback {
        return Err("binding to a non-loopback address requires allow_non_loopback: true".into());
    }
    Ok(())
}

/// Builder for the gateway server.
pub struct GatewayBuilder {
    runtime: Option<KavachRuntime>,
    token_hex: Option<String>,
    config: GatewayConfig,
}

impl Default for GatewayBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayBuilder {
    pub fn new() -> Self {
        Self {
            runtime: None,
            token_hex: None,
            config: GatewayConfig::default(),
        }
    }

    pub fn with_runtime(mut self, runtime: KavachRuntime) -> Self {
        self.runtime = Some(runtime);
        self
    }

    pub fn with_auth_token_hex(mut self, token_hex: Option<String>) -> Self {
        self.token_hex = token_hex;
        self
    }

    pub fn with_bind(mut self, bind: String) -> Self {
        self.config.bind = bind;
        self
    }

    pub fn with_config(mut self, config: GatewayConfig) -> Self {
        self.config = config;
        self
    }

    /// Build and start the server. Returns when shutdown completes.
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = self.runtime.ok_or("runtime is required")?;
        let config = self.config;

        validate_bind(&config.bind, config.allow_non_loopback)?;
        let addr: std::net::SocketAddr = config.bind.parse()?;

        let (token, _token_hex_display) = match self.token_hex {
            Some(hex_str) => {
                let raw = hex::decode(&hex_str).map_err(|_| "invalid token hex")?;
                let mut hash = [0u8; 32];
                let mut hasher = sha2::Sha256::new();
                use sha2::Digest;
                hasher.update(&raw);
                let result = hasher.finalize();
                hash.copy_from_slice(&result);
                (GatewayToken::from_hash(hash), hex_str)
            }
            None => {
                let (token, hex_str) = GatewayToken::generate();
                eprintln!("=== GATEWAY AUTH TOKEN (store this securely) ===");
                eprintln!("{hex_str}");
                eprintln!("================================================");
                (token, hex_str)
            }
        };

        let state = Arc::new(GatewayState {
            runtime: std::sync::RwLock::new(runtime),
            token,
            config: config.clone(),
            concurrency_semaphore: tokio::sync::Semaphore::new(config.concurrency_limit),
            rate_limiter: RateLimiter::new(config.rate_limit_per_second, config.rate_limit_burst),
        });

        let api_routes = Router::new()
            .route("/status", get(health::status))
            .route("/requests/evaluate", post(evaluate::evaluate))
            .route("/requests/execute", post(execute::execute))
            .route("/approvals", get(approvals::list_approvals))
            .route("/approvals/{id}", get(approvals::get_approval))
            .route("/approvals/{id}/approve", post(approvals::approve_approval))
            .route("/approvals/{id}/deny", post(approvals::deny_approval))
            .route("/audit/events", get(audit::list_events))
            .route("/audit/verify", post(audit::verify_chain))
            .route("/policies", get(policies::list_policies))
            .route("/policies/reload", post(policies::reload_policies))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth_mw::require_auth,
            ));

        let app = Router::new()
            .route("/health", get(health::health))
            .route("/ready", get(health::ready))
            .nest("/api", api_routes);

        // Serve dashboard static files at /dashboard/.
        let dashboard_path = PathBuf::from("dashboard/dist");
        let app = {
            use axum::routing::get_service;
            use tower_http::services::fs::ServeDir;
            let serve_dir = ServeDir::new(&dashboard_path).append_index_html_on_directories(true);
            app.route(
                "/dashboard/*path",
                get_service(serve_dir).handle_error(|e| async move {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("static file error: {e}"),
                    )
                }),
            )
        };

        let app = app
            .with_state(state.clone())
            .layer(middleware::from_fn(rid_mw::inject_request_id))
            .layer(SetResponseHeaderLayer::overriding(
                http::header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                http::header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                http::header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("frame-ancestors 'none'"),
            ))
            .layer(
                CorsLayer::new()
                    .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                    .allow_headers([AUTHORIZATION, CONTENT_TYPE])
                    .max_age(Duration::from_secs(86400)),
            )
            .layer(RequestBodyLimitLayer::new(config.request_body_limit))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::timeout::request_timeout,
            ))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::concurrency::concurrency_limit,
            ))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::rate_limit::rate_limit,
            ));

        tracing::info!(addr = %addr, "starting KAVACH gateway");

        let listener = TcpListener::bind(addr).await?;

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;

        Ok(())
    }
}

pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
