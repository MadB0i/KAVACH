use std::sync::Mutex;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use kavach_runtime::runtime::KavachRuntime;

use crate::auth::GatewayToken;

/// Configuration for the gateway server.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// HTTP bind address.
    pub bind: String,
    /// Maximum request body size in bytes.
    pub request_body_limit: usize,
    /// Total request timeout.
    pub request_timeout: Duration,
    /// Maximum concurrent requests.
    pub concurrency_limit: usize,
    /// Rate limit: max requests per second.
    pub rate_limit_per_second: u64,
    /// Rate limit: burst size.
    pub rate_limit_burst: u32,
    /// CORS allowed origins (empty = no CORS).
    pub cors_allowed_origins: Vec<String>,
    /// Graceful shutdown timeout.
    pub shutdown_timeout: Duration,
    /// When `false` (default), binding to a non-loopback address is rejected.
    pub allow_non_loopback: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:7421".to_string(),
            request_body_limit: 1_048_576,
            request_timeout: Duration::from_secs(30),
            concurrency_limit: 100,
            rate_limit_per_second: 50,
            rate_limit_burst: 100,
            cors_allowed_origins: vec![],
            shutdown_timeout: Duration::from_secs(10),
            allow_non_loopback: false,
        }
    }
}

/// Shared application state available to all route handlers.
pub struct GatewayState {
    /// The runtime, protected by a read-write lock so policy reload can
    /// atomically swap the engine.
    pub runtime: RwLock<KavachRuntime>,
    /// Bearer token for API authentication.
    pub token: GatewayToken,
    /// Gateway configuration.
    pub config: GatewayConfig,
    /// Semaphore for concurrency limiting.
    pub concurrency_semaphore: tokio::sync::Semaphore,
    /// Rate limiter for request throttling.
    pub rate_limiter: RateLimiter,
}

/// Sliding-window rate limiter.
pub struct RateLimiter {
    inner: Mutex<RateLimiterInner>,
    max_per_second: u64,
    burst: u32,
}

struct RateLimiterInner {
    /// Timestamps of recent requests.
    timestamps: Vec<Instant>,
}

impl RateLimiter {
    pub fn new(max_per_second: u64, burst: u32) -> Self {
        Self {
            inner: Mutex::new(RateLimiterInner {
                timestamps: Vec::with_capacity(burst as usize + 1),
            }),
            max_per_second,
            burst,
        }
    }

    /// Returns `true` if the request is within the rate limit.
    pub fn check(&self) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        // Remove timestamps older than 1 second.
        inner
            .timestamps
            .retain(|t| now.duration_since(*t) < Duration::from_secs(1));
        if inner.timestamps.len() >= self.burst as usize {
            return false;
        }
        // Also check sustained rate (per second).
        if inner.timestamps.len() as u64 >= self.max_per_second {
            return false;
        }
        inner.timestamps.push(now);
        true
    }
}
