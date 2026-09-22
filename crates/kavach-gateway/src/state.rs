use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use kavach_approval::ApprovalToken;
use kavach_core::permit::ExecutionPermit;
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
    /// Server-owned issued permits. Clients may echo permit metadata, but
    /// execution always uses the original server-side permit.
    pub issued_permits: IssuedPermitRegistry,
    /// Raw approval tokens retained only in process memory until an agent
    /// exchanges an approved request for a permit.
    pub approval_tokens: ApprovalTokenRegistry,
    /// Monotonic gateway start time used for real uptime reporting.
    pub started_at: Instant,
}

/// Maximum number of unconsumed gateway permits retained in memory.
const MAX_ISSUED_PERMITS: usize = 10_000;

/// Server-side registry for request-bound permits issued by the gateway.
pub struct IssuedPermitRegistry {
    inner: Mutex<HashMap<Vec<u8>, Arc<Mutex<ExecutionPermit>>>>,
}

impl IssuedPermitRegistry {
    /// Create an empty permit registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Register a newly issued permit, purging expired entries first.
    pub fn register(&self, permit: ExecutionPermit) -> Result<(), &'static str> {
        let mut permits = self.inner.lock().map_err(|_| "permit registry lock")?;
        permits.retain(|_, existing| {
            existing
                .lock()
                .map(|permit| !permit.is_expired() && !permit.is_consumed())
                .unwrap_or(false)
        });
        if permits.len() >= MAX_ISSUED_PERMITS {
            return Err("permit registry capacity reached");
        }
        permits.insert(
            permit.permit_token_hash().to_vec(),
            Arc::new(Mutex::new(permit)),
        );
        Ok(())
    }

    /// Get a server-owned permit. The per-permit lock serializes competing
    /// execution attempts while allowing invalid presentations to be retried.
    pub fn get(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<Arc<Mutex<ExecutionPermit>>>, &'static str> {
        let mut permits = self.inner.lock().map_err(|_| "permit registry lock")?;
        permits.retain(|_, existing| {
            existing
                .lock()
                .map(|permit| !permit.is_expired() && !permit.is_consumed())
                .unwrap_or(false)
        });
        Ok(permits.get(token_hash).cloned())
    }

    /// Remove a consumed or expired permit from the registry.
    pub fn remove(&self, token_hash: &[u8]) -> Result<(), &'static str> {
        let mut permits = self.inner.lock().map_err(|_| "permit registry lock")?;
        permits.remove(token_hash);
        Ok(())
    }
}

impl Default for IssuedPermitRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory registry for raw approval tokens. Tokens are never serialized,
/// logged, or returned to the dashboard.
pub struct ApprovalTokenRegistry {
    inner: Mutex<HashMap<String, ApprovalTokenEntry>>,
}

struct ApprovalTokenEntry {
    token: Option<ApprovalToken>,
    expires_at: DateTime<Utc>,
}

impl ApprovalTokenRegistry {
    /// Create an empty approval-token registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve capacity before making the irreversible approval transition.
    pub fn reserve(
        &self,
        approval_id: String,
        expires_at: DateTime<Utc>,
    ) -> Result<(), &'static str> {
        let mut tokens = self
            .inner
            .lock()
            .map_err(|_| "approval token registry lock")?;
        let now = Utc::now();
        tokens.retain(|_, entry| entry.expires_at > now);
        if tokens.contains_key(&approval_id) {
            return Err("approval token is already reserved");
        }
        if tokens.len() >= MAX_ISSUED_PERMITS {
            return Err("approval token registry capacity reached");
        }
        tokens.insert(
            approval_id,
            ApprovalTokenEntry {
                token: None,
                expires_at,
            },
        );
        Ok(())
    }

    /// Fill a previously reserved slot with the generated one-time token.
    pub fn fulfill(&self, approval_id: &str, token: ApprovalToken) -> Result<(), &'static str> {
        let mut tokens = self
            .inner
            .lock()
            .map_err(|_| "approval token registry lock")?;
        let entry = tokens
            .get_mut(approval_id)
            .ok_or("approval token reservation missing")?;
        entry.token = Some(token);
        Ok(())
    }

    /// Clone a token for a broker exchange without exposing its value.
    pub fn get(&self, approval_id: &str) -> Result<Option<ApprovalToken>, &'static str> {
        let mut tokens = self
            .inner
            .lock()
            .map_err(|_| "approval token registry lock")?;
        let now = Utc::now();
        tokens.retain(|_, entry| entry.expires_at > now);
        Ok(tokens
            .get(approval_id)
            .and_then(|entry| entry.token.clone()))
    }

    /// Remove a token after successful consumption.
    pub fn remove(&self, approval_id: &str) -> Result<(), &'static str> {
        let mut tokens = self
            .inner
            .lock()
            .map_err(|_| "approval token registry lock")?;
        tokens.remove(approval_id);
        Ok(())
    }
}

impl Default for ApprovalTokenRegistry {
    fn default() -> Self {
        Self::new()
    }
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
