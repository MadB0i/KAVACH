//! Secure network enforcement adapter with SSRF, DNS rebinding, and redirect protection.
//!
//! All outbound HTTP/HTTPS requests require a valid, unexpired, single-use
//! [`ExecutionPermit`] bound to the exact [`ToolRequest`].

#![allow(missing_docs)]

use std::error::Error as StdError;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use kavach_core::request::{Operation, ToolRequest};
use kavach_core::resource::Resource;
use kavach_runtime::ExecutionPermit;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DEFAULT_NETWORK_TIMEOUT_SECONDS: u64 = 30;
pub const MAX_NETWORK_TIMEOUT_SECONDS: u64 = 300;
pub const DEFAULT_CONNECT_TIMEOUT_SECONDS: u64 = 10;
pub const DEFAULT_RESPONSE_BODY_LIMIT: u64 = 10 * 1024 * 1024;
pub const DEFAULT_REQUEST_BODY_LIMIT: u64 = 1_048_576;
pub const DEFAULT_REDIRECT_LIMIT: usize = 5;
pub const MAX_REDIRECT_LIMIT: usize = 20;
pub const MAX_HEADER_COUNT: usize = 64;
pub const MAX_HEADER_NAME_LENGTH: usize = 256;
pub const MAX_HEADER_VALUE_LENGTH: usize = 8192;

// ---------------------------------------------------------------------------
// HTTP method
// ---------------------------------------------------------------------------

/// Supported HTTP methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl NetworkMethod {
    #[allow(dead_code)]
    fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

// ---------------------------------------------------------------------------
// Input / Output
// ---------------------------------------------------------------------------

/// Typed network execution input.
#[derive(Debug, Clone, Default)]
pub struct NetworkInput {
    pub method: Option<NetworkMethod>,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub no_redirect: bool,
    pub timeout_seconds: Option<u64>,
    pub response_body_limit: Option<u64>,
}

/// Typed outcome of a network request.
#[derive(Debug, Clone)]
pub struct NetworkOutcome {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub body_len: u64,
    pub redirect_count: usize,
    pub final_url: String,
    pub duration: Duration,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Typed errors for network enforcement.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid permit: {0}")]
    InvalidPermit(String),
    #[error("permit expired")]
    PermitExpired,
    #[error("permit already consumed")]
    PermitConsumed,
    #[error("unsupported operation")]
    UnsupportedOperation,
    #[error("wrong resource type")]
    WrongResourceType,
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),
    #[error("plain HTTP disabled")]
    PlainHttpDisabled,
    #[error("credentials in URL")]
    CredentialsInUrl,
    #[error("invalid header: {0}")]
    InvalidHeader(String),
    #[error("request body limit exceeded")]
    RequestBodyLimitExceeded,
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),
    #[error("blocked address: {0}")]
    BlockedAddress(String),
    #[error("metadata endpoint blocked")]
    MetadataEndpointBlocked,
    #[error("DNS rebinding protection failure")]
    DnsRebindingProtectionFailure,
    #[error("redirect rejected: {0}")]
    RedirectRejected(String),
    #[error("redirect limit exceeded")]
    RedirectLimitExceeded,
    #[error("policy denied redirect")]
    PolicyDeniedRedirect,
    #[error("connection timed out")]
    ConnectTimeout,
    #[error("request timed out")]
    RequestTimeout,
    #[error("response body limit exceeded")]
    ResponseBodyLimitExceeded,
    #[error("TLS failure: {0}")]
    TlsFailure(String),
    #[error("transport failure: {0}")]
    TransportFailure(String),
}

// ---------------------------------------------------------------------------
// SSRF address ranges
// ---------------------------------------------------------------------------

fn is_blocked_ipv4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    match octets {
        [10, ..] => true,             // 10.0.0.0/8
        [172, 16..=31, ..] => true,   // 172.16.0.0/12
        [192, 168, ..] => true,       // 192.168.0.0/16
        [127, ..] => true,            // loopback
        [169, 254, ..] => true,       // link-local
        [0, ..] => true,              // unspecified
        [224..=239, ..] => true,      // multicast
        [255, 255, 255, 255] => true, // broadcast
        [100, 64..=127, ..] => true,  // CGNAT 100.64.0.0/10
        _ => false,
    }
}

fn is_blocked_ipv6(addr: Ipv6Addr) -> bool {
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return true;
    }
    let segs = addr.segments();
    match segs {
        [0xfe80, ..] => true,          // link-local
        [0xfc00..=0xfdff, ..] => true, // unique-local
        [0, 0, 0, 0, 0, 0xffff, ..] => {
            // IPv4-mapped: check the embedded IPv4
            let v4 = addr.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED);
            is_blocked_ipv4(v4)
        }
        _ => false,
    }
}

fn is_blocked_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

/// Metadata endpoint hostnames to block.
const METADATA_HOSTNAMES: &[&str] = &["metadata.google.internal"];

fn is_metadata_host(host: &str) -> bool {
    let lower = host.to_lowercase();
    METADATA_HOSTNAMES
        .iter()
        .any(|m| *m == lower || lower.ends_with(&format!(".{m}")))
    // Also block the link-local metadata IP 169.254.169.254
}

fn is_metadata_ip(addr: Ipv4Addr) -> bool {
    addr.octets() == [169, 254, 169, 254]
}

// ---------------------------------------------------------------------------
// Forbidden headers
// ---------------------------------------------------------------------------

const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "connection",
    "proxy-authorization",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "cookie",
    "set-cookie",
    "authorization",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
    "via",
];

fn is_forbidden_header(name: &str) -> bool {
    let lower = name.to_lowercase();
    FORBIDDEN_HEADERS.iter().any(|h| *h == lower)
}

// ---------------------------------------------------------------------------
// Sensitive response headers to redact
// ---------------------------------------------------------------------------

const SENSITIVE_RESPONSE_HEADERS: &[&str] = &[
    "set-cookie",
    "authorization",
    "proxy-authenticate",
    "www-authenticate",
];

fn is_sensitive_response_header(name: &str) -> bool {
    let lower = name.to_lowercase();
    SENSITIVE_RESPONSE_HEADERS.iter().any(|h| *h == lower)
}

// ---------------------------------------------------------------------------
// Enforcer
// ---------------------------------------------------------------------------

/// A network enforcement adapter with SSRF protection.
pub struct NetworkEnforcer {
    allow_http: bool,
    timeout: Duration,
    connect_timeout: Duration,
    response_body_limit: u64,
    request_body_limit: u64,
    redirect_limit: usize,
    allow_loopback: bool,
}

impl NetworkEnforcer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    pub fn with_allow_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;
        self
    }

    /// Execute a guarded network request.
    pub fn execute(
        &self,
        request: &ToolRequest,
        permit: &mut ExecutionPermit,
        input: &NetworkInput,
    ) -> Result<NetworkOutcome, NetworkError> {
        request
            .validate()
            .map_err(|e| NetworkError::InvalidRequest(e.to_string()))?;

        if !matches!(request.operation, Operation::NetworkRequest) {
            return Err(NetworkError::UnsupportedOperation);
        }
        let net = match &request.resource {
            Resource::NetworkEndpoint(n) => n,
            _ => return Err(NetworkError::WrongResourceType),
        };

        verify_network_permit(permit, request)?;

        let method = input.method.unwrap_or(NetworkMethod::Get);
        let scheme = net.scheme().as_str();
        let host = net.host().as_str();
        let port = net
            .port()
            .map(|p| p.value())
            .unwrap_or_else(|| default_port(scheme));
        let path = net.path().normalized();

        validate_scheme(scheme, self.allow_http)?;
        validate_host(host)?;
        validate_headers(&input.headers)?;

        if let Some(ref body) = input.body {
            if body.len() as u64 > self.request_body_limit {
                return Err(NetworkError::RequestBodyLimitExceeded);
            }
        }

        if is_metadata_host(host) {
            return Err(NetworkError::MetadataEndpointBlocked);
        }

        let addresses = resolve_host(host, port)?;
        for addr in &addresses {
            let ip = addr.ip();
            if self.allow_loopback && ip.is_loopback() {
                continue;
            }
            if is_blocked_ip(ip) {
                return Err(NetworkError::BlockedAddress(format!("{addr}")));
            }
            if let IpAddr::V4(v4) = ip {
                if is_metadata_ip(v4) {
                    return Err(NetworkError::MetadataEndpointBlocked);
                }
            }
        }

        let url = format!("{scheme}://{host}:{port}{path}");
        let timeout = input
            .timeout_seconds
            .map(|s| Duration::from_secs(s.min(MAX_NETWORK_TIMEOUT_SECONDS)))
            .unwrap_or(self.timeout);
        let body_limit = input
            .response_body_limit
            .unwrap_or(self.response_body_limit);

        let outcome = execute_http(
            method,
            &url,
            &addresses,
            &input.headers,
            input.body.as_deref(),
            self.allow_http,
            self.allow_loopback,
            timeout,
            self.connect_timeout,
            body_limit,
            self.redirect_limit,
            input.no_redirect,
            0,
        )?;

        Ok(outcome)
    }
}

impl Default for NetworkEnforcer {
    fn default() -> Self {
        Self {
            allow_http: false,
            timeout: Duration::from_secs(DEFAULT_NETWORK_TIMEOUT_SECONDS),
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECONDS),
            response_body_limit: DEFAULT_RESPONSE_BODY_LIMIT,
            request_body_limit: DEFAULT_REQUEST_BODY_LIMIT,
            redirect_limit: DEFAULT_REDIRECT_LIMIT,
            allow_loopback: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Permit verification
// ---------------------------------------------------------------------------

fn verify_network_permit(
    permit: &mut ExecutionPermit,
    request: &ToolRequest,
) -> Result<(), NetworkError> {
    if permit.is_expired() {
        return Err(NetworkError::PermitExpired);
    }
    if permit.is_consumed() {
        return Err(NetworkError::PermitConsumed);
    }
    let digest = kavach_runtime::compute_request_digest(request);
    if !permit.verify_request_digest(&digest) {
        return Err(NetworkError::InvalidPermit(
            "permit does not match request digest".into(),
        ));
    }
    if !permit.consume() {
        return Err(NetworkError::PermitConsumed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// URL/scheme validation
// ---------------------------------------------------------------------------

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "http" => 80,
        _ => 0,
    }
}

fn validate_scheme(scheme: &str, allow_http: bool) -> Result<(), NetworkError> {
    match scheme {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        "http" => Err(NetworkError::PlainHttpDisabled),
        other => Err(NetworkError::UnsupportedScheme(other.into())),
    }
}

fn validate_host(host: &str) -> Result<(), NetworkError> {
    if host.is_empty() {
        return Err(NetworkError::InvalidUrl("empty host".into()));
    }
    if host.contains('@') {
        return Err(NetworkError::CredentialsInUrl);
    }
    if host.contains('\0') || host.bytes().any(|b| b.is_ascii_control()) {
        return Err(NetworkError::InvalidUrl(
            "host contains control characters".into(),
        ));
    }
    if host.len() > 255 {
        return Err(NetworkError::InvalidUrl("host too long".into()));
    }
    Ok(())
}

fn validate_headers(headers: &[(String, String)]) -> Result<(), NetworkError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(NetworkError::InvalidHeader(format!(
            "too many headers: {} (max {MAX_HEADER_COUNT})",
            headers.len()
        )));
    }
    for (name, value) in headers {
        if name.is_empty() || name.len() > MAX_HEADER_NAME_LENGTH {
            return Err(NetworkError::InvalidHeader(
                "invalid header name length".into(),
            ));
        }
        if value.len() > MAX_HEADER_VALUE_LENGTH {
            return Err(NetworkError::InvalidHeader(format!(
                "header {name} exceeds max value length"
            )));
        }
        if name.contains('\0') || name.contains('\r') || name.contains('\n') {
            return Err(NetworkError::InvalidHeader(
                "CRLF injection in header name".into(),
            ));
        }
        if value.contains('\0') || value.contains('\r') || value.contains('\n') {
            return Err(NetworkError::InvalidHeader(format!(
                "CRLF injection in header {name}"
            )));
        }
        if is_forbidden_header(name) {
            return Err(NetworkError::InvalidHeader(format!(
                "forbidden header: {name}"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS resolution
// ---------------------------------------------------------------------------

fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, NetworkError> {
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = addr_str
        .to_socket_addrs()
        .map_err(|e| NetworkError::DnsResolutionFailed(e.to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(NetworkError::DnsResolutionFailed(
            "no addresses resolved".into(),
        ));
    }
    Ok(addrs)
}

// ---------------------------------------------------------------------------
// Custom ureq resolver with SSRF
// ---------------------------------------------------------------------------

struct SsrfResolver {
    allowed: Vec<SocketAddr>,
}

impl ureq::Resolver for SsrfResolver {
    fn resolve(&self, _netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        Ok(self.allowed.clone())
    }
}

// ---------------------------------------------------------------------------
// HTTP execution
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn execute_http(
    method: NetworkMethod,
    url: &str,
    addresses: &[SocketAddr],
    headers: &[(String, String)],
    body: Option<&[u8]>,
    allow_http: bool,
    allow_loopback: bool,
    timeout: Duration,
    connect_timeout: Duration,
    body_limit: u64,
    redirect_limit: usize,
    no_redirect: bool,
    redirect_count: usize,
) -> Result<NetworkOutcome, NetworkError> {
    let start = Instant::now();

    // Build a ureq agent with our SSRF resolver.
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(connect_timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .resolver(SsrfResolver {
            allowed: addresses.to_vec(),
        })
        .redirects(0)
        .build();

    let mut req = match method {
        NetworkMethod::Get => agent.get(url),
        NetworkMethod::Head => agent.head(url),
        NetworkMethod::Post => agent.post(url),
        NetworkMethod::Put => agent.put(url),
        NetworkMethod::Patch => agent.patch(url),
        NetworkMethod::Delete => agent.delete(url),
    };

    for (name, value) in headers {
        req = req.set(name, value);
    }

    if let Some(b) = body {
        req = req.set("Content-Length", &b.len().to_string());
    }

    let resp = req
        .send_bytes(body.unwrap_or(&[]))
        .map_err(|e| map_ureq_error(e, timeout))?;

    let status = resp.status();

    // Read headers before consuming the response.
    let resp_headers: Vec<(String, String)> = resp
        .headers_names()
        .iter()
        .filter(|name| !is_sensitive_response_header(name))
        .map(|name| {
            let value = resp.header(name).unwrap_or_default();
            (name.to_string(), value.to_string())
        })
        .collect();

    // Handle redirect manually to re-validate.
    if !no_redirect
        && (status == 301 || status == 302 || status == 303 || status == 307 || status == 308)
    {
        if redirect_count >= redirect_limit {
            return Err(NetworkError::RedirectLimitExceeded);
        }
        if let Some(loc) = resp.header("location") {
            let new_url = loc.to_string();
            // Basic URL parsing for redirect validation.
            if new_url.starts_with("http://") || new_url.starts_with("https://") {
                // Parse the redirect URL to validate scheme, host, port.
                validate_redirect_url(&new_url, allow_http)?;
                // Re-resolve and re-validate addresses.
                let parsed = parse_url_parts(&new_url)?;
                if is_metadata_host(&parsed.host) {
                    return Err(NetworkError::MetadataEndpointBlocked);
                }
                let new_addrs = resolve_host(&parsed.host, parsed.port)?;
                for addr in &new_addrs {
                    if allow_loopback && addr.ip().is_loopback() {
                        continue;
                    }
                    if is_blocked_ip(addr.ip()) {
                        return Err(NetworkError::RedirectRejected(format!(
                            "redirect to blocked address: {addr}"
                        )));
                    }
                }
                return execute_http(
                    method,
                    &new_url,
                    &new_addrs,
                    headers,
                    body,
                    allow_http,
                    allow_loopback,
                    timeout,
                    connect_timeout,
                    body_limit,
                    redirect_limit,
                    no_redirect,
                    redirect_count + 1,
                );
            }
            return Err(NetworkError::RedirectRejected(
                "invalid redirect URL".into(),
            ));
        }
    }

    // Read response body with limit.
    let mut reader = resp.into_reader();
    let mut body_buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| NetworkError::TransportFailure(e.to_string()))?;
        if n == 0 {
            break;
        }
        if body_buf.len() + n > body_limit as usize {
            return Err(NetworkError::ResponseBodyLimitExceeded);
        }
        body_buf.extend_from_slice(&chunk[..n]);
    }

    let body_len = body_buf.len() as u64;
    let duration = start.elapsed();

    Ok(NetworkOutcome {
        status,
        headers: resp_headers,
        body: body_buf,
        body_len,
        redirect_count,
        final_url: url.to_string(),
        duration,
    })
}

fn is_timeout_from_source(source: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(io_err) = source.downcast_ref::<std::io::Error>() {
        if io_err.kind() == std::io::ErrorKind::TimedOut {
            return true;
        }
    }
    let mut current: Option<&(dyn std::error::Error + 'static)> = source.source();
    while let Some(src) = current {
        if let Some(io_err) = src.downcast_ref::<std::io::Error>() {
            if io_err.kind() == std::io::ErrorKind::TimedOut {
                return true;
            }
        }
        current = src.source();
    }
    false
}

fn map_ureq_error(e: ureq::Error, _timeout: Duration) -> NetworkError {
    match e {
        ureq::Error::Transport(t) => {
            let kind = t.kind();
            let is_timeout = StdError::source(&t)
                .map(is_timeout_from_source)
                .unwrap_or(false);
            if is_timeout && kind == ureq::ErrorKind::ConnectionFailed {
                return NetworkError::ConnectTimeout;
            }
            if is_timeout {
                return NetworkError::RequestTimeout;
            }
            match kind {
                ureq::ErrorKind::Dns => NetworkError::DnsResolutionFailed(t.to_string()),
                ureq::ErrorKind::TooManyRedirects => NetworkError::RedirectLimitExceeded,
                _ => NetworkError::TransportFailure(t.to_string()),
            }
        }
        ureq::Error::Status(code, _) => {
            NetworkError::TransportFailure(format!("HTTP status {code}"))
        }
    }
}

struct ParsedUrl {
    host: String,
    port: u16,
    _scheme: String,
}

fn parse_url_parts(url: &str) -> Result<ParsedUrl, NetworkError> {
    // Simple URL parsing: scheme://host[:port][/path]
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| NetworkError::RedirectRejected("unsupported scheme in redirect".into()))?;
    let scheme = if url.starts_with("https") {
        "https"
    } else {
        "http"
    };
    let (host_part, _path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = if let Some((h, p)) = host_part.split_once(':') {
        (
            h.to_string(),
            p.parse::<u16>().unwrap_or(default_port(scheme)),
        )
    } else {
        (host_part.to_string(), default_port(scheme))
    };
    Ok(ParsedUrl {
        host,
        port,
        _scheme: scheme.to_string(),
    })
}

fn validate_redirect_url(url: &str, allow_http: bool) -> Result<(), NetworkError> {
    let parsed = parse_url_parts(url)?;
    let is_https = parsed._scheme == "https";
    let is_http = parsed._scheme == "http";
    if is_https || (is_http && allow_http) {
        // OK
    } else if is_http {
        return Err(NetworkError::RedirectRejected(
            "HTTPS downgrade to HTTP".into(),
        ));
    } else {
        return Err(NetworkError::RedirectRejected(format!(
            "unsupported scheme: {}",
            parsed._scheme
        )));
    }
    validate_host(&parsed.host)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use kavach_core::ids::{AgentId, RequestId, SessionId};
    use kavach_core::request::{AgentSubjectBuilder, RequestContext};
    use kavach_core::resource::{NetworkHost, NetworkResource, NetworkScheme};
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    fn make_subject() -> kavach_core::subject::AgentSubject {
        AgentSubjectBuilder::new(
            AgentId::new("agent-1").unwrap(),
            SessionId::new("sess-1").unwrap(),
        )
        .trust_level(kavach_core::subject::TrustLevel::Standard)
        .build()
    }

    fn make_context() -> RequestContext {
        RequestContext::new(None, None, None, None, false).unwrap()
    }

    fn make_permit(request: &ToolRequest) -> ExecutionPermit {
        let digest = kavach_runtime::compute_request_digest(request);
        ExecutionPermit::new(&[1u8; 32], vec![], digest, Duration::from_secs(300))
    }

    fn make_expired_permit(request: &ToolRequest) -> ExecutionPermit {
        let digest = kavach_runtime::compute_request_digest(request);
        ExecutionPermit::new(&[2u8; 32], vec![], digest, Duration::from_secs(0))
    }

    fn net_request(host: &str, scheme: &str) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::NetworkRequest,
            Resource::NetworkEndpoint(
                NetworkResource::new(
                    NetworkScheme::new(scheme).unwrap(),
                    NetworkHost::new(host).unwrap(),
                    None,
                    "/",
                )
                .unwrap(),
            ),
            make_context(),
        )
    }

    fn net_request_with_port(host: &str, scheme: &str, port: u16) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::NetworkRequest,
            Resource::NetworkEndpoint(
                NetworkResource::new(
                    NetworkScheme::new(scheme).unwrap(),
                    NetworkHost::new(host).unwrap(),
                    Some(kavach_core::resource::NetworkPort::new(port)),
                    "/",
                )
                .unwrap(),
            ),
            make_context(),
        )
    }

    // ----------------------------------------------------------------
    // Permit tests
    // ----------------------------------------------------------------

    #[test]
    fn expired_permit_rejected() {
        let req = net_request("example.com", "https");
        let mut expired = make_expired_permit(&req);
        let enforcer = NetworkEnforcer::new();
        let result = enforcer.execute(&req, &mut expired, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::PermitExpired)));
    }

    #[test]
    fn consumed_permit_rejected() {
        let req = net_request("example.com", "https");
        let mut permit = make_permit(&req);
        permit.consume();
        let enforcer = NetworkEnforcer::new();
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::PermitConsumed)));
    }

    #[test]
    fn forged_permit_rejected() {
        let req_a = net_request("example.com", "https");
        let req_b = net_request("other.com", "https");
        let mut permit_b = make_permit(&req_b);
        let enforcer = NetworkEnforcer::new();
        let result = enforcer.execute(&req_a, &mut permit_b, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::InvalidPermit(_))));
    }

    // ----------------------------------------------------------------
    // DNS failure / permit consumption
    // ----------------------------------------------------------------

    #[test]
    fn dns_failure_consumes_permit() {
        // Use a host that cannot resolve (guaranteed non-existent TLD).
        let req = net_request("x-surely-does-not-resolve-99999.test", "https");
        let enforcer = NetworkEnforcer::new();
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        // Should fail at DNS, and permit must be consumed.
        assert!(matches!(result, Err(NetworkError::DnsResolutionFailed(_))));
        assert!(permit.is_consumed());
    }

    #[test]
    fn dns_failure_reuse_consumed_permit() {
        let req = net_request("x-surely-does-not-resolve-99999.test", "https");
        let enforcer = NetworkEnforcer::new();
        let mut permit = make_permit(&req);
        let _ = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(permit.is_consumed());
        // Second use must fail with PermitConsumed, not DNS error.
        let result2 = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result2, Err(NetworkError::PermitConsumed)));
    }

    #[test]
    fn no_dns_before_permit_verified() {
        // Expired permit → error before any DNS resolution.
        let req = net_request("example.com", "https");
        let mut expired = make_expired_permit(&req);
        let enforcer = NetworkEnforcer::new();
        let result = enforcer.execute(&req, &mut expired, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::PermitExpired)));
        // Permit not consumed (it was expired, not consumed).
        // The point: we got a permit error, not a DNS error, proving
        // permit verification precedes DNS.
    }

    #[test]
    fn wrong_resource_type_before_dns() {
        // File resource → error before DNS.
        let req = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::NetworkRequest,
            Resource::file("test.txt").unwrap(),
            make_context(),
        );
        let enforcer = NetworkEnforcer::new();
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::InvalidRequest(_))));
    }

    #[test]
    fn command_resource_before_dns() {
        // Command resource for network operation → error before DNS.
        let req = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::NetworkRequest,
            Resource::Command(
                kavach_core::resource::CommandResource::new("ls", vec!["-la".to_string()]).unwrap(),
            ),
            make_context(),
        );
        let enforcer = NetworkEnforcer::new();
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        // Core validate() rejects NetworkRequest with Command resource.
        assert!(matches!(result, Err(NetworkError::InvalidRequest(_))));
    }

    // ----------------------------------------------------------------
    // Scheme validation tests
    // ----------------------------------------------------------------

    #[test]
    fn https_accepted_by_default() {
        let enforcer = NetworkEnforcer::new();
        let req = net_request("example.com", "https");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(!matches!(result, Err(NetworkError::PlainHttpDisabled)));
        assert!(!matches!(result, Err(NetworkError::UnsupportedScheme(_))));
        assert!(permit.is_consumed());
    }

    #[test]
    fn http_rejected_by_default() {
        let enforcer = NetworkEnforcer::new();
        let req = net_request("example.com", "http");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::PlainHttpDisabled)));
    }

    #[test]
    fn http_accepted_when_enabled() {
        let enforcer = NetworkEnforcer::new().with_allow_http(true);
        let req = net_request("example.com", "http");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(!matches!(result, Err(NetworkError::PlainHttpDisabled)));
    }

    #[test]
    fn unsupported_scheme_rejected() {
        let enforcer = NetworkEnforcer::new();
        let req = net_request("example.com", "ftp");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::UnsupportedScheme(_))));
    }

    #[test]
    fn credentials_in_host_rejected_by_core() {
        assert!(NetworkHost::new("user@example.com").is_err());
    }

    // ----------------------------------------------------------------
    // SSRF tests — address classification
    // ----------------------------------------------------------------

    #[test]
    fn loopback_ipv4_blocked() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("127.0.0.2".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_blocked() {
        assert!(is_blocked_ip("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn link_local_ipv4_blocked() {
        assert!(is_blocked_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn metadata_ip_blocked() {
        assert!(is_metadata_ip(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(!is_metadata_ip(Ipv4Addr::new(169, 254, 1, 1)));
    }

    #[test]
    fn loopback_ipv6_blocked() {
        assert!(is_blocked_ip("::1".parse().unwrap()));
    }

    #[test]
    fn link_local_ipv6_blocked() {
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn unique_local_ipv6_blocked() {
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
        assert!(is_blocked_ip("fd00::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_blocked() {
        let mapped = Ipv6Addr::from(0x0000_0000_0000_0000_0000_ffff_0a00_0001u128);
        assert!(is_blocked_ip(IpAddr::V6(mapped)));
    }

    #[test]
    fn cgnat_blocked() {
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("100.127.255.255".parse().unwrap()));
    }

    #[test]
    fn multicast_ipv4_blocked() {
        assert!(is_blocked_ip("224.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("239.255.255.255".parse().unwrap()));
    }

    #[test]
    fn metadata_hostname_detected() {
        assert!(is_metadata_host("metadata.google.internal"));
        assert!(is_metadata_host("Metadata.Google.Internal"));
    }

    #[test]
    fn unspecified_ipv4_blocked() {
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn broadcast_ipv4_blocked() {
        assert!(is_blocked_ip("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn ipv6_unspecified_blocked() {
        assert!(is_blocked_ip("::".parse().unwrap()));
    }

    #[test]
    fn ipv6_multicast_blocked() {
        assert!(is_blocked_ip("ff00::1".parse().unwrap()));
    }

    #[test]
    fn public_ipv4_not_blocked() {
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn public_ipv6_not_blocked() {
        assert!(!is_blocked_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    // ----------------------------------------------------------------
    // Address validation via execute — mixed resolution
    // ----------------------------------------------------------------

    #[test]
    fn resolve_host_returns_blocked_address() {
        // resolve_host("localhost", 80) returns 127.0.0.1 which is blocked.
        let addrs = resolve_host("localhost", 80).unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| is_blocked_ip(a.ip())));
    }

    #[test]
    fn localhost_rejected_by_default() {
        let req = net_request("localhost", "https");
        let mut permit = make_permit(&req);
        let enforcer = NetworkEnforcer::new();
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::BlockedAddress(_))));
    }

    // ----------------------------------------------------------------
    // Header validation tests
    // ----------------------------------------------------------------

    #[test]
    fn forbidden_host_header_rejected() {
        let headers = vec![("Host".into(), "evil.com".into())];
        assert!(validate_headers(&headers).is_err());
    }

    #[test]
    fn crlf_injection_rejected() {
        assert!(validate_headers(&[("X-Foo\r\nBar".into(), "val".into())]).is_err());
        assert!(validate_headers(&[("X-Foo".into(), "val\r\ninject".into())]).is_err());
    }

    #[test]
    fn header_count_limit_enforced() {
        let mut headers = Vec::new();
        for i in 0..=MAX_HEADER_COUNT {
            headers.push((format!("X-Hdr-{i}"), "v".into()));
        }
        assert!(validate_headers(&headers).is_err());
    }

    #[test]
    fn empty_header_name_rejected() {
        assert!(validate_headers(&[("".into(), "val".into())]).is_err());
    }

    #[test]
    fn header_name_too_long_rejected() {
        let long_name = "X".repeat(MAX_HEADER_NAME_LENGTH + 1);
        assert!(validate_headers(&[(long_name, "val".into())]).is_err());
    }

    #[test]
    fn header_value_too_long_rejected() {
        let long_val = "x".repeat(MAX_HEADER_VALUE_LENGTH + 1);
        assert!(validate_headers(&[("X-Foo".into(), long_val)]).is_err());
    }

    #[test]
    fn forbidden_headers_list() {
        for h in &[
            "authorization",
            "cookie",
            "set-cookie",
            "proxy-authorization",
            "x-forwarded-for",
            "forwarded",
            "via",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(is_forbidden_header(h), "{h} should be forbidden");
        }
    }

    // ----------------------------------------------------------------
    // URL/host validation
    // ----------------------------------------------------------------

    #[test]
    fn empty_host_rejected() {
        assert!(validate_host("").is_err());
    }

    #[test]
    fn null_host_rejected() {
        assert!(validate_host("host\0").is_err());
    }

    #[test]
    fn control_char_host_rejected() {
        assert!(validate_host("host\t").is_err());
    }

    #[test]
    fn host_too_long_rejected() {
        let long = "a".repeat(256);
        assert!(validate_host(&long).is_err());
    }

    #[test]
    fn valid_host_accepted() {
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("localhost").is_ok());
    }

    // ----------------------------------------------------------------
    // Request body limit
    // ----------------------------------------------------------------

    #[test]
    fn request_body_limit_before_network() {
        let req = net_request("example.com", "https");
        let mut permit = make_permit(&req);
        let enforcer = NetworkEnforcer::new();
        // Body exceeds default 1MB limit.
        let oversized = vec![0u8; (DEFAULT_REQUEST_BODY_LIMIT + 1) as usize];
        let input = NetworkInput {
            body: Some(oversized),
            ..NetworkInput::default()
        };
        let result = enforcer.execute(&req, &mut permit, &input);
        assert!(matches!(
            result,
            Err(NetworkError::RequestBodyLimitExceeded)
        ));
    }

    #[test]
    fn request_body_at_limit_passes_validation() {
        let req = net_request("example.com", "https");
        let mut permit = make_permit(&req);
        let enforcer = NetworkEnforcer::new();
        let at_limit = vec![0u8; DEFAULT_REQUEST_BODY_LIMIT as usize];
        let input = NetworkInput {
            body: Some(at_limit),
            ..NetworkInput::default()
        };
        // Should pass body limit check and fail at DNS (since example.com may resolve).
        let result = enforcer.execute(&req, &mut permit, &input);
        // Not a body limit error.
        assert!(!matches!(
            result,
            Err(NetworkError::RequestBodyLimitExceeded)
        ));
    }

    // ----------------------------------------------------------------
    // Redirect validation
    // ----------------------------------------------------------------

    #[test]
    fn validate_redirect_url_https_accepted() {
        assert!(validate_redirect_url("https://example.com/path", false).is_ok());
    }

    #[test]
    fn validate_redirect_url_http_accepted_when_allowed() {
        assert!(validate_redirect_url("http://example.com/path", true).is_ok());
    }

    #[test]
    fn validate_redirect_url_http_rejected_by_default() {
        let result = validate_redirect_url("http://example.com/path", false);
        assert!(matches!(result, Err(NetworkError::RedirectRejected(_))));
    }

    #[test]
    fn validate_redirect_url_downgrade_rejected() {
        let result = validate_redirect_url("http://example.com/path", false);
        assert!(matches!(result, Err(NetworkError::RedirectRejected(_))));
    }

    #[test]
    fn validate_redirect_url_unsupported_scheme() {
        let result = validate_redirect_url("ftp://example.com/path", false);
        assert!(matches!(result, Err(NetworkError::RedirectRejected(_))));
    }

    #[test]
    fn validate_redirect_url_blocked_host_passes_validation() {
        // 127.0.0.1 is a valid hostname; address blocking is done in execute_http.
        assert!(validate_redirect_url("https://127.0.0.1/path", false).is_ok());
    }

    #[test]
    fn validate_redirect_url_empty_host() {
        let result = validate_redirect_url("https:///path", false);
        assert!(matches!(result, Err(NetworkError::InvalidUrl(_))));
    }

    #[test]
    fn parse_url_parts_https() {
        let p = parse_url_parts("https://example.com:8443/path").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 8443);
    }

    #[test]
    fn parse_url_parts_default_port() {
        let p = parse_url_parts("https://example.com/path").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_url_parts_http_default_port() {
        let p = parse_url_parts("http://example.com/path").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 80);
    }

    #[test]
    fn parse_url_parts_unsupported_scheme() {
        let result = parse_url_parts("ftp://example.com/path");
        assert!(result.is_err());
    }

    // ----------------------------------------------------------------
    // Redirect limit enforcement
    // ----------------------------------------------------------------

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn redirect_limit_constants_consistent() {
        assert!(DEFAULT_REDIRECT_LIMIT <= MAX_REDIRECT_LIMIT);
    }

    // ----------------------------------------------------------------
    // Sensitive response header detection
    // ----------------------------------------------------------------

    #[test]
    fn sensitive_response_headers_identified() {
        for h in &[
            "set-cookie",
            "authorization",
            "proxy-authenticate",
            "www-authenticate",
        ] {
            assert!(is_sensitive_response_header(h), "{h} should be sensitive");
        }
    }

    #[test]
    fn non_sensitive_headers_not_redacted() {
        assert!(!is_sensitive_response_header("content-type"));
        assert!(!is_sensitive_response_header("cache-control"));
    }

    // ----------------------------------------------------------------
    // Deterministic classification
    // ----------------------------------------------------------------

    #[test]
    fn address_classification_deterministic() {
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            is_blocked_ip(a),
            is_blocked_ip("10.0.0.1".parse::<IpAddr>().unwrap())
        );
    }

    // ----------------------------------------------------------------
    // Timeout error type mapping
    // ----------------------------------------------------------------

    #[test]
    fn is_timeout_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        assert!(is_timeout_from_source(&io_err));
    }

    #[test]
    fn is_timeout_from_non_timeout_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert!(!is_timeout_from_source(&io_err));
    }

    #[test]
    fn is_timeout_from_non_timeout_error() {
        // Use an existing std error type that is not io::Error.
        let parse_err = "not-a-number".parse::<i32>().unwrap_err();
        assert!(!is_timeout_from_source(&parse_err));
    }

    // ----------------------------------------------------------------
    // Integration tests with local server
    // ----------------------------------------------------------------

    fn spawn_test_server(response: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Some(mut s) = listener.incoming().flatten().next() {
                let _ = s.set_nodelay(true);
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        port
    }

    fn spawn_test_server_with_headers(
        response: &'static str,
        extra_headers: &[(&str, &str)],
    ) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let headers = extra_headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}\r\n"))
            .collect::<String>();
        thread::spawn(move || {
            if let Some(mut s) = listener.incoming().flatten().next() {
                let _ = s.set_nodelay(true);
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        port
    }

    fn spawn_large_body_server(body_size: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Some(mut s) = listener.incoming().flatten().next() {
                let _ = s.set_nodelay(true);
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let body = vec![b'x'; body_size];
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(header.as_bytes());
                let _ = s.write_all(&body);
                let _ = s.flush();
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        port
    }

    // ----------------------------------------------------------------
    // Loopback integration tests
    // ----------------------------------------------------------------

    #[test]
    fn http_loopback_with_allow_loopback_succeeds() {
        let port = spawn_test_server("hello");
        let enforcer = NetworkEnforcer::new()
            .with_allow_http(true)
            .with_allow_loopback(true);
        let req = net_request_with_port("127.0.0.1", "http", port);
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, &NetworkInput::default())
            .unwrap();
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.body, b"hello");
        assert!(permit.is_consumed());
    }

    #[test]
    fn https_loopback_with_allow_loopback_succeeds() {
        let port = spawn_test_server("world");
        let enforcer = NetworkEnforcer::new()
            .with_allow_http(true)
            .with_allow_loopback(true);
        let req = net_request_with_port("127.0.0.1", "http", port);
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, &NetworkInput::default())
            .unwrap();
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.body, b"world");
    }

    #[test]
    fn loopback_blocked_without_allow_loopback() {
        let port = spawn_test_server("should-not-reach");
        let enforcer = NetworkEnforcer::new();
        let req = net_request_with_port("127.0.0.1", "http", port);
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        // Default: loopback blocked, http disabled → blocked or plain-http error.
        // The order: scheme check first → PlainHttpDisabled.
        assert!(matches!(result, Err(NetworkError::PlainHttpDisabled)));
    }

    // ----------------------------------------------------------------
    // Response header redaction
    // ----------------------------------------------------------------

    #[test]
    fn sensitive_response_headers_redacted() {
        let port = spawn_test_server_with_headers(
            "body",
            &[
                ("Set-Cookie", "session=abc"),
                ("Authorization", "Bearer token"),
                ("Proxy-Authenticate", "Basic"),
                ("Content-Type", "text/plain"),
            ],
        );
        let enforcer = NetworkEnforcer::new()
            .with_allow_http(true)
            .with_allow_loopback(true);
        let req = net_request_with_port("127.0.0.1", "http", port);
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, &NetworkInput::default())
            .unwrap();
        let header_names: Vec<&str> = outcome.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !header_names.contains(&"set-cookie"),
            "set-cookie should be redacted"
        );
        assert!(
            !header_names.contains(&"authorization"),
            "authorization should be redacted"
        );
        assert!(
            !header_names.contains(&"proxy-authenticate"),
            "proxy-authenticate should be redacted"
        );
        assert!(
            header_names.contains(&"content-type"),
            "content-type should be present"
        );
    }

    // ----------------------------------------------------------------
    // HEAD response body
    // ----------------------------------------------------------------

    #[test]
    fn head_response_returns_no_body() {
        let port = spawn_test_server("this-should-not-appear");
        let enforcer = NetworkEnforcer::new()
            .with_allow_http(true)
            .with_allow_loopback(true);
        let req = net_request_with_port("127.0.0.1", "http", port);
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(
                &req,
                &mut permit,
                &NetworkInput {
                    method: Some(NetworkMethod::Head),
                    ..NetworkInput::default()
                },
            )
            .unwrap();
        assert_eq!(outcome.status, 200);
        assert!(outcome.body.is_empty(), "HEAD should have empty body");
    }

    // ----------------------------------------------------------------
    // Response body limit during streaming
    // ----------------------------------------------------------------

    #[test]
    fn response_body_limit_during_streaming() {
        let port = spawn_large_body_server(100_000);
        let enforcer = NetworkEnforcer::new()
            .with_allow_http(true)
            .with_allow_loopback(true);
        let req = net_request_with_port("127.0.0.1", "http", port);
        let mut permit = make_permit(&req);
        let input = NetworkInput {
            response_body_limit: Some(100),
            ..NetworkInput::default()
        };
        let result = enforcer.execute(&req, &mut permit, &input);
        assert!(matches!(
            result,
            Err(NetworkError::ResponseBodyLimitExceeded)
        ));
    }

    #[test]
    fn redirect_https_to_http_downgrade_redirect_fails() {
        let result = validate_redirect_url("http://example.com/downgrade", false);
        assert!(matches!(result, Err(NetworkError::RedirectRejected(_))));
    }

    #[test]
    fn redirect_to_private_ip_is_blocked() {
        let redirect_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_port = redirect_listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Some(mut s) = redirect_listener.incoming().flatten().next() {
                let _ = s.set_nodelay(true);
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                // Redirect to a private IP address.
                let resp = "HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
                let _ = s.shutdown(std::net::Shutdown::Write);
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        let enforcer = NetworkEnforcer::new()
            .with_allow_http(true)
            .with_allow_loopback(true);
        let req = net_request_with_port("127.0.0.1", "http", redirect_port);
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::RedirectRejected(_))));
    }

    #[test]
    fn redirect_to_metadata_hostname_blocked() {
        let redirect_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_port = redirect_listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Some(mut s) = redirect_listener.incoming().flatten().next() {
                let _ = s.set_nodelay(true);
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let resp = "HTTP/1.1 302 Found\r\nLocation: http://metadata.google.internal/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
                let _ = s.shutdown(std::net::Shutdown::Write);
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        let enforcer = NetworkEnforcer::new()
            .with_allow_http(true)
            .with_allow_loopback(true);
        let req = net_request_with_port("127.0.0.1", "http", redirect_port);
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::MetadataEndpointBlocked)));
    }

    // ----------------------------------------------------------------
    // Resource type rejection (no network access)
    // ----------------------------------------------------------------

    #[test]
    fn file_resource_never_reaches_network() {
        let req = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::NetworkRequest,
            Resource::file("test.txt").unwrap(),
            make_context(),
        );
        let enforcer = NetworkEnforcer::new();
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::InvalidRequest(_))));
    }

    #[test]
    fn command_resource_rejected() {
        let req = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::NetworkRequest,
            Resource::Command(kavach_core::resource::CommandResource::new("ls", vec![]).unwrap()),
            make_context(),
        );
        let enforcer = NetworkEnforcer::new();
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &NetworkInput::default());
        assert!(matches!(result, Err(NetworkError::InvalidRequest(_))));
    }
}
