//! MCP request/response proxy with KavachRuntime policy enforcement.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use kavach_core::Operation;
use kavach_core::ids::{AgentId, RequestId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use kavach_redaction::Redactor;
use kavach_runtime::outcome::RuntimeOutcome;
use kavach_runtime::runtime::KavachRuntime;

use crate::protocol;
use crate::protocol::JsonRpcMessage;
use crate::transport::McpTransport;

/// The MCP proxy configuration.
pub struct McpProxyConfig {
    /// Command to spawn the MCP server process.
    pub server_command: String,
    /// Arguments for the MCP server command.
    pub server_args: Vec<String>,
    /// Timeout for individual MCP requests forwarded to the server.
    pub request_timeout: Duration,
    /// Agent ID to use for KavachRuntime evaluation.
    pub agent_id: String,
    /// Session ID to use for KavachRuntime evaluation.
    pub session_id: String,
}

impl Default for McpProxyConfig {
    fn default() -> Self {
        Self {
            server_command: String::new(),
            server_args: Vec::new(),
            request_timeout: Duration::from_secs(30),
            agent_id: "mcp-proxy".into(),
            session_id: "mcp-session".into(),
        }
    }
}

/// The MCP security proxy.
pub struct McpProxy {
    config: McpProxyConfig,
    runtime: Arc<KavachRuntime>,
    server_transport: McpTransport,
    _server_process: Option<std::process::Child>,
    tools: HashMap<String, protocol::Tool>,
    initialized: bool,
}

impl McpProxy {
    /// Spawn the MCP server subprocess and create a proxy connected to it.
    pub fn spawn(config: McpProxyConfig, runtime: Arc<KavachRuntime>) -> Result<Self, String> {
        let (server_transport, server_process) =
            McpTransport::spawn_server(&config.server_command, &config.server_args)
                .map_err(|e| format!("failed to spawn MCP server: {e}"))?;

        Ok(Self {
            config,
            runtime,
            server_transport,
            _server_process: Some(server_process),
            tools: HashMap::new(),
            initialized: false,
        })
    }

    /// Get the mutable server transport for direct I/O.
    pub fn server_transport(&mut self) -> &mut McpTransport {
        &mut self.server_transport
    }

    /// Handle a single JSON-RPC message from the client.
    /// Returns the raw response string to send back, or `None` for notifications.
    pub fn handle_message(&mut self, msg: &JsonRpcMessage) -> Result<Option<String>, String> {
        match msg {
            JsonRpcMessage::Request(req) => self.handle_request(req),
            JsonRpcMessage::Notification(notif) => {
                self.handle_notification(notif)?;
                Ok(None)
            }
            JsonRpcMessage::Response(_) | JsonRpcMessage::Error(_) => {
                Err("unexpected response from client".into())
            }
        }
    }

    fn handle_request(&mut self, req: &protocol::JsonRpcRequest) -> Result<Option<String>, String> {
        match req.method.as_str() {
            "initialize" => self.handle_initialize(req),
            "ping" => self.forward_and_receive(req),
            "tools/list" => self.handle_tools_list(req),
            "tools/call" => self.handle_tool_call(req),
            _ => self.forward_and_receive(req),
        }
    }

    fn handle_notification(&mut self, notif: &protocol::JsonRpcNotification) -> Result<(), String> {
        let msg = JsonRpcMessage::Notification(notif.clone());
        self.server_transport.send(&msg)
    }

    fn handle_initialize(
        &mut self,
        req: &protocol::JsonRpcRequest,
    ) -> Result<Option<String>, String> {
        self.forward(req)?;
        match self.server_transport.receive()? {
            JsonRpcMessage::Response(resp) => {
                if let Ok(init_result) =
                    serde_json::from_value::<protocol::InitializeResult>(resp.result.clone())
                {
                    self.initialized = init_result.capabilities.tools.is_some();
                }
                Ok(Some(protocol::make_response(
                    req.id.clone(),
                    redact_response(resp.result),
                )))
            }
            JsonRpcMessage::Error(err) => Ok(Some(protocol::make_error(
                Some(req.id.clone()),
                err.error.code,
                &redact_text(&err.error.message),
            ))),
            _ => Err("unexpected response during initialize".into()),
        }
    }

    fn handle_tools_list(
        &mut self,
        req: &protocol::JsonRpcRequest,
    ) -> Result<Option<String>, String> {
        self.forward(req)?;
        match self.server_transport.receive()? {
            JsonRpcMessage::Response(resp) => {
                if let Some(tools_array) = resp.result.get("tools").and_then(|v| v.as_array()) {
                    for tool_val in tools_array {
                        if let Ok(tool) = serde_json::from_value::<protocol::Tool>(tool_val.clone())
                        {
                            self.tools.insert(tool.name.clone(), tool);
                        }
                    }
                }
                Ok(Some(protocol::make_response(
                    req.id.clone(),
                    redact_response(resp.result),
                )))
            }
            JsonRpcMessage::Error(err) => Ok(Some(protocol::make_error(
                Some(req.id.clone()),
                err.error.code,
                &redact_text(&err.error.message),
            ))),
            _ => Err("unexpected response during tools/list".into()),
        }
    }

    fn handle_tool_call(
        &mut self,
        req: &protocol::JsonRpcRequest,
    ) -> Result<Option<String>, String> {
        let params = req.params.as_ref().ok_or_else(|| {
            protocol::make_error(
                Some(req.id.clone()),
                protocol::INVALID_PARAMS,
                "missing params",
            )
        })?;

        let call_params: protocol::CallToolRequestParams = serde_json::from_value(params.clone())
            .map_err(|e| {
            protocol::make_error(
                Some(req.id.clone()),
                protocol::INVALID_PARAMS,
                &format!("invalid params: {e}"),
            )
        })?;

        let tool_name = &call_params.name;
        if !self.tools.contains_key(tool_name) {
            return Ok(Some(protocol::make_error(
                Some(req.id.clone()),
                protocol::KAVACH_TOOL_NOT_FOUND,
                &format!("tool not found: {tool_name}"),
            )));
        }

        let tool_request = build_tool_request(tool_name, &call_params.arguments, &self.config)?;

        let outcome = self.runtime.evaluate(&tool_request).map_err(|e| {
            protocol::make_error(
                Some(req.id.clone()),
                protocol::KAVACH_INTERNAL,
                &format!("evaluation failed: {e}"),
            )
        })?;

        match outcome {
            RuntimeOutcome::Denied {
                sanitized_summary, ..
            } => {
                tracing::warn!(tool = %tool_name, "denied: {sanitized_summary}");
                return Ok(Some(protocol::make_error(
                    Some(req.id.clone()),
                    protocol::KAVACH_DENIED,
                    &sanitized_summary,
                )));
            }
            RuntimeOutcome::ApprovalRequired {
                sanitized_summary, ..
            } => {
                tracing::warn!(tool = %tool_name, "approval required: {sanitized_summary}");
                return Ok(Some(protocol::make_error(
                    Some(req.id.clone()),
                    protocol::KAVACH_APPROVAL_REQUIRED,
                    &sanitized_summary,
                )));
            }
            RuntimeOutcome::Permitted(_) => {}
        }

        self.forward(req)?;
        match self.server_transport.receive()? {
            JsonRpcMessage::Response(resp) => {
                let redacted = redact_response(resp.result);
                Ok(Some(protocol::make_response(req.id.clone(), redacted)))
            }
            JsonRpcMessage::Error(err) => Ok(Some(protocol::make_error(
                Some(req.id.clone()),
                err.error.code,
                &redact_text(&err.error.message),
            ))),
            _ => Err("unexpected response from MCP server".into()),
        }
    }

    fn forward(&mut self, req: &protocol::JsonRpcRequest) -> Result<(), String> {
        self.server_transport
            .send(&JsonRpcMessage::Request(req.clone()))
    }

    fn forward_and_receive(
        &mut self,
        req: &protocol::JsonRpcRequest,
    ) -> Result<Option<String>, String> {
        self.forward(req)?;
        match self.server_transport.receive()? {
            JsonRpcMessage::Response(resp) => Ok(Some(protocol::make_response(
                req.id.clone(),
                redact_response(resp.result),
            ))),
            JsonRpcMessage::Error(err) => Ok(Some(protocol::make_error(
                Some(req.id.clone()),
                err.error.code,
                &redact_text(&err.error.message),
            ))),
            _ => Err("unexpected response from server".into()),
        }
    }
}

/// Run the MCP proxy: reads requests from `client`, forwards to the
/// MCP server via `self`, writes responses back to `client`.
/// This is a blocking call that returns when the connection is closed.
pub fn run_proxy(proxy: &mut McpProxy, client: &mut McpTransport) -> Result<(), String> {
    loop {
        let msg = client.receive()?;
        let response = proxy.handle_message(&msg)?;
        if let Some(resp_str) = response {
            client.send_raw(&resp_str)?;
        }
        // If the message was an error or response, stop.
        if matches!(
            msg,
            protocol::JsonRpcMessage::Error(_) | protocol::JsonRpcMessage::Response(_)
        ) {
            break;
        }
    }
    Ok(())
}

fn build_tool_request(
    tool_name: &str,
    arguments: &Option<serde_json::Value>,
    config: &McpProxyConfig,
) -> Result<ToolRequest, String> {
    let agent_id = AgentId::new(&config.agent_id).map_err(|e| format!("invalid agent ID: {e}"))?;
    let session_id =
        SessionId::new(&config.session_id).map_err(|e| format!("invalid session ID: {e}"))?;
    let request_id = RequestId::new(format!("mcp-{tool_name}-{}", uuid::Uuid::new_v4()))
        .map_err(|e| format!("invalid request ID: {e}"))?;

    let subject = AgentSubjectBuilder::new(agent_id, session_id)
        .trust_level(TrustLevel::Standard)
        .build();

    let operation = Operation::ToolInvoke {
        tool_id: tool_name.to_string(),
    };
    let resource = Resource::ExternalTool {
        identifier: tool_name.to_string(),
    };

    let intent_str = arguments.as_ref().map(|a| {
        let s = serde_json::to_string(a).unwrap_or_default();
        if s.len() > 4000 {
            let mut end = 4000;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            s[..end].to_string()
        } else {
            s
        }
    });

    let context = RequestContext::new(None, intent_str.as_deref(), None, None, false)
        .map_err(|e| format!("invalid request context: {e}"))?;

    Ok(ToolRequest::new(
        request_id, subject, operation, resource, context,
    ))
}

fn redact_response(result: serde_json::Value) -> serde_json::Value {
    match result {
        serde_json::Value::String(value) => serde_json::Value::String(redact_text(&value)),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(redact_response).collect())
        }
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let value = if is_sensitive_key(&key) {
                        serde_json::Value::String("[REDACTED:sensitive_field]".to_string())
                    } else {
                        redact_response(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        value => value,
    }
}

fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "key"
            | "api_key"
            | "apikey"
            | "token"
            | "access_token"
            | "refresh_token"
            | "secret"
            | "client_secret"
            | "password"
            | "passwd"
            | "credential"
            | "credentials"
            | "authorization"
    )
}

/// Redact known secret patterns from text. Redaction failures never return the
/// original potentially sensitive value.
pub fn redact_text(input: &str) -> String {
    let redactor = kavach_redaction::CompositeRedactor::builder().build();
    let redacted = redactor
        .redact_text(input)
        .map(|result| result.redacted)
        .unwrap_or_else(|_| "[REDACTION FAILED]".to_string());
    match serde_json::from_str(&redacted) {
        Ok(value) => serde_json::to_string(&redact_response(value))
            .unwrap_or_else(|_| "[REDACTION FAILED]".to_string()),
        Err(_) => redacted,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod redaction_tests {
    use super::{redact_response, redact_text};

    #[test]
    fn all_bearer_tokens_are_redacted() {
        let output =
            redact_text("Bearer first-secret-token-1234 and Bearer second-secret-token-5678.");
        assert!(!output.contains("first-secret-token"));
        assert!(!output.contains("second-secret-token"));
    }

    #[test]
    fn nested_json_strings_are_redacted() {
        let output = redact_response(serde_json::json!({
            "content": [{"type": "text", "text": "password=supersecret123"}],
            "nested": {"token": "Bearer another-secret-token-1234"},
        }));
        let serialized = serde_json::to_string(&output).unwrap();
        assert!(!serialized.contains("supersecret123"));
        assert!(!serialized.contains("another-secret-token"));
    }

    #[test]
    fn oversized_text_fails_closed() {
        let output = redact_text(&"x".repeat(kavach_redaction::MAX_INPUT_BYTES + 1));
        assert_eq!(output, "[REDACTION FAILED]");
    }
}
