use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use kavach_core::ids::{AgentId, RequestId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, RequestContext, ToolRequest};
use kavach_core::resource::Resource;
use kavach_core::subject::TrustLevel;
use kavach_core::Operation;
use kavach_runtime::outcome::RuntimeOutcome;
use kavach_runtime::runtime::KavachRuntime;

use crate::protocol;
use crate::transport::McpTransport;

/// The MCP proxy configuration.
pub struct McpProxyConfig {
    /// Command to spawn the MCP server.
    pub server_command: String,
    /// Arguments for the MCP server command.
    pub server_args: Vec<String>,
    /// Request timeout for MCP server calls.
    pub request_timeout: Duration,
    /// Agent ID to use for tool call evaluations.
    pub agent_id: String,
    /// Session ID to use for tool call evaluations.
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
    server_process: Option<std::process::Child>,
    /// Cached tool list from the server.
    tools: HashMap<String, protocol::Tool>,
    /// Whether initialization is complete.
    initialized: bool,
}

impl McpProxy {
    /// Create a new proxy, spawning the MCP server.
    pub fn spawn(
        config: McpProxyConfig,
        runtime: Arc<KavachRuntime>,
    ) -> Result<Self, String> {
        let (server_transport, server_process) =
            McpTransport::spawn_server(&config.server_command, &config.server_args)
                .map_err(|e| format!("failed to spawn MCP server: {e}"))?;

        Ok(Self {
            config,
            runtime,
            server_transport,
            server_process: Some(server_process),
            tools: HashMap::new(),
            initialized: false,
        })
    }

    /// Get the mutable server transport for direct I/O.
    pub fn server_transport(&mut self) -> &mut McpTransport {
        &mut self.server_transport
    }

    /// Handle a single JSON-RPC message from the client.
    /// Returns the raw response string to send back, or `None` if no response is needed (notification).
    pub fn handle_message(&mut self, msg: &protocol::JsonRpcMessage) -> Result<Option<String>, String> {
        match msg {
            protocol::JsonRpcMessage::Request(req) => self.handle_request(req),
            protocol::JsonRpcMessage::Notification(notif) => {
                self.handle_notification(notif)?;
                Ok(None)
            }
            protocol::JsonRpcMessage::Response(_) | protocol::JsonRpcMessage::Error(_) => {
                // Unexpected: client shouldn't send responses.
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
            "resources/list" | "resources/templates/list" | "resources/read" |
            "prompts/list" | "prompts/get" | "completion/complete" => {
                self.forward_and_receive(req)
            }
            _ => {
                // Unknown method — forward to server as a fallback for forward compatibility.
                self.forward_and_receive(req)
            }
        }
    }

    fn handle_notification(&mut self, notif: &protocol::JsonRpcNotification) -> Result<(), String> {
        match notif.method.as_str() {
            "notifications/initialized" => {
                // Server already received initialize from us — forward.
                self.server_transport.send(msg_to_notification(notif))?;
            }
            "notifications/cancelled" => {
                // Forward cancellation to server.
                self.server_transport.send(msg_to_notification(notif))?;
            }
            "notifications/message" => {
                // Server log messages — forward.
                self.server_transport.send(msg_to_notification(notif))?;
            }
            _ => {
                // Unknown notification — forward.
                self.server_transport.send(msg_to_notification(notif))?;
            }
        }
        Ok(())
    }

    fn handle_initialize(&mut self, req: &protocol::JsonRpcRequest) -> Result<Option<String>, String> {
        // Forward initialize to server, then cache the response
        self.forward(req)?;
        let response = self.server_transport.receive()?;
        match response {
            protocol::JsonRpcMessage::Response(resp) => {
                // Parse the result to cache capabilities.
                if let Ok(init_result) = serde_json::from_value::<protocol::InitializeResult>(resp.result.clone()) {
                    if init_result.capabilities.tools.is_some() {
                        // Server supports tools — we'll cache them on first tools/list.
                    }
                }
                self.initialized = true;
                Ok(Some(protocol::make_response(req.id.clone(), resp.result)))
            }
            protocol::JsonRpcMessage::Error(err) => {
                Ok(Some(protocol::make_error(Some(req.id.clone()), err.error.code, &err.error.message)))
            }
            _ => Err("unexpected response during initialize".into()),
        }
    }

    fn handle_tools_list(&mut self, req: &protocol::JsonRpcRequest) -> Result<Option<String>, String> {
        self.forward(req)?;
        let response = self.server_transport.receive()?;
        match response {
            protocol::JsonRpcMessage::Response(resp) => {
                // Cache discovered tools.
                if let Some(tools_array) = resp.result.get("tools").and_then(|v| v.as_array()) {
                    for tool_val in tools_array {
                        if let Ok(tool) = serde_json::from_value::<protocol::Tool>(tool_val.clone()) {
                            self.tools.insert(tool.name.clone(), tool);
                        }
                    }
                }
                Ok(Some(protocol::make_response(req.id.clone(), resp.result)))
            }
            protocol::JsonRpcMessage::Error(err) => {
                Ok(Some(protocol::make_error(Some(req.id.clone()), err.error.code, &err.error.message)))
            }
            _ => Err("unexpected response during tools/list".into()),
        }
    }

    fn handle_tool_call(&mut self, req: &protocol::JsonRpcRequest) -> Result<Option<String>, String> {
        // 1. Validate params.
        let params = req.params.as_ref().ok_or_else(|| {
            protocol::make_error(Some(req.id.clone()), protocol::INVALID_PARAMS, "missing params")
        })?;

        let call_params: protocol::CallToolRequestParams =
            serde_json::from_value(params.clone()).map_err(|e| {
                protocol::make_error(Some(req.id.clone()), protocol::INVALID_PARAMS, &format!("invalid params: {e}"))
            })?;

        // 2. Validate tool exists.
        let tool_name = &call_params.name;
        if !self.tools.contains_key(tool_name) {
            return Ok(Some(protocol::make_error(
                Some(req.id.clone()),
                protocol::KAVACH_TOOL_NOT_FOUND,
                &format!("tool not found: {tool_name}"),
            )));
        }

        // 3. Build a ToolRequest from the call.
        let tool_request = build_tool_request(tool_name, &call_params.arguments, &self.config)?;

        // 4. Evaluate with KavachRuntime.
        let outcome = self.runtime.evaluate(&tool_request).map_err(|e| {
            protocol::make_error(
                Some(req.id.clone()),
                protocol::KAVACH_INTERNAL,
                &format!("evaluation failed: {e}"),
            )
        })?;

        // 5. Handle the outcome.
        match outcome {
            RuntimeOutcome::Denied { sanitized_summary, .. } => {
                // Denied — never forward.
                tracing::warn!(tool = %tool_name, "tool call denied: {sanitized_summary}");
                return Ok(Some(protocol::make_error(
                    Some(req.id.clone()),
                    protocol::KAVACH_DENIED,
                    &sanitized_summary,
                )));
            }
            RuntimeOutcome::ApprovalRequired { sanitized_summary, .. } => {
                // Approval required — never forward.
                tracing::warn!(tool = %tool_name, "tool call requires approval: {sanitized_summary}");
                return Ok(Some(protocol::make_error(
                    Some(req.id.clone()),
                    protocol::KAVACH_APPROVAL_REQUIRED,
                    &sanitized_summary,
                )));
            }
            RuntimeOutcome::Permitted(outcome) => {
                // Permit obtained — forward to MCP server.
                let _permit = outcome.permit;
                // We don't actually execute with the permit here — we forward the call.
                // The permit is just for policy compliance.
            }
        }

        // 6. Forward the tool call to the MCP server.
        self.forward(req)?;

        // 7. Receive the response.
        let response = self.server_transport.receive()?;
        match response {
            protocol::JsonRpcMessage::Response(resp) => {
                // 8. Redact text content in the response.
                let redacted = redact_response(resp.result.clone());
                Ok(Some(protocol::make_response(req.id.clone(), redacted)))
            }
            protocol::JsonRpcMessage::Error(err) => {
                Ok(Some(protocol::make_error(Some(req.id.clone()), err.error.code, &err.error.message)))
            }
            _ => Err("unexpected response from MCP server".into()),
        }
    }

    fn forward(&mut self, req: &protocol::JsonRpcRequest) -> Result<(), String> {
        let msg = protocol::JsonRpcMessage::Request(req.clone());
        self.server_transport.send(&msg)
    }

    fn forward_and_receive(&mut self, req: &protocol::JsonRpcRequest) -> Result<Option<String>, String> {
        self.forward(req)?;
        let response = self.server_transport.receive()?;
        match response {
            protocol::JsonRpcMessage::Response(resp) => {
                Ok(Some(protocol::make_response(req.id.clone(), resp.result)))
            }
            protocol::JsonRpcMessage::Error(err) => {
                Ok(Some(protocol::make_error(Some(req.id.clone()), err.error.code, &err.error.message)))
            }
            _ => Err("unexpected response from server".into()),
        }
    }
}

fn msg_to_notification(notif: &protocol::JsonRpcNotification) -> protocol::JsonRpcNotification {
    notif.clone()
}

/// Build a ToolRequest from an MCP tool call.
fn build_tool_request(
    tool_name: &str,
    arguments: &Option<serde_json::Value>,
    config: &McpProxyConfig,
) -> Result<ToolRequest, String> {
    let agent_id = AgentId::new(&config.agent_id)
        .map_err(|e| format!("invalid agent ID: {e}"))?;
    let session_id = SessionId::new(&config.session_id)
        .map_err(|e| format!("invalid session ID: {e}"))?;
    let request_id = RequestId::new(&format!("mcp-{tool_name}-{}", uuid::Uuid::new_v4()))
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

    // Serialize arguments as context metadata (or declare intent).
    let intent = arguments
        .as_ref()
        .map(|a| {
            let s = serde_json::to_string(a).unwrap_or_default();
            if s.len() > 4000 {
                &s[..4000]
            } else {
                &s
            }
        })
        .map(|s| s.to_string());

    let context = RequestContext::new(
        None,
        intent.as_deref(),
        None,
        None,
        false,
    )
    .map_err(|e| format!("invalid request context: {e}"))?;

    Ok(ToolRequest::new(request_id, subject, operation, resource, context))
}

/// Redact text content in a CallToolResult response.
/// Replaces known secret patterns with `[REDACTED]`.
fn redact_response(result: serde_json::Value) -> serde_json::Value {
    // Clone the value to avoid partial moves.
    match result {
        serde_json::Value::Object(mut map) => {
            if let Some(content) = map.get_mut("content").and_then(|c| c.as_array_mut()) {
                for item in content.iter_mut() {
                    if let serde_json::Value::Object(obj) = item {
                        if obj.get("type").and_then(|t| t.as_str()) == Some("text") {
                            if let Some(text) = obj.get_mut("text").and_then(|t| t.as_str()) {
                                let redacted = redact_text(text);
                                obj.insert("text".into(), serde_json::Value::String(redacted));
                            }
                        }
                    }
                }
            }
            serde_json::Value::Object(map)
        }
        other => other,
    }
}

/// Simple text redaction — replaces patterns that look like secrets.
fn redact_text(input: &str) -> String {
    // Replace common secret patterns.
    let mut result = input.to_string();
    // Bearer tokens: Bearer <hex-or-base64>
    if let Some(start) = result.find("Bearer ") {
        let after = &result[start + 7..];
        let end = after.find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '}').unwrap_or(after.len());
        if end >= 8 {
            result.replace_range(start + 7..start + 7 + end, "[REDACTED]");
        }
    }
    // API keys: "key": "..." or "api_key": "..."
    for pattern in &[r#""key": ""#, r#""api_key": ""#, r#""token": ""#, r#""secret": ""#] {
        while let Some(start) = result.find(pattern) {
            let value_start = start + pattern.len();
            if let Some(end) = result[value_start..].find('"') {
                let secret_len = std::cmp::min(end, 64);
                result.replace_range(value_start..value_start + secret_len, "[REDACTED]");
            }
        }
    }
    result
}
