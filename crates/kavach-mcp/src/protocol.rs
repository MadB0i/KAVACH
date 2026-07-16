use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request ID.
pub type RequestId = serde_json::Value;

/// Maximum allowed JSON-RPC message size (1 MiB).
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Maximum allowed method name length.
pub const MAX_METHOD_LENGTH: usize = 128;

/// Supported MCP protocol version.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

// ── JSON-RPC 2.0 base types ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: RequestId,
    pub result: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub jsonrpc: String,
    pub id: RequestId,
    pub error: JsonRpcErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcErrorBody {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// A parsed JSON-RPC message (any variant).
#[derive(Debug, Clone)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Notification(JsonRpcNotification),
    Response(JsonRpcResponse),
    Error(JsonRpcError),
}

// ── MCP-specific types ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputSchema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolRequestParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolResult {
    pub content: Vec<ToolContent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isError: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToolContent {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
    },
    #[serde(rename = "image")]
    Image {
        data: String,
        mimeType: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
    },
    #[serde(rename = "resource")]
    Resource {
        resource: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    pub protocolVersion: String,
    pub capabilities: ServerCapabilities,
    pub serverInfo: Implementation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Implementation {
    pub name: String,
    pub version: String,
}

// ── JSON-RPC error codes ──────────────────────────────────────────────

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

// KAVACH-specific error codes (in server error range -32000 to -32099)
pub const KAVACH_DENIED: i32 = -32000;
pub const KAVACH_APPROVAL_REQUIRED: i32 = -32001;
pub const KAVACH_TOOL_NOT_FOUND: i32 = -32002;
pub const KAVACH_REQUEST_TOO_LARGE: i32 = -32003;
pub const KAVACH_INTERNAL: i32 = -32099;

// ── Parsing helpers ──────────────────────────────────────────────────

/// Parse a JSON-RPC message from a raw JSON string.
/// Rejects unknown fields, oversized messages, and invalid structure.
pub fn parse_message(json: &str) -> Result<JsonRpcMessage, JsonRpcErrorResponse> {
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(jsonrpc_error(None, PARSE_ERROR, "message too large"));
    }

    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        jsonrpc_error(None, PARSE_ERROR, &format!("invalid JSON: {e}"))
    })?;

    let obj = value.as_object().ok_or_else(|| {
        jsonrpc_error(None, PARSE_ERROR, "expected JSON object")
    })?;

    let has_id = obj.contains_key("id");
    let has_method = obj.contains_key("method");
    let has_result = obj.contains_key("result");
    let has_error = obj.contains_key("error");

    if !has_method && !has_result && !has_error {
        return Err(jsonrpc_error(None, INVALID_REQUEST, "not a valid JSON-RPC message"));
    }

    if has_error {
        serde_json::from_value::<JsonRpcError>(value).map(JsonRpcMessage::Error).map_err(|e| {
            jsonrpc_error(None, PARSE_ERROR, &format!("invalid error message: {e}"))
        })
    } else if has_result {
        serde_json::from_value::<JsonRpcResponse>(value).map(JsonRpcMessage::Response).map_err(|e| {
            jsonrpc_error(None, PARSE_ERROR, &format!("invalid response: {e}"))
        })
    } else if has_id {
        serde_json::from_value::<JsonRpcRequest>(value).map(JsonRpcMessage::Request).map_err(|e| {
            jsonrpc_error(None, PARSE_ERROR, &format!("invalid request: {e}"))
        })
    } else {
        serde_json::from_value::<JsonRpcNotification>(value).map(JsonRpcMessage::Notification).map_err(|e| {
            jsonrpc_error(None, PARSE_ERROR, &format!("invalid notification: {e}"))
        })
    }
}

/// Serialize a JSON-RPC message.
pub fn serialize_message(msg: &JsonRpcMessage) -> Result<String, serde_json::Error> {
    match msg {
        JsonRpcMessage::Request(req) => serde_json::to_string(req),
        JsonRpcMessage::Notification(notif) => serde_json::to_string(notif),
        JsonRpcMessage::Response(resp) => serde_json::to_string(resp),
        JsonRpcMessage::Error(err) => serde_json::to_string(err),
    }
}

/// Create a JSON-RPC error response.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcErrorResponse {
    pub jsonrpc: String,
    pub id: Option<RequestId>,
    pub error: JsonRpcErrorBody,
}

fn jsonrpc_error(id: Option<RequestId>, code: i32, message: &str) -> JsonRpcErrorResponse {
    JsonRpcErrorResponse {
        jsonrpc: "2.0".into(),
        id,
        error: JsonRpcErrorBody {
            code,
            message: message.into(),
            data: None,
        },
    }
}

pub fn make_error(id: Option<RequestId>, code: i32, message: &str) -> String {
    let err = jsonrpc_error(id, code, message);
    serde_json::to_string(&err).unwrap_or_else(|_| "{}".into())
}

pub fn make_response(id: RequestId, result: serde_json::Value) -> String {
    let resp = JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result,
    };
    serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
}

/// Build a `method_not_found` error response.
pub fn method_not_found(id: Option<RequestId>) -> String {
    make_error(id, METHOD_NOT_FOUND, "method not found")
}

pub fn invalid_params(id: Option<RequestId>) -> String {
    make_error(id, INVALID_PARAMS, "invalid params")
}

pub fn internal_error(id: Option<RequestId>) -> String {
    make_error(id, INTERNAL_ERROR, "internal error")
}
