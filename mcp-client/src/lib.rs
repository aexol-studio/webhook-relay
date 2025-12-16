//! MCP (Model Context Protocol) client for webhook-relay
//!
//! This crate provides an MCP server that exposes webhook relay functionality
//! to AI assistants and other MCP clients.

mod mcp;

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::Arc;

use anyhow::{Context, Result};
use api::{relay_service_client::RelayServiceClient, GetConfigRequest, HttpResponse};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_stream::StreamExt;
use tonic::{metadata::MetadataValue, transport::Channel, Request};

pub use mcp::*;

/// Shared state for the MCP server
pub struct McpState {
    /// gRPC channel to the relay server
    channel: Option<Channel>,
    /// Access token for authentication
    access_token: Option<String>,
    /// Server address
    server_address: String,
    /// Client endpoint (assigned by server)
    endpoint: Option<String>,
    /// Pending webhook requests waiting for responses
    pending_requests: HashMap<String, api::HttpRequest>,
    /// Channel to send responses back to the gRPC stream
    response_tx: Option<mpsc::Sender<HttpResponse>>,
    /// Whether we're connected to the relay server
    connected: bool,
}

impl McpState {
    /// Create a new MCP state
    pub fn new() -> Self {
        Self {
            channel: None,
            access_token: None,
            server_address: String::new(),
            endpoint: None,
            pending_requests: HashMap::new(),
            response_tx: None,
            connected: false,
        }
    }
    
    /// Check if connected to the relay server
    pub fn is_connected(&self) -> bool {
        self.connected
    }
    
    /// Get the webhook endpoint URL
    pub fn get_endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }
    
    /// Get pending requests count
    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }
}

impl Default for McpState {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state type alias
pub type SharedState = Arc<RwLock<McpState>>;

/// Create a new shared state
pub fn new_shared_state() -> SharedState {
    Arc::new(RwLock::new(McpState::new()))
}

/// Run the MCP server on stdio
pub async fn run_mcp_server(state: SharedState) -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = Arc::new(Mutex::new(std::io::stdout()));

    let reader = std::io::BufReader::new(stdin.lock());

    for line in reader.lines() {
        let line = line.context("Failed to read from stdin")?;

        if line.trim().is_empty() {
            continue;
        }

        tracing::debug!("Received: {}", line);

        let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
            Ok(request) => handle_request(request, state.clone()).await,
            Err(e) => {
                tracing::error!("Failed to parse request: {}", e);
                Some(JsonRpcResponse::error(
                    None,
                    error_codes::PARSE_ERROR,
                    &format!("Parse error: {}", e),
                ))
            }
        };

        if let Some(resp) = response {
            let response_json = serde_json::to_string(&resp)?;
            tracing::debug!("Sending: {}", response_json);

            let mut stdout = stdout.lock().await;
            writeln!(stdout, "{}", response_json)?;
            stdout.flush()?;
        }
    }

    Ok(())
}

/// Handle a single MCP request and return the response
pub async fn handle_request(request: JsonRpcRequest, state: SharedState) -> Option<JsonRpcResponse> {
    let id = request.id.clone();

    match request.method.as_str() {
        "initialize" => Some(handle_initialize(id)),
        "initialized" => {
            // Notification, no response needed
            None
        }
        "tools/list" => Some(handle_list_tools(id)),
        "tools/call" => Some(handle_call_tool(id, request.params, state).await),
        "resources/list" => Some(handle_list_resources(id, state).await),
        "resources/read" => Some(handle_read_resource(id, request.params, state).await),
        "ping" => Some(JsonRpcResponse::success(id, json!({}))),
        _ => Some(JsonRpcResponse::error(
            id,
            error_codes::METHOD_NOT_FOUND,
            &format!("Method not found: {}", request.method),
        )),
    }
}

fn handle_initialize(id: Option<Value>) -> JsonRpcResponse {
    let result = InitializeResult {
        protocol_version: "2024-11-05".to_string(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability {
                list_changed: Some(true),
            }),
            resources: Some(ResourcesCapability {
                subscribe: Some(false),
                list_changed: Some(true),
            }),
            prompts: None,
        },
        server_info: ServerInfo {
            name: "webhook-relay-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };

    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

fn handle_list_tools(id: Option<Value>) -> JsonRpcResponse {
    let tools = vec![
        Tool {
            name: "connect".to_string(),
            description: "Connect to the webhook relay server".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_address": {
                        "type": "string",
                        "description": "The gRPC server address (e.g., http://localhost:50051)"
                    },
                    "access_token": {
                        "type": "string",
                        "description": "OAuth2 access token for authentication"
                    }
                },
                "required": ["server_address", "access_token"]
            }),
        },
        Tool {
            name: "disconnect".to_string(),
            description: "Disconnect from the webhook relay server".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        Tool {
            name: "get_endpoint".to_string(),
            description: "Get the webhook endpoint URL assigned to this client".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        Tool {
            name: "list_pending_webhooks".to_string(),
            description: "List pending webhook requests that need responses".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        Tool {
            name: "get_webhook".to_string(),
            description: "Get details of a specific pending webhook request".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "The ID of the webhook request"
                    }
                },
                "required": ["request_id"]
            }),
        },
        Tool {
            name: "respond_to_webhook".to_string(),
            description: "Send a response to a pending webhook request".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "The ID of the webhook request to respond to"
                    },
                    "status_code": {
                        "type": "integer",
                        "description": "HTTP status code (e.g., 200, 404, 500)"
                    },
                    "headers": {
                        "type": "object",
                        "description": "HTTP response headers",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": {
                        "type": "string",
                        "description": "HTTP response body"
                    }
                },
                "required": ["request_id", "status_code"]
            }),
        },
    ];

    let result = ListToolsResult { tools };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

async fn handle_call_tool(
    id: Option<Value>,
    params: Option<Value>,
    state: SharedState,
) -> JsonRpcResponse {
    let params: CallToolParams = match params {
        Some(p) => match serde_json::from_value(p) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    error_codes::INVALID_PARAMS,
                    &format!("Invalid params: {}", e),
                )
            }
        },
        None => {
            return JsonRpcResponse::error(id, error_codes::INVALID_PARAMS, "Missing params")
        }
    };

    let result = match params.name.as_str() {
        "connect" => tool_connect(params.arguments, state).await,
        "disconnect" => tool_disconnect(state).await,
        "get_endpoint" => tool_get_endpoint(state).await,
        "list_pending_webhooks" => tool_list_pending_webhooks(state).await,
        "get_webhook" => tool_get_webhook(params.arguments, state).await,
        "respond_to_webhook" => tool_respond_to_webhook(params.arguments, state).await,
        _ => CallToolResult::error(format!("Unknown tool: {}", params.name)),
    };

    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

/// Connect to the relay server
pub async fn tool_connect(args: Option<Value>, state: SharedState) -> CallToolResult {
    let args = match args {
        Some(a) => a,
        None => return CallToolResult::error("Missing arguments".to_string()),
    };

    let server_address = match args.get("server_address").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return CallToolResult::error("Missing server_address".to_string()),
    };

    let access_token = match args.get("access_token").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return CallToolResult::error("Missing access_token".to_string()),
    };

    // Connect to the gRPC server
    let channel = match Channel::from_shared(server_address.clone()) {
        Ok(c) => match c.connect().await {
            Ok(ch) => ch,
            Err(e) => return CallToolResult::error(format!("Failed to connect: {}", e)),
        },
        Err(e) => return CallToolResult::error(format!("Invalid server address: {}", e)),
    };

    // Get config to register and get endpoint
    let mut client = RelayServiceClient::new(channel.clone());
    let mut request = Request::new(GetConfigRequest {});

    let token: MetadataValue<_> = match format!("Bearer {}", access_token).parse() {
        Ok(t) => t,
        Err(e) => return CallToolResult::error(format!("Invalid token format: {}", e)),
    };
    request.metadata_mut().insert("authorization", token);

    let config = match client.get_config(request).await {
        Ok(response) => match response.into_inner().config {
            Some(c) => c,
            None => return CallToolResult::error("Server returned empty config".to_string()),
        },
        Err(e) => return CallToolResult::error(format!("GetConfig failed: {}", e)),
    };

    let endpoint = config.endpoint.clone();

    // Update state
    {
        let mut state = state.write().await;
        state.channel = Some(channel.clone());
        state.access_token = Some(access_token.clone());
        state.server_address = server_address;
        state.endpoint = Some(endpoint.clone());
        state.connected = true;
    }

    // Start webhook stream in background
    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = run_webhook_stream(channel, access_token, state_clone).await {
            tracing::error!("Webhook stream error: {}", e);
        }
    });

    CallToolResult::text(format!(
        "Connected successfully!\nYour webhook endpoint: {}",
        endpoint
    ))
}

async fn run_webhook_stream(
    channel: Channel,
    access_token: String,
    state: SharedState,
) -> Result<()> {
    let mut client = RelayServiceClient::new(channel);

    let (response_tx, response_rx) = mpsc::channel::<HttpResponse>(32);
    let response_stream = tokio_stream::wrappers::ReceiverStream::new(response_rx);

    // Store the sender in state
    {
        let mut state = state.write().await;
        state.response_tx = Some(response_tx);
    }

    let mut request = Request::new(response_stream);
    let token: MetadataValue<_> = format!("Bearer {}", access_token).parse()?;
    request.metadata_mut().insert("authorization", token);

    let response = client
        .do_webhook(request)
        .await
        .context("DoWebhook RPC failed")?;

    let mut request_stream = response.into_inner();

    tracing::info!("Connected to webhook stream");

    while let Some(result) = request_stream.next().await {
        match result {
            Ok(http_request) => {
                let request_id = http_request.request_id.clone();
                tracing::info!(
                    request_id = %request_id,
                    method = %http_request.method,
                    path = %http_request.path,
                    "Received webhook request"
                );

                // Store pending request
                {
                    let mut state = state.write().await;
                    state.pending_requests.insert(request_id, http_request);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Error receiving from server");
                break;
            }
        }
    }

    // Mark as disconnected
    {
        let mut state = state.write().await;
        state.connected = false;
        state.response_tx = None;
    }

    tracing::info!("Webhook stream ended");
    Ok(())
}

/// Disconnect from the relay server
pub async fn tool_disconnect(state: SharedState) -> CallToolResult {
    let mut state = state.write().await;

    if !state.connected {
        return CallToolResult::error("Not connected".to_string());
    }

    state.channel = None;
    state.access_token = None;
    state.endpoint = None;
    state.pending_requests.clear();
    state.response_tx = None;
    state.connected = false;

    CallToolResult::text("Disconnected from webhook relay server".to_string())
}

/// Get the webhook endpoint
pub async fn tool_get_endpoint(state: SharedState) -> CallToolResult {
    let state = state.read().await;

    match &state.endpoint {
        Some(endpoint) => CallToolResult::text(format!("Webhook endpoint: {}", endpoint)),
        None => CallToolResult::error("Not connected. Use 'connect' tool first.".to_string()),
    }
}

/// List pending webhooks
pub async fn tool_list_pending_webhooks(state: SharedState) -> CallToolResult {
    let state = state.read().await;

    if !state.connected {
        return CallToolResult::error("Not connected. Use 'connect' tool first.".to_string());
    }

    if state.pending_requests.is_empty() {
        return CallToolResult::text("No pending webhook requests".to_string());
    }

    let mut output = String::from("Pending webhook requests:\n\n");
    for (id, req) in &state.pending_requests {
        output.push_str(&format!(
            "- {} {} {} (ID: {})\n",
            req.method, req.path, req.query, id
        ));
    }

    CallToolResult::text(output)
}

/// Get details of a specific webhook
pub async fn tool_get_webhook(args: Option<Value>, state: SharedState) -> CallToolResult {
    let args = match args {
        Some(a) => a,
        None => return CallToolResult::error("Missing arguments".to_string()),
    };

    let request_id = match args.get("request_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::error("Missing request_id".to_string()),
    };

    let state = state.read().await;

    match state.pending_requests.get(request_id) {
        Some(req) => {
            let headers_str: String = req
                .headers
                .iter()
                .map(|(k, v)| format!("  {}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\n");

            let body_str = String::from_utf8_lossy(&req.body);

            let output = format!(
                "Webhook Request Details:\n\
                 ID: {}\n\
                 Method: {}\n\
                 Path: {}\n\
                 Query: {}\n\
                 Headers:\n{}\n\
                 Body:\n{}",
                req.request_id, req.method, req.path, req.query, headers_str, body_str
            );

            CallToolResult::text(output)
        }
        None => CallToolResult::error(format!("Request {} not found", request_id)),
    }
}

/// Respond to a pending webhook
pub async fn tool_respond_to_webhook(args: Option<Value>, state: SharedState) -> CallToolResult {
    let args = match args {
        Some(a) => a,
        None => return CallToolResult::error("Missing arguments".to_string()),
    };

    let request_id = match args.get("request_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return CallToolResult::error("Missing request_id".to_string()),
    };

    let status_code = match args.get("status_code").and_then(|v| v.as_u64()) {
        Some(s) => s as u32,
        None => return CallToolResult::error("Missing status_code".to_string()),
    };

    let headers: HashMap<String, String> = args
        .get("headers")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let body = args
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .as_bytes()
        .to_vec();

    let mut state = state.write().await;

    // Remove from pending
    if state.pending_requests.remove(&request_id).is_none() {
        return CallToolResult::error(format!("Request {} not found", request_id));
    }

    // Send response
    let response = HttpResponse {
        request_id: request_id.clone(),
        status_code,
        headers,
        body,
    };

    match &state.response_tx {
        Some(tx) => {
            if let Err(e) = tx.send(response).await {
                return CallToolResult::error(format!("Failed to send response: {}", e));
            }
        }
        None => return CallToolResult::error("Not connected to server".to_string()),
    }

    CallToolResult::text(format!(
        "Response sent for request {} with status {}",
        request_id, status_code
    ))
}

async fn handle_list_resources(id: Option<Value>, state: SharedState) -> JsonRpcResponse {
    let state = state.read().await;

    let mut resources = vec![];

    if state.connected {
        if let Some(endpoint) = &state.endpoint {
            resources.push(Resource {
                uri: "webhook://endpoint".to_string(),
                name: "Webhook Endpoint".to_string(),
                description: Some(format!("Your webhook endpoint: {}", endpoint)),
                mime_type: Some("text/plain".to_string()),
            });
        }

        resources.push(Resource {
            uri: "webhook://pending".to_string(),
            name: "Pending Webhooks".to_string(),
            description: Some("List of pending webhook requests".to_string()),
            mime_type: Some("application/json".to_string()),
        });
    }

    let result = ListResourcesResult { resources };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

async fn handle_read_resource(
    id: Option<Value>,
    params: Option<Value>,
    state: SharedState,
) -> JsonRpcResponse {
    let params: ReadResourceParams = match params {
        Some(p) => match serde_json::from_value(p) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    error_codes::INVALID_PARAMS,
                    &format!("Invalid params: {}", e),
                )
            }
        },
        None => {
            return JsonRpcResponse::error(id, error_codes::INVALID_PARAMS, "Missing params")
        }
    };

    let state = state.read().await;

    let content = match params.uri.as_str() {
        "webhook://endpoint" => match &state.endpoint {
            Some(endpoint) => ResourceContent {
                uri: params.uri,
                mime_type: Some("text/plain".to_string()),
                text: Some(endpoint.clone()),
                blob: None,
            },
            None => {
                return JsonRpcResponse::error(
                    id,
                    error_codes::INTERNAL_ERROR,
                    "Not connected",
                )
            }
        },
        "webhook://pending" => {
            let pending: Vec<_> = state
                .pending_requests
                .iter()
                .map(|(id, req)| {
                    json!({
                        "request_id": id,
                        "method": req.method,
                        "path": req.path,
                        "query": req.query,
                    })
                })
                .collect();

            ResourceContent {
                uri: params.uri,
                mime_type: Some("application/json".to_string()),
                text: Some(serde_json::to_string_pretty(&pending).unwrap()),
                blob: None,
            }
        }
        _ => {
            return JsonRpcResponse::error(
                id,
                error_codes::INVALID_PARAMS,
                &format!("Unknown resource: {}", params.uri),
            )
        }
    };

    let result = ReadResourceResult {
        contents: vec![content],
    };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}
