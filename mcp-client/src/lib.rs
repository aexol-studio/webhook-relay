//! MCP (Model Context Protocol) client for webhook-relay
//!
//! This crate provides an MCP server that exposes webhook relay functionality
//! to AI assistants and other MCP clients.

mod mcp;

use std::io::{BufRead, Write};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{Mutex, RwLock};

pub use mcp::*;

pub mod auth {
    pub use common::auth::AuthManager;
}

pub mod config {
    use std::path::{Path, PathBuf};

    use anyhow::{bail, Context, Result};
    use serde::{Deserialize, Serialize};

    pub use common::config::{config_dir, config_path, discover_oauth_endpoints, OAuthConfig};

    /// Full client configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Config {
        pub server_address: String,
        pub local_endpoint: String,

        #[serde(default)]
        pub oauth: OAuthConfig,
    }

    impl Config {
        /// Get config directory (wrapper for common::config::config_dir)
        pub fn config_dir() -> Result<PathBuf> {
            config_dir()
        }

        /// Get config path (wrapper for common::config::config_path)
        pub fn config_path() -> Result<PathBuf> {
            config_path()
        }

        /// Load configuration from the default path
        pub fn load() -> Result<Self> {
            Self::load_from(Self::config_path()?)
        }

        /// Load configuration from a specific path
        pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self> {
            let path = path.as_ref();

            if !path.exists() {
                bail!(
                    "Config file not found at {}. Run with --init to create a default config.",
                    path.display()
                );
            }

            let contents =
                std::fs::read_to_string(path).context("Failed to read config file")?;

            toml::from_str(&contents).context("Failed to parse config file")
        }

        /// Create default configuration file
        pub fn create_default() -> Result<Self> {
            let config_dir = Self::config_dir()?;
            std::fs::create_dir_all(&config_dir).context("Failed to create config directory")?;

            let config = Config {
                server_address: "http://localhost:50051".to_string(),
                local_endpoint: "http://localhost:3000".to_string(),
                oauth: OAuthConfig {
                    client_id: "webhook-relay-cli".to_string(),
                    issuer: "http://localhost:8180/realms/relay".to_string(),
                    auth_url: None,
                    token_url: None,
                    callback_port: None,
                },
            };

            let path = Self::config_path()?;
            let contents =
                toml::to_string_pretty(&config).context("Failed to serialize config")?;

            std::fs::write(&path, contents).context("Failed to write config file")?;

            tracing::info!(path = %path.display(), "Created default config file");

            Ok(config)
        }

        /// Discover OAuth endpoints from OIDC well-known configuration
        pub async fn discover_oauth_endpoints(&mut self) -> Result<()> {
            discover_oauth_endpoints(&mut self.oauth).await
        }
    }
}

/// A log entry recording a webhook request and its response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogEntry {
    /// Unique request ID
    pub request_id: String,
    /// Timestamp when the request was received
    pub timestamp: DateTime<Utc>,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Query string
    pub query: String,
    /// Request headers
    pub request_headers: std::collections::HashMap<String, String>,
    /// Request body (as string, lossy conversion)
    pub request_body: String,
    /// Response status code
    pub response_status: u32,
    /// Response headers
    pub response_headers: std::collections::HashMap<String, String>,
    /// Response body (as string, lossy conversion)
    pub response_body: String,
}

/// Shared state for the MCP server
pub struct McpState {
    /// The loaded configuration
    config: config::Config,
    /// Client endpoint (assigned by server)
    endpoint: Option<String>,
    /// Whether we're connected to the relay server
    connected: bool,
    /// Request log (newest entries at the end)
    request_log: Vec<RequestLogEntry>,
}

impl McpState {
    /// Create a new MCP state with the given config
    pub fn new(config: config::Config) -> Self {
        Self {
            config,
            endpoint: None,
            connected: false,
            request_log: Vec::new(),
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

    /// Get the config
    pub fn get_config(&self) -> &config::Config {
        &self.config
    }

    /// Add an entry to the request log
    pub fn add_log_entry(&mut self, entry: RequestLogEntry) {
        self.request_log.push(entry);
    }

    /// Get request log entries, paginated, sorted from newest to oldest
    /// 
    /// Returns (entries, total_count)
    pub fn get_request_log(&self, page: usize, page_size: usize) -> (Vec<&RequestLogEntry>, usize) {
        let total = self.request_log.len();
        let start = page * page_size;
        
        if start >= total {
            return (Vec::new(), total);
        }
        
        // Reverse iteration for newest first
        let entries: Vec<_> = self.request_log
            .iter()
            .rev()
            .skip(start)
            .take(page_size)
            .collect();
        
        (entries, total)
    }

    /// Set connected status and endpoint
    pub fn set_connected(&mut self, endpoint: String) {
        self.connected = true;
        self.endpoint = Some(endpoint);
    }

    /// Set disconnected status
    pub fn set_disconnected(&mut self) {
        self.connected = false;
        self.endpoint = None;
    }
}

/// Shared state type alias
pub type SharedState = Arc<RwLock<McpState>>;

/// Create a new shared state with the given config
pub fn new_shared_state(config: config::Config) -> SharedState {
    Arc::new(RwLock::new(McpState::new(config)))
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
pub async fn handle_request(
    request: JsonRpcRequest,
    state: SharedState,
) -> Option<JsonRpcResponse> {
    let id = request.id.clone();

    match request.method.as_str() {
        "initialize" => Some(handle_initialize(id)),
        "initialized" => {
            // Notification, no response needed
            None
        }
        "tools/list" => Some(handle_list_tools(id)),
        "tools/call" => Some(handle_call_tool(id, request.params, state).await),
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
            resources: None,
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
            name: "get_config".to_string(),
            description: "Get the current webhook relay configuration".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        Tool {
            name: "get_request_log".to_string(),
            description: "Get the log of webhook requests and responses, sorted from newest to oldest".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "page": {
                        "type": "integer",
                        "description": "Page number (0-indexed, default: 0)"
                    },
                    "page_size": {
                        "type": "integer",
                        "description": "Number of entries per page (default: 10, max: 100)"
                    }
                }
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
        "get_config" => tool_get_config(state).await,
        "get_request_log" => tool_get_request_log(params.arguments, state).await,
        _ => CallToolResult::error(format!("Unknown tool: {}", params.name)),
    };

    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

/// Get config tool implementation
async fn tool_get_config(state: SharedState) -> CallToolResult {
    let state = state.read().await;
    let config = state.get_config();

    let mut output = String::new();
    output.push_str("Webhook Relay Configuration:\n\n");
    output.push_str(&format!("Server Address: {}\n", config.server_address));
    output.push_str(&format!("Local Endpoint: {}\n", config.local_endpoint));
    output.push_str("\nOAuth Configuration:\n");
    output.push_str(&format!("  Client ID: {}\n", config.oauth.client_id));
    output.push_str(&format!("  Issuer: {}\n", config.oauth.issuer));
    if let Some(auth_url) = &config.oauth.auth_url {
        output.push_str(&format!("  Auth URL: {}\n", auth_url));
    }
    if let Some(token_url) = &config.oauth.token_url {
        output.push_str(&format!("  Token URL: {}\n", token_url));
    }
    if let Some(port) = config.oauth.callback_port {
        output.push_str(&format!("  Callback Port: {}\n", port));
    }

    output.push_str("\nConnection Status:\n");
    if state.is_connected() {
        output.push_str("  Status: Connected\n");
        if let Some(endpoint) = state.get_endpoint() {
            output.push_str(&format!("  Webhook Endpoint: {}\n", endpoint));
        }
    } else {
        output.push_str("  Status: Disconnected\n");
    }

    CallToolResult::text(output)
}

/// Get request log tool implementation
async fn tool_get_request_log(args: Option<Value>, state: SharedState) -> CallToolResult {
    let page = args
        .as_ref()
        .and_then(|a| a.get("page"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    
    let page_size = args
        .as_ref()
        .and_then(|a| a.get("page_size"))
        .and_then(|v| v.as_u64())
        .map(|v| v.min(100) as usize)
        .unwrap_or(10);

    let state = state.read().await;
    let (entries, total) = state.get_request_log(page, page_size);

    if entries.is_empty() {
        if total == 0 {
            return CallToolResult::text("No webhook requests logged yet.".to_string());
        } else {
            return CallToolResult::text(format!(
                "No entries on page {} (total entries: {})",
                page, total
            ));
        }
    }

    let total_pages = (total + page_size - 1) / page_size;
    let mut output = format!(
        "Request Log (Page {} of {}, {} total entries):\n\n",
        page + 1,
        total_pages,
        total
    );

    for entry in entries {
        output.push_str(&format!("--- Request {} ---\n", entry.request_id));
        output.push_str(&format!("Timestamp: {}\n", entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        output.push_str(&format!("Method: {}\n", entry.method));
        output.push_str(&format!("Path: {}\n", entry.path));
        if !entry.query.is_empty() {
            output.push_str(&format!("Query: {}\n", entry.query));
        }
        output.push_str(&format!("Request Headers: {:?}\n", entry.request_headers));
        if !entry.request_body.is_empty() {
            output.push_str(&format!("Request Body: {}\n", entry.request_body));
        }
        output.push_str(&format!("Response Status: {}\n", entry.response_status));
        output.push_str(&format!("Response Headers: {:?}\n", entry.response_headers));
        if !entry.response_body.is_empty() {
            output.push_str(&format!("Response Body: {}\n", entry.response_body));
        }
        output.push('\n');
    }

    CallToolResult::text(output)
}
