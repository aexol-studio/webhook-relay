//! MCP client binary for webhook-relay

use std::path::PathBuf;

use anyhow::Result;
use api::HttpResponse;
use chrono::Utc;
use mcp_client::{
    auth::AuthManager, config::Config, new_shared_state, run_mcp_server, RequestLogEntry,
    SharedState,
};

fn print_usage() {
    eprintln!("Usage: mcp-client [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --init              Create default config file");
    eprintln!("  --config <PATH>     Path to config file (default: ~/.config/webhook-relay/config.toml)");
    eprintln!("  --help              Show this help message");
}

fn parse_args() -> Result<Option<PathBuf>> {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path: Option<PathBuf> = None;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--init" => {
                Config::create_default()?;
                eprintln!(
                    "Created default config at {}",
                    Config::config_path()?.display()
                );
                eprintln!("Please edit the config file and run again.");
                std::process::exit(0);
            }
            "--config" | "-c" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--config requires a path argument");
                }
                config_path = Some(PathBuf::from(&args[i]));
            }
            arg if arg.starts_with('-') => {
                anyhow::bail!("Unknown option: {}", arg);
            }
            _ => {
                anyhow::bail!("Unexpected argument: {}", args[i]);
            }
        }
        i += 1;
    }

    Ok(config_path)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing to stderr (stdout is for MCP protocol)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Parse arguments
    let config_path = parse_args()?;

    // Load configuration
    let mut config = match config_path {
        Some(path) => {
            tracing::info!(path = %path.display(), "Loading config from custom path");
            Config::load_from(&path)?
        }
        None => Config::load()?,
    };

    tracing::info!(
        server_address = %config.server_address,
        local_endpoint = %config.local_endpoint,
        "Configuration loaded"
    );

    // Discover OAuth endpoints
    config.discover_oauth_endpoints().await?;

    // Create auth manager
    let auth_manager = AuthManager::new(&config.oauth)?;

    // Create shared state with config
    let state = new_shared_state(config.clone());

    // Get initial access token
    let access_token = auth_manager.get_access_token().await?;

    // Connect to relay server
    let mut relay_client =
        common::RelayClient::connect(&config.server_address, access_token).await?;

    // Get config (establishes session)
    let client_config = relay_client.get_config().await?;
    let endpoint = client_config.endpoint.clone();

    tracing::info!(endpoint = %endpoint, "Connected to relay server");

    // Update state with connection info
    {
        let mut s = state.write().await;
        s.set_connected(endpoint.clone());
    }

    // Start the webhook forwarding in background
    spawn_webhook_handler(state.clone(), relay_client, config.local_endpoint.clone());

    // Run the MCP server on stdio
    run_mcp_server(state).await
}

fn spawn_webhook_handler(
    state: SharedState,
    relay_client: common::RelayClient,
    local_endpoint: String,
) {
    let http_client = reqwest::Client::new();
    let local_endpoint = local_endpoint.trim_end_matches('/').to_string();
    let state_for_disconnect = state.clone();

    tokio::spawn(async move {
        if let Err(e) = relay_client
            .run_webhook_loop(move |http_request| {
                let state = state.clone();
                let http_client = http_client.clone();
                let local_endpoint = local_endpoint.clone();

                async move {
                    let request_id = http_request.request_id.clone();
                    let timestamp = Utc::now();
                    let method = http_request.method.clone();
                    let path = http_request.path.clone();
                    let query = http_request.query.clone();
                    let request_headers = http_request.headers.clone();
                    let request_body = String::from_utf8_lossy(&http_request.body).to_string();

                    // Forward the request
                    let response =
                        forward_request(&http_client, &local_endpoint, http_request).await;

                    // Log the request/response
                    let log_entry = RequestLogEntry {
                        request_id: request_id.clone(),
                        timestamp,
                        method,
                        path,
                        query,
                        request_headers,
                        request_body,
                        response_status: response.status_code,
                        response_headers: response.headers.clone(),
                        response_body: String::from_utf8_lossy(&response.body).to_string(),
                    };

                    {
                        let mut s = state.write().await;
                        s.add_log_entry(log_entry);
                    }

                    response
                }
            })
            .await
        {
            tracing::error!(error = %e, "Webhook stream error");
        }

        // Mark as disconnected
        {
            let mut s = state_for_disconnect.write().await;
            s.set_disconnected();
        }

        tracing::info!("Webhook stream ended");
    });
}

async fn forward_request(
    client: &reqwest::Client,
    local_endpoint: &str,
    request: api::HttpRequest,
) -> HttpResponse {
    let url = if request.query.is_empty() {
        format!("{}{}", local_endpoint, request.path)
    } else {
        format!("{}{}?{}", local_endpoint, request.path, request.query)
    };

    tracing::debug!(
        request_id = %request.request_id,
        method = %request.method,
        url = %url,
        "Forwarding request to local endpoint"
    );

    let method: reqwest::Method = match request.method.parse() {
        Ok(m) => m,
        Err(e) => {
            return HttpResponse {
                request_id: request.request_id,
                status_code: 400,
                headers: Default::default(),
                body: format!("Invalid HTTP method: {}", e).into_bytes(),
            }
        }
    };

    let mut req_builder = client.request(method, &url);

    // Add headers (filter out some hop-by-hop headers)
    let skip_headers = ["host", "connection", "transfer-encoding", "keep-alive"];
    for (name, value) in &request.headers {
        if !skip_headers.contains(&name.to_lowercase().as_str()) {
            req_builder = req_builder.header(name, value);
        }
    }

    // Add body
    if !request.body.is_empty() {
        req_builder = req_builder.body(request.body);
    }

    match req_builder.send().await {
        Ok(response) => {
            let status_code = response.status().as_u16() as u32;

            let mut headers = std::collections::HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(value_str) = value.to_str() {
                    headers.insert(name.to_string(), value_str.to_string());
                }
            }

            let body = response
                .bytes()
                .await
                .map(|b| b.to_vec())
                .unwrap_or_default();

            tracing::debug!(
                request_id = %request.request_id,
                status_code = status_code,
                "Received response from local endpoint"
            );

            HttpResponse {
                request_id: request.request_id,
                status_code,
                headers,
                body,
            }
        }
        Err(e) => {
            tracing::error!(
                request_id = %request.request_id,
                error = %e,
                "Failed to forward request"
            );
            HttpResponse {
                request_id: request.request_id,
                status_code: 502,
                headers: Default::default(),
                body: format!("Failed to forward request: {}", e).into_bytes(),
            }
        }
    }
}
