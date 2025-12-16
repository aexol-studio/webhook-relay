//! End-to-end tests for the MCP client
//!
//! These tests require Keycloak to be running on localhost:8180
//! Start it with: docker-compose up -d keycloak

use std::time::Duration;

use mcp_client::{
    handle_request, new_shared_state, tool_connect, tool_disconnect, tool_get_endpoint,
    tool_get_webhook, tool_list_pending_webhooks, tool_respond_to_webhook, CallToolResult,
    JsonRpcRequest, SharedState,
};
use server::config::Config;
use serde_json::{json, Value};

use test_helpers::get_test_token;

// Test configuration
const KEYCLOAK_ISSUER: &str = "http://localhost:8180/realms/relay";
const KEYCLOAK_CLIENT_ID: &str = "webhook-relay-cli";
const TEST_USERNAME: &str = "testuser";
const TEST_PASSWORD: &str = "testpass";
const JWT_AUDIENCE: &str = "webhook-relay-cli";

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();
}

fn create_test_config(http_port: u16, grpc_port: u16) -> Config {
    Config {
        external_url: format!("http://localhost:{}", http_port),
        http_port,
        grpc_port,
        jwks_url: format!("{}/protocol/openid-connect/certs", KEYCLOAK_ISSUER),
        jwt_issuer: KEYCLOAK_ISSUER.to_string(),
        jwt_audience: JWT_AUDIENCE.to_string(),
        jwks_refresh_secs: 300,
        webhook_timeout_secs: 30,
    }
}

/// Helper to create a JSON-RPC request
fn make_request(method: &str, params: Option<Value>) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: method.to_string(),
        params,
    }
}

/// Helper to extract text from CallToolResult
fn get_result_text(result: &CallToolResult) -> &str {
    if let Some(mcp_client::ToolResultContent::Text { text }) = result.content.first() {
        text.as_str()
    } else {
        ""
    }
}

/// Test MCP initialize handshake
#[tokio::test]
async fn test_mcp_initialize() {
    init_tracing();

    let state = new_shared_state();
    
    // Send initialize request
    let request = make_request(
        "initialize",
        Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        })),
    );

    let response = handle_request(request, state.clone())
        .await
        .expect("Initialize should return response");

    // Verify response
    assert!(response.error.is_none(), "Initialize returned error");
    let result = response.result.expect("Should have result");

    assert_eq!(result["protocolVersion"], "2024-11-05");
    assert!(result["capabilities"]["tools"].is_object());
    assert_eq!(result["serverInfo"]["name"], "webhook-relay-mcp");

    // Send initialized notification (no response expected)
    let request = make_request("initialized", None);
    let response = handle_request(request, state).await;
    assert!(response.is_none(), "initialized notification should not return response");
}

/// Test listing available tools
#[tokio::test]
async fn test_mcp_list_tools() {
    init_tracing();

    let state = new_shared_state();

    // Initialize first
    let request = make_request("initialize", Some(json!({})));
    handle_request(request, state.clone()).await;

    // List tools
    let request = make_request("tools/list", None);
    let response = handle_request(request, state)
        .await
        .expect("List tools should return response");

    assert!(response.error.is_none(), "List tools returned error");
    let result = response.result.expect("Should have result");
    let tools = result["tools"].as_array().expect("No tools array");

    // Verify expected tools exist
    let tool_names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();

    assert!(tool_names.contains(&"connect"), "Missing connect tool");
    assert!(tool_names.contains(&"disconnect"), "Missing disconnect tool");
    assert!(tool_names.contains(&"get_endpoint"), "Missing get_endpoint tool");
    assert!(
        tool_names.contains(&"list_pending_webhooks"),
        "Missing list_pending_webhooks tool"
    );
    assert!(tool_names.contains(&"get_webhook"), "Missing get_webhook tool");
    assert!(
        tool_names.contains(&"respond_to_webhook"),
        "Missing respond_to_webhook tool"
    );

    tracing::info!("Found {} tools: {:?}", tools.len(), tool_names);
}

/// Test connecting to the relay server via MCP
#[tokio::test]
async fn test_mcp_connect_to_server() {
    init_tracing();

    // Start the relay server
    let config = create_test_config(0, 0);
    let (handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    let grpc_addr = format!("http://{}", addresses.grpc_addr);

    // Get OAuth token
    let token = get_test_token(KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID, TEST_USERNAME, TEST_PASSWORD)
        .await
        .expect("Failed to get test token");

    // Create MCP state
    let state = new_shared_state();

    // Connect to relay server
    let result = tool_connect(
        Some(json!({
            "server_address": grpc_addr,
            "access_token": token
        })),
        state.clone(),
    )
    .await;

    // Verify connection succeeded
    let text = get_result_text(&result);
    assert!(
        text.contains("Connected successfully"),
        "Expected success message, got: {}",
        text
    );
    assert!(
        text.contains("webhook endpoint"),
        "Expected endpoint in message, got: {}",
        text
    );

    tracing::info!("MCP connect result: {}", text);

    // Get endpoint
    let result = tool_get_endpoint(state.clone()).await;
    let text = get_result_text(&result);
    assert!(
        text.contains("Webhook endpoint:"),
        "Expected endpoint, got: {}",
        text
    );

    tracing::info!("MCP endpoint: {}", text);

    handle.stop();
}

/// Test full webhook flow through MCP
#[tokio::test]
async fn test_mcp_webhook_flow() {
    init_tracing();

    // Start the relay server
    let config = create_test_config(0, 0);
    let (handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    let http_addr = format!("http://{}", addresses.http_addr);
    let grpc_addr = format!("http://{}", addresses.grpc_addr);

    // Get OAuth token
    let token = get_test_token(KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID, TEST_USERNAME, TEST_PASSWORD)
        .await
        .expect("Failed to get test token");

    // Create MCP state
    let state = new_shared_state();

    // Connect to relay server
    let result = tool_connect(
        Some(json!({
            "server_address": grpc_addr,
            "access_token": token
        })),
        state.clone(),
    )
    .await;

    let connect_text = get_result_text(&result);
    tracing::info!("Connected: {}", connect_text);

    // Extract endpoint from connect result
    let endpoint_line = connect_text
        .lines()
        .find(|l| l.contains("endpoint:"))
        .expect("No endpoint in connect result");
    let endpoint = endpoint_line.split(": ").nth(1).unwrap().trim();

    // Extract route from endpoint
    let route = endpoint.rsplit('/').next().expect("Invalid endpoint format");

    // Give the stream time to establish
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send a webhook to the server
    let webhook_url = format!("{}/{}/test-webhook", http_addr, route);
    let webhook_body = r#"{"event": "test_event", "data": "hello from test"}"#;

    tracing::info!("Sending webhook to: {}", webhook_url);

    // Spawn webhook send in background (it will block until response)
    let webhook_handle = tokio::spawn(async move {
        let client = reqwest::Client::new();
        client
            .post(&webhook_url)
            .header("content-type", "application/json")
            .header("x-test-header", "test-value")
            .body(webhook_body)
            .timeout(Duration::from_secs(10))
            .send()
            .await
    });

    // Wait a bit for webhook to arrive
    tokio::time::sleep(Duration::from_millis(500)).await;

    // List pending webhooks
    let result = tool_list_pending_webhooks(state.clone()).await;
    let list_text = get_result_text(&result);
    tracing::info!("Pending webhooks: {}", list_text);

    // Should have at least one pending webhook
    assert!(
        list_text.contains("POST") || list_text.contains("/test-webhook"),
        "Expected pending webhook, got: {}",
        list_text
    );

    // Extract request ID from the list (format: "ID: <request_id>")
    let request_id = list_text
        .lines()
        .find(|l| l.contains("ID:"))
        .and_then(|l| l.split("ID:").nth(1))
        .map(|s| s.trim().trim_end_matches(')'))
        .expect("Could not find request ID in list");

    tracing::info!("Found request ID: {}", request_id);

    // Get webhook details
    let result = tool_get_webhook(
        Some(json!({
            "request_id": request_id
        })),
        state.clone(),
    )
    .await;

    let details_text = get_result_text(&result);
    tracing::info!("Webhook details: {}", details_text);

    assert!(
        details_text.contains("POST"),
        "Expected POST method in details"
    );
    assert!(
        details_text.contains("/test-webhook"),
        "Expected path in details"
    );
    assert!(
        details_text.contains("test_event"),
        "Expected body content in details"
    );

    // Respond to the webhook
    let result = tool_respond_to_webhook(
        Some(json!({
            "request_id": request_id,
            "status_code": 200,
            "headers": {
                "content-type": "application/json"
            },
            "body": "{\"status\": \"received\", \"message\": \"OK from MCP\"}"
        })),
        state.clone(),
    )
    .await;

    let respond_text = get_result_text(&result);
    tracing::info!("Response result: {}", respond_text);

    assert!(
        respond_text.contains("Response sent"),
        "Expected response sent confirmation, got: {}",
        respond_text
    );

    // Wait for webhook response
    let webhook_response = webhook_handle
        .await
        .expect("Webhook task panicked")
        .expect("Webhook request failed");

    assert!(
        webhook_response.status().is_success(),
        "Webhook response should be success, got: {}",
        webhook_response.status()
    );

    let response_body = webhook_response.text().await.unwrap();
    assert!(
        response_body.contains("OK from MCP"),
        "Expected MCP response body, got: {}",
        response_body
    );

    tracing::info!("Full MCP webhook flow test passed!");

    handle.stop();
}

/// Test MCP resources
#[tokio::test]
async fn test_mcp_resources() {
    init_tracing();

    // Start the relay server
    let config = create_test_config(0, 0);
    let (handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    let grpc_addr = format!("http://{}", addresses.grpc_addr);

    // Get OAuth token
    let token = get_test_token(KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID, TEST_USERNAME, TEST_PASSWORD)
        .await
        .expect("Failed to get test token");

    // Create MCP state
    let state = new_shared_state();

    // List resources before connecting (should be empty)
    let request = make_request("resources/list", None);
    let response = handle_request(request, state.clone())
        .await
        .expect("List resources should return response");

    let result = response.result.expect("Should have result");
    let resources = result["resources"]
        .as_array()
        .expect("No resources array");
    assert!(
        resources.is_empty(),
        "Expected no resources before connect"
    );

    // Connect to relay server
    tool_connect(
        Some(json!({
            "server_address": grpc_addr,
            "access_token": token
        })),
        state.clone(),
    )
    .await;

    // Wait for connection
    tokio::time::sleep(Duration::from_millis(100)).await;

    // List resources after connecting
    let request = make_request("resources/list", None);
    let response = handle_request(request, state.clone())
        .await
        .expect("List resources should return response");

    let result = response.result.expect("Should have result");
    let resources = result["resources"]
        .as_array()
        .expect("No resources array");

    assert!(
        !resources.is_empty(),
        "Expected resources after connect"
    );

    let resource_uris: Vec<&str> = resources
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();

    assert!(
        resource_uris.contains(&"webhook://endpoint"),
        "Missing endpoint resource"
    );
    assert!(
        resource_uris.contains(&"webhook://pending"),
        "Missing pending resource"
    );

    // Read endpoint resource
    let request = make_request(
        "resources/read",
        Some(json!({
            "uri": "webhook://endpoint"
        })),
    );
    let response = handle_request(request, state.clone())
        .await
        .expect("Read resource should return response");

    let result = response.result.expect("Should have result");
    let contents = &result["contents"][0];
    assert!(
        contents["text"].as_str().unwrap().contains("http"),
        "Expected endpoint URL in resource content"
    );

    // Read pending resource
    let request = make_request(
        "resources/read",
        Some(json!({
            "uri": "webhook://pending"
        })),
    );
    let response = handle_request(request, state.clone())
        .await
        .expect("Read resource should return response");

    let result = response.result.expect("Should have result");
    let contents = &result["contents"][0];
    let pending_json: Value =
        serde_json::from_str(contents["text"].as_str().unwrap()).expect("Invalid JSON");
    assert!(
        pending_json.is_array(),
        "Expected pending to be JSON array"
    );

    tracing::info!("MCP resources test passed!");

    handle.stop();
}

/// Test disconnect functionality
#[tokio::test]
async fn test_mcp_disconnect() {
    init_tracing();

    // Start the relay server
    let config = create_test_config(0, 0);
    let (handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    let grpc_addr = format!("http://{}", addresses.grpc_addr);

    // Get OAuth token
    let token = get_test_token(KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID, TEST_USERNAME, TEST_PASSWORD)
        .await
        .expect("Failed to get test token");

    // Create MCP state
    let state = new_shared_state();

    // Disconnect without connecting first should fail
    let result = tool_disconnect(state.clone()).await;
    let text = get_result_text(&result);
    assert!(
        result.is_error == Some(true) || text.contains("Not connected"),
        "Expected error for disconnect without connect"
    );

    // Connect
    tool_connect(
        Some(json!({
            "server_address": grpc_addr,
            "access_token": token
        })),
        state.clone(),
    )
    .await;

    // Disconnect
    let result = tool_disconnect(state.clone()).await;
    let text = get_result_text(&result);
    assert!(
        text.contains("Disconnected"),
        "Expected disconnect confirmation, got: {}",
        text
    );

    // Get endpoint should fail after disconnect
    let result = tool_get_endpoint(state.clone()).await;
    let text = get_result_text(&result);
    assert!(
        result.is_error == Some(true) || text.contains("Not connected"),
        "Expected error after disconnect, got: {}",
        text
    );

    tracing::info!("MCP disconnect test passed!");

    handle.stop();
}

/// Test error handling for invalid tool arguments
#[tokio::test]
async fn test_mcp_tool_error_handling() {
    init_tracing();

    let state = new_shared_state();

    // Call connect without required arguments
    let result = tool_connect(Some(json!({})), state.clone()).await;
    let text = get_result_text(&result);
    assert!(
        result.is_error == Some(true) || text.contains("Missing"),
        "Expected error for missing arguments"
    );

    // Call get_webhook without request_id
    let result = tool_get_webhook(Some(json!({})), state.clone()).await;
    let text = get_result_text(&result);
    assert!(
        result.is_error == Some(true) || text.contains("Missing"),
        "Expected error for missing request_id"
    );

    // Call respond_to_webhook without required arguments
    let result = tool_respond_to_webhook(
        Some(json!({
            "request_id": "test"
        })),
        state.clone(),
    )
    .await;
    let text = get_result_text(&result);
    assert!(
        result.is_error == Some(true) || text.contains("Missing"),
        "Expected error for missing status_code"
    );

    tracing::info!("MCP error handling test passed!");
}

/// Test MCP ping
#[tokio::test]
async fn test_mcp_ping() {
    init_tracing();

    let state = new_shared_state();

    // Initialize
    let request = make_request("initialize", Some(json!({})));
    handle_request(request, state.clone()).await;

    // Send ping
    let request = make_request("ping", None);
    let response = handle_request(request, state)
        .await
        .expect("Ping should return response");

    assert!(response.error.is_none(), "Ping returned error");
    assert!(response.result.is_some(), "Ping should return result");

    tracing::info!("MCP ping test passed!");
}
