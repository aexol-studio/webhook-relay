//! End-to-end tests for the MCP client
//!
//! These tests follow the black-box testing pattern, testing the MCP protocol
//! handlers and the webhook relay flow through the MCP client.
//!
//! These tests require Keycloak to be running on localhost:8180
//! Start it with: docker-compose up -d keycloak

use std::time::Duration;

use chrono::Utc;
use mcp_client::{
    config::{Config, OAuthConfig},
    handle_request, new_shared_state, JsonRpcRequest, RequestLogEntry,
    SharedState,
};
use serde_json::{json, Value};
use server::config::Config as ServerConfig;

use test_helpers::{get_test_token, MockLocalServer};

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

fn create_server_config(http_port: u16, grpc_port: u16) -> ServerConfig {
    ServerConfig {
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

/// Create a test MCP client config
fn create_mcp_config(grpc_addr: &str, local_endpoint: &str) -> Config {
    Config {
        server_address: grpc_addr.to_string(),
        local_endpoint: local_endpoint.to_string(),
        oauth: OAuthConfig {
            client_id: KEYCLOAK_CLIENT_ID.to_string(),
            issuer: KEYCLOAK_ISSUER.to_string(),
            auth_url: None,
            token_url: None,
            callback_port: None,
        },
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

/// Helper to simulate the webhook handler adding a log entry
async fn simulate_webhook_log(
    state: &SharedState,
    request_id: &str,
    method: &str,
    path: &str,
    request_body: &str,
    response_status: u32,
    response_body: &str,
) {
    let entry = RequestLogEntry {
        request_id: request_id.to_string(),
        timestamp: Utc::now(),
        method: method.to_string(),
        path: path.to_string(),
        query: String::new(),
        request_headers: std::collections::HashMap::new(),
        request_body: request_body.to_string(),
        response_status,
        response_headers: std::collections::HashMap::new(),
        response_body: response_body.to_string(),
    };

    let mut s = state.write().await;
    s.add_log_entry(entry);
}

/// Test MCP initialize handshake
#[tokio::test]
async fn test_mcp_initialize() {
    init_tracing();

    let config = create_mcp_config("http://localhost:50051", "http://localhost:3000");
    let state = new_shared_state(config);

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
    assert!(
        response.is_none(),
        "initialized notification should not return response"
    );
}

/// Test listing available tools
#[tokio::test]
async fn test_mcp_list_tools() {
    init_tracing();

    let config = create_mcp_config("http://localhost:50051", "http://localhost:3000");
    let state = new_shared_state(config);

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

    assert!(tool_names.contains(&"get_config"), "Missing get_config tool");
    assert!(
        tool_names.contains(&"get_request_log"),
        "Missing get_request_log tool"
    );

    // Should have exactly 2 tools
    assert_eq!(tools.len(), 2, "Expected exactly 2 tools");

    tracing::info!("Found {} tools: {:?}", tools.len(), tool_names);
}

/// Test get_config tool
#[tokio::test]
async fn test_mcp_get_config_tool() {
    init_tracing();

    let config = create_mcp_config("http://test-server:50051", "http://localhost:8080");
    let state = new_shared_state(config);

    // Call get_config tool
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "get_config",
            "arguments": {}
        })),
    );

    let response = handle_request(request, state.clone())
        .await
        .expect("Tool call should return response");

    assert!(response.error.is_none(), "Tool call returned error");
    let result = response.result.expect("Should have result");
    let content = &result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    // Verify config is displayed
    assert!(
        content.contains("http://test-server:50051"),
        "Should show server address"
    );
    assert!(
        content.contains("http://localhost:8080"),
        "Should show local endpoint"
    );
    assert!(
        content.contains("Disconnected"),
        "Should show disconnected status"
    );

    tracing::info!("get_config result:\n{}", content);
}

/// Test get_config tool shows connected status
#[tokio::test]
async fn test_mcp_get_config_connected_status() {
    init_tracing();

    let config = create_mcp_config("http://test-server:50051", "http://localhost:8080");
    let state = new_shared_state(config);

    // Simulate connected state
    {
        let mut s = state.write().await;
        s.set_connected("http://relay.example.com/webhook/abc123".to_string());
    }

    // Call get_config tool
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "get_config",
            "arguments": {}
        })),
    );

    let response = handle_request(request, state)
        .await
        .expect("Tool call should return response");

    let result = response.result.expect("Should have result");
    let content = &result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    // Verify connected status is displayed
    assert!(content.contains("Connected"), "Should show connected status");
    assert!(
        content.contains("http://relay.example.com/webhook/abc123"),
        "Should show webhook endpoint"
    );

    tracing::info!("get_config (connected) result:\n{}", content);
}

/// Test get_request_log tool with no entries
#[tokio::test]
async fn test_mcp_get_request_log_empty() {
    init_tracing();

    let config = create_mcp_config("http://localhost:50051", "http://localhost:3000");
    let state = new_shared_state(config);

    // Call get_request_log tool
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "get_request_log",
            "arguments": {}
        })),
    );

    let response = handle_request(request, state)
        .await
        .expect("Tool call should return response");

    let result = response.result.expect("Should have result");
    let content = &result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    assert!(
        content.contains("No webhook requests logged"),
        "Should indicate no requests logged"
    );

    tracing::info!("get_request_log (empty) result: {}", content);
}

/// Test get_request_log tool with entries
#[tokio::test]
async fn test_mcp_get_request_log_with_entries() {
    init_tracing();

    let config = create_mcp_config("http://localhost:50051", "http://localhost:3000");
    let state = new_shared_state(config);

    // Simulate some webhook logs
    simulate_webhook_log(
        &state,
        "req-001",
        "POST",
        "/webhook/test",
        r#"{"event": "test1"}"#,
        200,
        "OK",
    )
    .await;

    simulate_webhook_log(
        &state,
        "req-002",
        "POST",
        "/webhook/another",
        r#"{"event": "test2"}"#,
        201,
        "Created",
    )
    .await;

    // Call get_request_log tool
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "get_request_log",
            "arguments": {}
        })),
    );

    let response = handle_request(request, state)
        .await
        .expect("Tool call should return response");

    let result = response.result.expect("Should have result");
    let content = &result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    // Verify entries are displayed (newest first)
    assert!(content.contains("req-002"), "Should contain second request ID");
    assert!(content.contains("req-001"), "Should contain first request ID");
    assert!(content.contains("POST"), "Should show method");
    assert!(
        content.contains("/webhook/test"),
        "Should show first request path"
    );
    assert!(
        content.contains("/webhook/another"),
        "Should show second request path"
    );
    assert!(content.contains("2 total entries"), "Should show total count");

    // Verify newest first ordering (req-002 should appear before req-001)
    let pos_002 = content.find("req-002").expect("req-002 not found");
    let pos_001 = content.find("req-001").expect("req-001 not found");
    assert!(
        pos_002 < pos_001,
        "Newest entry (req-002) should appear before older entry (req-001)"
    );

    tracing::info!("get_request_log result:\n{}", content);
}

/// Test get_request_log pagination
#[tokio::test]
async fn test_mcp_get_request_log_pagination() {
    init_tracing();

    let config = create_mcp_config("http://localhost:50051", "http://localhost:3000");
    let state = new_shared_state(config);

    // Add 5 entries
    for i in 1..=5 {
        simulate_webhook_log(
            &state,
            &format!("req-{:03}", i),
            "POST",
            &format!("/webhook/test{}", i),
            "{}",
            200,
            "OK",
        )
        .await;
    }

    // Get page 0 with page_size 2
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "get_request_log",
            "arguments": {
                "page": 0,
                "page_size": 2
            }
        })),
    );

    let response = handle_request(request, state.clone())
        .await
        .expect("Tool call should return response");

    let result = response.result.expect("Should have result");
    let content = result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    // Page 0 should have newest 2 entries (req-005, req-004)
    assert!(content.contains("req-005"), "Page 0 should have req-005");
    assert!(content.contains("req-004"), "Page 0 should have req-004");
    assert!(!content.contains("req-003"), "Page 0 should not have req-003");
    assert!(content.contains("Page 1 of 3"), "Should show correct page info");

    // Get page 1 with page_size 2
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "get_request_log",
            "arguments": {
                "page": 1,
                "page_size": 2
            }
        })),
    );

    let response = handle_request(request, state.clone())
        .await
        .expect("Tool call should return response");

    let result = response.result.expect("Should have result");
    let content = result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    // Page 1 should have req-003, req-002
    assert!(content.contains("req-003"), "Page 1 should have req-003");
    assert!(content.contains("req-002"), "Page 1 should have req-002");
    assert!(!content.contains("req-005"), "Page 1 should not have req-005");
    assert!(content.contains("Page 2 of 3"), "Should show correct page info");

    // Get page 2 with page_size 2
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "get_request_log",
            "arguments": {
                "page": 2,
                "page_size": 2
            }
        })),
    );

    let response = handle_request(request, state.clone())
        .await
        .expect("Tool call should return response");

    let result = response.result.expect("Should have result");
    let content = result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    // Page 2 should have only req-001
    assert!(content.contains("req-001"), "Page 2 should have req-001");
    assert!(!content.contains("req-002"), "Page 2 should not have req-002");

    tracing::info!("Pagination test passed!");
}

/// Test MCP ping
#[tokio::test]
async fn test_mcp_ping() {
    init_tracing();

    let config = create_mcp_config("http://localhost:50051", "http://localhost:3000");
    let state = new_shared_state(config);

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

/// Test unknown method handling
#[tokio::test]
async fn test_mcp_unknown_method() {
    init_tracing();

    let config = create_mcp_config("http://localhost:50051", "http://localhost:3000");
    let state = new_shared_state(config);

    // Send unknown method
    let request = make_request("unknown/method", None);
    let response = handle_request(request, state)
        .await
        .expect("Should return error response");

    assert!(response.error.is_some(), "Should have error");
    let error = response.error.unwrap();
    assert!(
        error.message.contains("Method not found"),
        "Error should mention method not found"
    );

    tracing::info!("Unknown method test passed!");
}

/// Test unknown tool handling
#[tokio::test]
async fn test_mcp_unknown_tool() {
    init_tracing();

    let config = create_mcp_config("http://localhost:50051", "http://localhost:3000");
    let state = new_shared_state(config);

    // Call unknown tool
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "nonexistent_tool",
            "arguments": {}
        })),
    );

    let response = handle_request(request, state)
        .await
        .expect("Should return response");

    let result = response.result.expect("Should have result");
    let content = result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    assert!(
        content.contains("Unknown tool"),
        "Should indicate unknown tool"
    );

    tracing::info!("Unknown tool test passed!");
}

/// Integration test: Full MCP client flow with real server
///
/// This test follows the black-box pattern:
/// 1. Start relay server
/// 2. Start mock local server
/// 3. Create MCP state and connect to relay
/// 4. Send webhook through relay
/// 5. Verify request log contains the webhook
#[tokio::test]
async fn test_mcp_full_webhook_flow() {
    init_tracing();

    // 1. Start mock local server
    let mock_server = MockLocalServer::start()
        .await
        .expect("Failed to start mock server");
    let local_endpoint = format!("http://{}", mock_server.addr);
    tracing::info!("Mock local server listening on {}", local_endpoint);

    // 2. Start relay server
    let server_config = create_server_config(0, 0);
    let (server_handle, addresses) = server::run_server(server_config)
        .await
        .expect("Failed to start server");

    let http_addr = format!("http://{}", addresses.http_addr);
    let grpc_addr = format!("http://{}", addresses.grpc_addr);
    tracing::info!("Relay server HTTP: {}, gRPC: {}", http_addr, grpc_addr);

    // 3. Get OAuth token
    let token = get_test_token(KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID, TEST_USERNAME, TEST_PASSWORD)
        .await
        .expect("Failed to get test token");

    // 4. Create MCP state with config
    let mcp_config = create_mcp_config(&grpc_addr, &local_endpoint);
    let state = new_shared_state(mcp_config);

    // 5. Connect to relay server (simulating what main.rs does)
    let mut relay_client = common::RelayClient::connect(&grpc_addr, token)
        .await
        .expect("Failed to connect to relay server");

    let client_config = relay_client
        .get_config()
        .await
        .expect("Failed to get config");
    let endpoint = client_config.endpoint.clone();

    tracing::info!("Connected with endpoint: {}", endpoint);

    // Update state with connection info
    {
        let mut s = state.write().await;
        s.set_connected(endpoint.clone());
    }

    // 6. Spawn webhook handler (simplified version for testing)
    let state_clone = state.clone();
    let http_client = reqwest::Client::new();
    let local_endpoint_clone = local_endpoint.clone();

    tokio::spawn(async move {
        relay_client
            .run_webhook_loop(move |http_request| {
                let state = state_clone.clone();
                let http_client = http_client.clone();
                let local_endpoint = local_endpoint_clone.clone();

                async move {
                    let request_id = http_request.request_id.clone();
                    let timestamp = chrono::Utc::now();
                    let method = http_request.method.clone();
                    let path = http_request.path.clone();
                    let query = http_request.query.clone();
                    let request_headers = http_request.headers.clone();
                    let request_body =
                        String::from_utf8_lossy(&http_request.body).to_string();

                    // Forward request to local endpoint
                    let url = format!("{}{}", local_endpoint.trim_end_matches('/'), path);
                    let response = http_client
                        .post(&url)
                        .body(http_request.body.clone())
                        .send()
                        .await;

                    let (response_status, response_body) = match response {
                        Ok(resp) => {
                            let status = resp.status().as_u16() as u32;
                            let body = resp.text().await.unwrap_or_default();
                            (status, body)
                        }
                        Err(_) => (502, "Failed to forward".to_string()),
                    };

                    // Log the request/response
                    let log_entry = mcp_client::RequestLogEntry {
                        request_id: request_id.clone(),
                        timestamp,
                        method,
                        path,
                        query,
                        request_headers,
                        request_body,
                        response_status,
                        response_headers: std::collections::HashMap::new(),
                        response_body: response_body.clone(),
                    };

                    {
                        let mut s = state.write().await;
                        s.add_log_entry(log_entry);
                    }

                    api::HttpResponse {
                        request_id,
                        status_code: response_status,
                        headers: std::collections::HashMap::new(),
                        body: response_body.into_bytes(),
                    }
                }
            })
            .await
            .ok();
    });

    // Give the stream time to establish
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 7. Verify get_config shows connected status
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "get_config",
            "arguments": {}
        })),
    );

    let response = handle_request(request, state.clone())
        .await
        .expect("Tool call should return response");

    let result = response.result.expect("Should have result");
    let content = result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    assert!(
        content.contains("Connected"),
        "Should show connected status"
    );
    assert!(
        content.contains(&endpoint),
        "Should show webhook endpoint"
    );

    // 8. Send a webhook to the relay server
    let route = endpoint.rsplit('/').next().expect("Invalid endpoint format");
    let webhook_url = format!("{}/{}/test-path", http_addr, route);
    let webhook_body = r#"{"event": "mcp_test", "data": "hello"}"#;

    tracing::info!("Sending webhook to: {}", webhook_url);

    let http_client = reqwest::Client::new();
    let webhook_response = http_client
        .post(&webhook_url)
        .header("content-type", "application/json")
        .body(webhook_body)
        .send()
        .await
        .expect("Failed to send webhook");

    assert!(
        webhook_response.status().is_success(),
        "Webhook should succeed"
    );

    // 9. Wait for the webhook to be processed and logged
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 10. Verify mock server received the forwarded request
    let captured = mock_server
        .wait_for_requests(1, Duration::from_secs(5))
        .await
        .expect("Mock server didn't receive webhook");

    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "POST");
    assert_eq!(captured[0].path, "/test-path");

    // 11. Verify request log contains the webhook
    let request = make_request(
        "tools/call",
        Some(json!({
            "name": "get_request_log",
            "arguments": {}
        })),
    );

    let response = handle_request(request, state.clone())
        .await
        .expect("Tool call should return response");

    let result = response.result.expect("Should have result");
    let content = result["content"][0]["text"]
        .as_str()
        .expect("Should have text content");

    assert!(
        content.contains("/test-path"),
        "Request log should contain the webhook path"
    );
    assert!(
        content.contains("POST"),
        "Request log should show POST method"
    );
    assert!(
        content.contains("200"),
        "Request log should show response status"
    );

    tracing::info!("Request log:\n{}", content);
    tracing::info!("Full MCP webhook flow test passed!");

    server_handle.stop();
}
