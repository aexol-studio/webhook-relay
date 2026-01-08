//! End-to-end tests for webhook relay
//!
//! These tests require Keycloak to be running on localhost:8180
//! Start it with: docker-compose up -d keycloak

use std::time::Duration;

use server::config::Config;

use test_helpers::{MockLocalServer, TestAuthProvider};

// Test configuration
const KEYCLOAK_ISSUER: &str = "http://localhost:8180/realms/relay";
const KEYCLOAK_CLIENT_ID: &str = "webhook-relay-cli";
const TEST_USERNAME: &str = "testuser";
const TEST_PASSWORD: &str = "testpass";
// For Keycloak, the audience is the client_id (azp field in token)
const JWT_AUDIENCE: &str = "webhook-relay-cli";

fn init_tracing() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
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

/// Create a test auth provider for the standard test credentials
fn test_auth_provider() -> TestAuthProvider {
    TestAuthProvider::new(
        KEYCLOAK_ISSUER,
        KEYCLOAK_CLIENT_ID,
        TEST_USERNAME,
        TEST_PASSWORD,
    )
}

/// Test that a client can authenticate and get config
#[tokio::test]
async fn test_client_registration() {
    init_tracing();

    // Start the server with random ports
    let config = create_test_config(0, 0);
    let (handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    // Start client (black-box: just give it server address, auth provider, and local endpoint)
    let grpc_addr = format!("http://{}", addresses.grpc_addr);
    let client_handle = client::run_client(client::ClientConfig {
        server_address: grpc_addr,
        auth_provider: test_auth_provider(),
        local_endpoint: "http://localhost:9999".to_string(), // doesn't matter for this test
        session_id: None,
    })
    .await
    .expect("Failed to start client");

    // Verify we got an endpoint
    assert!(!client_handle.endpoint.is_empty());
    tracing::info!("Got endpoint: {}", client_handle.endpoint);

    client_handle.stop();
    handle.stop();
}

/// Test full webhook relay flow: server -> client -> local endpoint
///
/// This is a true black-box test:
/// 1. Start relay server
/// 2. Start mock local server (simulates user's local service)
/// 3. Start client (connects relay server to local server)
/// 4. Send HTTP request to relay server
/// 5. Verify mock server received the forwarded request
/// 6. Verify HTTP response came back through relay
#[tokio::test]
async fn test_webhook_relay_flow() {
    init_tracing();

    // 1. Start mock local server (this simulates the user's local application)
    let mock_server = MockLocalServer::start()
        .await
        .expect("Failed to start mock server");
    let local_endpoint = format!("http://{}", mock_server.addr);
    tracing::info!("Mock local server listening on {}", local_endpoint);

    // 2. Start the relay server
    let config = create_test_config(0, 0);
    let (server_handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    let http_addr = format!("http://{}", addresses.http_addr);
    let grpc_addr = format!("http://{}", addresses.grpc_addr);
    tracing::info!("Relay server HTTP: {}, gRPC: {}", http_addr, grpc_addr);

    // 3. Start the client with auth provider
    let client_handle = client::run_client(client::ClientConfig {
        server_address: grpc_addr,
        auth_provider: test_auth_provider(),
        local_endpoint,
        session_id: None,
    })
    .await
    .expect("Failed to start client");

    // Extract route from endpoint
    let route = client_handle
        .endpoint
        .rsplit('/')
        .next()
        .expect("Invalid endpoint format");
    tracing::info!("Client connected with route: {}", route);

    // Give the client stream time to establish
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Send a webhook to the relay server's HTTP endpoint
    let webhook_url = format!("{}/{}/test-path", http_addr, route);
    let webhook_body = r#"{"event": "test", "data": "hello"}"#;

    tracing::info!("Sending webhook to: {}", webhook_url);

    let http_client = reqwest::Client::new();
    let webhook_response = http_client
        .post(&webhook_url)
        .header("content-type", "application/json")
        .header("x-custom-header", "test-value")
        .body(webhook_body)
        .send()
        .await
        .expect("Failed to send webhook");

    // 5. Verify the response from relay (which came from mock server -> client -> relay)
    assert!(
        webhook_response.status().is_success(),
        "Webhook request failed with status: {}",
        webhook_response.status()
    );

    // 6. Verify mock server received the forwarded request
    let captured = mock_server
        .wait_for_requests(1, Duration::from_secs(5))
        .await
        .expect("Mock server didn't receive webhook");

    assert_eq!(captured.len(), 1);
    let captured_req = &captured[0];
    assert_eq!(captured_req.method, "POST");
    assert_eq!(captured_req.path, "/test-path");
    assert_eq!(String::from_utf8_lossy(&captured_req.body), webhook_body);

    // Verify custom header was forwarded
    let has_custom_header = captured_req
        .headers
        .iter()
        .any(|(k, v)| k == "x-custom-header" && v == "test-value");
    assert!(has_custom_header, "Custom header was not forwarded");

    // Verify X-Forwarded-For header is set
    let has_forwarded_for = captured_req
        .headers
        .iter()
        .any(|(k, _)| k == "x-forwarded-for");
    assert!(has_forwarded_for, "X-Forwarded-For header was not set");

    // Verify X-Forwarded-Proto header is set
    let has_forwarded_proto = captured_req
        .headers
        .iter()
        .any(|(k, v)| k == "x-forwarded-proto" && v == "http");
    assert!(
        has_forwarded_proto,
        "X-Forwarded-Proto header was not set correctly"
    );

    tracing::info!("Webhook successfully relayed!");

    // Cleanup
    client_handle.stop();
    server_handle.stop();
}

/// Test that unauthenticated requests are rejected
#[tokio::test]
async fn test_unauthenticated_rejected() {
    init_tracing();

    // Start the server
    let config = create_test_config(0, 0);
    let (handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    let grpc_addr = format!("http://{}", addresses.grpc_addr);

    // Try to connect without auth token (empty string)
    let result = client::run_client(client::ClientConfig {
        server_address: grpc_addr,
        auth_provider: test_helpers::StaticTokenAuthProvider::empty(),
        local_endpoint: "http://localhost:9999".to_string(),
        session_id: None,
    })
    .await;

    assert!(result.is_err(), "Connection should have been rejected");

    handle.stop();
}

/// Test that invalid tokens are rejected
#[tokio::test]
async fn test_invalid_token_rejected() {
    init_tracing();

    // Start the server
    let config = create_test_config(0, 0);
    let (handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    let grpc_addr = format!("http://{}", addresses.grpc_addr);

    // Try with invalid token
    let result = client::run_client(client::ClientConfig {
        server_address: grpc_addr,
        auth_provider: test_helpers::StaticTokenAuthProvider::invalid(),
        local_endpoint: "http://localhost:9999".to_string(),
        session_id: None,
    })
    .await;

    assert!(result.is_err(), "Connection should have been rejected");

    handle.stop();
}

/// Test that tokens with wrong audience are rejected
#[tokio::test]
async fn test_wrong_audience_rejected() {
    init_tracing();

    // Start the server with a different expected audience
    let mut config = create_test_config(0, 0);
    config.jwt_audience = "wrong-audience".to_string();

    let (handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    let grpc_addr = format!("http://{}", addresses.grpc_addr);

    // Try to use the token - should be rejected due to audience mismatch
    // The test auth provider will get a valid token with audience = webhook-relay-cli
    let result = client::run_client(client::ClientConfig {
        server_address: grpc_addr,
        auth_provider: test_auth_provider(),
        local_endpoint: "http://localhost:9999".to_string(),
        session_id: None,
    })
    .await;

    assert!(
        result.is_err(),
        "Connection should have been rejected due to audience mismatch"
    );

    handle.stop();
}

/// Test that X-Forwarded headers are properly handled (preserved or added)
#[tokio::test]
async fn test_x_forwarded_headers() {
    init_tracing();

    // Start mock local server
    let mock_server = MockLocalServer::start()
        .await
        .expect("Failed to start mock server");
    let local_endpoint = format!("http://{}", mock_server.addr);

    // Start the relay server
    let config = create_test_config(0, 0);
    let (server_handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");

    let http_addr = format!("http://{}", addresses.http_addr);
    let grpc_addr = format!("http://{}", addresses.grpc_addr);

    // Start client with auth provider
    let client_handle = client::run_client(client::ClientConfig {
        server_address: grpc_addr,
        auth_provider: test_auth_provider(),
        local_endpoint,
        session_id: None,
    })
    .await
    .expect("Failed to start client");

    let route = client_handle
        .endpoint
        .rsplit('/')
        .next()
        .expect("Invalid endpoint format");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send webhook WITH existing X-Forwarded headers (simulating being behind a proxy)
    let webhook_url = format!("{}/{}/test", http_addr, route);
    let http_client = reqwest::Client::new();

    let webhook_response = http_client
        .post(&webhook_url)
        .header("x-forwarded-for", "203.0.113.50")
        .header("x-forwarded-host", "original.example.com")
        .header("x-forwarded-proto", "https")
        .body("test")
        .send()
        .await
        .expect("Failed to send webhook");

    assert!(webhook_response.status().is_success());

    // Wait for the mock server to receive the request
    let captured = mock_server
        .wait_for_requests(1, Duration::from_secs(5))
        .await
        .expect("Mock server didn't receive webhook");

    let captured_req = &captured[0];

    // X-Forwarded-For should have the original IP appended with the relay server's client IP
    let forwarded_for = captured_req
        .headers
        .iter()
        .find(|(k, _)| k == "x-forwarded-for")
        .map(|(_, v)| v.as_str())
        .expect("X-Forwarded-For header missing");
    assert!(
        forwarded_for.starts_with("203.0.113.50, "),
        "X-Forwarded-For should start with original IP: {}",
        forwarded_for
    );

    // X-Forwarded-Host should be preserved (not overwritten)
    let forwarded_host = captured_req
        .headers
        .iter()
        .find(|(k, _)| k == "x-forwarded-host")
        .map(|(_, v)| v.as_str())
        .expect("X-Forwarded-Host header missing");
    assert_eq!(
        forwarded_host, "original.example.com",
        "X-Forwarded-Host should be preserved"
    );

    // X-Forwarded-Proto should be preserved (not overwritten)
    let forwarded_proto = captured_req
        .headers
        .iter()
        .find(|(k, _)| k == "x-forwarded-proto")
        .map(|(_, v)| v.as_str())
        .expect("X-Forwarded-Proto header missing");
    assert_eq!(
        forwarded_proto, "https",
        "X-Forwarded-Proto should be preserved"
    );

    tracing::info!("X-Forwarded headers test passed!");

    client_handle.stop();
    server_handle.stop();
}
