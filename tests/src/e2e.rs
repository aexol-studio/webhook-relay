//! End-to-end tests for webhook relay
//!
//! These tests require Keycloak to be running on localhost:8180
//! Start it with: docker-compose up -d keycloak

use std::time::Duration;

use api::relay_service_client::RelayServiceClient;
use api::{GetConfigRequest, HttpResponse};
use tokio_stream::StreamExt;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;
use server::config::Config;

use test_helpers::{MockLocalServer, get_test_token};

// Test configuration
const KEYCLOAK_ISSUER: &str = "http://localhost:8180/realms/relay";
const KEYCLOAK_CLIENT_ID: &str = "webhook-relay-cli";
const TEST_USERNAME: &str = "testuser";
const TEST_PASSWORD: &str = "testpass";
// For Keycloak, the audience is the client_id (azp field in token)
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

async fn create_grpc_client(grpc_addr: &str) -> RelayServiceClient<Channel> {
    let channel = Channel::from_shared(grpc_addr.to_string())
        .unwrap()
        .connect()
        .await
        .expect("Failed to connect to gRPC server");
    
    RelayServiceClient::new(channel)
}

fn add_auth_header<T>(request: &mut Request<T>, token: &str) {
    let value: MetadataValue<_> = format!("Bearer {}", token)
        .parse()
        .expect("Invalid token format");
    request.metadata_mut().insert("authorization", value);
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
    
    // Get OAuth token
    let token = get_test_token(KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID, TEST_USERNAME, TEST_PASSWORD)
        .await
        .expect("Failed to get test token");
    
    // Connect to gRPC
    let grpc_addr = format!("http://{}", addresses.grpc_addr);
    let mut client = create_grpc_client(&grpc_addr).await;
    
    // Get config (registers the client)
    let mut request = Request::new(GetConfigRequest {});
    add_auth_header(&mut request, &token);
    
    let response = client.get_config(request).await.expect("GetConfig failed");
    let config = response.into_inner().config.expect("No config returned");
    
    assert_eq!(config.client_id, TEST_USERNAME);
    assert!(!config.endpoint.is_empty());
    tracing::info!("Got endpoint: {}", config.endpoint);
    
    handle.stop();
}

/// Test full webhook relay flow: server -> client -> local endpoint
#[tokio::test]
async fn test_webhook_relay_flow() {
    init_tracing();
    
    // Start mock local server first
    let mock_server = MockLocalServer::start()
        .await
        .expect("Failed to start mock server");
    let local_endpoint = format!("http://{}", mock_server.addr);
    tracing::info!("Mock server listening on {}", local_endpoint);
    
    // Start the relay server with random ports
    let config = create_test_config(0, 0);
    let (handle, addresses) = server::run_server(config)
        .await
        .expect("Failed to start server");
    
    let http_addr = format!("http://{}", addresses.http_addr);
    let grpc_addr = format!("http://{}", addresses.grpc_addr);
    tracing::info!("Server HTTP: {}, gRPC: {}", http_addr, grpc_addr);
    
    // Get OAuth token
    let token = get_test_token(KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID, TEST_USERNAME, TEST_PASSWORD)
        .await
        .expect("Failed to get test token");
    
    // Connect to gRPC and get config (this registers the client and assigns a route)
    let mut client = create_grpc_client(&grpc_addr).await;
    
    let mut get_config_request = Request::new(GetConfigRequest {});
    add_auth_header(&mut get_config_request, &token);
    
    let response = client.get_config(get_config_request).await.expect("GetConfig failed");
    let client_config = response.into_inner().config.expect("No config returned");
    
    let route = client_config.endpoint
        .rsplit('/')
        .next()
        .expect("Invalid endpoint format");
    tracing::info!("Client registered with route: {}", route);
    
    // Start the webhook stream (same client_id will reuse the same route)
    let (response_tx, response_rx) = tokio::sync::mpsc::channel::<HttpResponse>(32);
    let response_stream = tokio_stream::wrappers::ReceiverStream::new(response_rx);
    
    let mut stream_request = Request::new(response_stream);
    add_auth_header(&mut stream_request, &token);
    
    let stream_response = client.do_webhook(stream_request)
        .await
        .expect("DoWebhook failed");
    let mut request_stream = stream_response.into_inner();
    
    // Spawn task to handle incoming webhook requests and forward to local server
    let local_endpoint_clone = local_endpoint.clone();
    let forward_task = tokio::spawn(async move {
        let http_client = reqwest::Client::new();
        
        while let Some(result) = request_stream.next().await {
            match result {
                Ok(http_request) => {
                    tracing::info!(
                        "Received webhook: {} {}",
                        http_request.method,
                        http_request.path
                    );
                    
                    // Forward to local endpoint
                    let url = format!("{}{}", local_endpoint_clone, http_request.path);
                    let mut req_builder = http_client.post(&url);
                    
                    for (key, value) in &http_request.headers {
                        req_builder = req_builder.header(key, value);
                    }
                    
                    let local_response = req_builder
                        .body(http_request.body.clone())
                        .send()
                        .await;
                    
                    let response = match local_response {
                        Ok(resp) => {
                            let status = resp.status().as_u16() as u32;
                            let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                            HttpResponse {
                                request_id: http_request.request_id,
                                status_code: status,
                                headers: Default::default(),
                                body,
                            }
                        }
                        Err(e) => {
                            tracing::error!("Forward failed: {}", e);
                            HttpResponse {
                                request_id: http_request.request_id,
                                status_code: 502,
                                headers: Default::default(),
                                body: format!("Forward failed: {}", e).into_bytes(),
                            }
                        }
                    };
                    
                    if response_tx.send(response).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Stream error: {}", e);
                    break;
                }
            }
        }
    });
    
    // Give the stream a moment to establish
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Send a webhook to the server's HTTP endpoint
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
    
    assert!(
        webhook_response.status().is_success(),
        "Webhook request failed with status: {}",
        webhook_response.status()
    );

    // Wait for the mock server to receive the request
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
    forward_task.abort();
    handle.stop();
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
    
    let channel = Channel::from_shared(grpc_addr)
        .unwrap()
        .connect()
        .await
        .expect("Failed to connect");
    
    let mut client = RelayServiceClient::new(channel);
    
    // Try to get config without auth
    let request = Request::new(GetConfigRequest {});
    let result = client.get_config(request).await;
    
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    
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
    
    let channel = Channel::from_shared(grpc_addr)
        .unwrap()
        .connect()
        .await
        .expect("Failed to connect");
    
    let mut client = RelayServiceClient::new(channel);
    
    // Try with invalid token
    let mut request = Request::new(GetConfigRequest {});
    add_auth_header(&mut request, "invalid.token.here");
    
    let result = client.get_config(request).await;
    
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    
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
    
    // Get a valid OAuth token (with audience = webhook-relay-cli)
    let token = get_test_token(KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID, TEST_USERNAME, TEST_PASSWORD)
        .await
        .expect("Failed to get test token");
    
    let grpc_addr = format!("http://{}", addresses.grpc_addr);
    let mut client = create_grpc_client(&grpc_addr).await;
    
    // Try to use the token - should be rejected due to audience mismatch
    let mut request = Request::new(GetConfigRequest {});
    add_auth_header(&mut request, &token);
    
    let result = client.get_config(request).await;
    
    assert!(result.is_err(), "Request should have been rejected");
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert!(
        status.message().contains("audience"),
        "Error message should mention audience: {}",
        status.message()
    );

    handle.stop();
}

/// Test that X-Forwarded headers are properly handled (preserved or added)
#[tokio::test]
async fn test_x_forwarded_headers() {
    init_tracing();

    // Start mock local server first
    let mock_server = MockLocalServer::start()
        .await
        .expect("Failed to start mock server");
    let local_endpoint = format!("http://{}", mock_server.addr);

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

    // Connect and register
    let mut client = create_grpc_client(&grpc_addr).await;

    let mut get_config_request = Request::new(GetConfigRequest {});
    add_auth_header(&mut get_config_request, &token);

    let response = client
        .get_config(get_config_request)
        .await
        .expect("GetConfig failed");
    let client_config = response.into_inner().config.expect("No config returned");

    let route = client_config
        .endpoint
        .rsplit('/')
        .next()
        .expect("Invalid endpoint format");

    // Start the webhook stream
    let (response_tx, response_rx) = tokio::sync::mpsc::channel::<HttpResponse>(32);
    let response_stream = tokio_stream::wrappers::ReceiverStream::new(response_rx);

    let mut stream_request = Request::new(response_stream);
    add_auth_header(&mut stream_request, &token);

    let stream_response = client
        .do_webhook(stream_request)
        .await
        .expect("DoWebhook failed");
    let mut request_stream = stream_response.into_inner();

    // Spawn task to forward webhooks
    let local_endpoint_clone = local_endpoint.clone();
    let forward_task = tokio::spawn(async move {
        let http_client = reqwest::Client::new();

        while let Some(result) = request_stream.next().await {
            if let Ok(http_request) = result {
                let url = format!("{}{}", local_endpoint_clone, http_request.path);
                let mut req_builder = http_client.post(&url);

                for (key, value) in &http_request.headers {
                    req_builder = req_builder.header(key, value);
                }

                let local_response = req_builder.body(http_request.body.clone()).send().await;

                let response = match local_response {
                    Ok(resp) => {
                        let status = resp.status().as_u16() as u32;
                        let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                        HttpResponse {
                            request_id: http_request.request_id,
                            status_code: status,
                            headers: Default::default(),
                            body,
                        }
                    }
                    Err(_) => HttpResponse {
                        request_id: http_request.request_id,
                        status_code: 502,
                        headers: Default::default(),
                        body: vec![],
                    },
                };

                if response_tx.send(response).await.is_err() {
                    break;
                }
            }
        }
    });

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

    forward_task.abort();
    handle.stop();
}
