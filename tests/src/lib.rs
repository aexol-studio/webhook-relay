//! Test helpers for e2e tests

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{Router, extract::State, routing::post};
use serde::Deserialize;
use tokio::sync::Mutex;

/// Get an OAuth access token from Keycloak using password grant
pub async fn get_test_token(
    issuer: &str,
    client_id: &str,
    username: &str,
    password: &str,
) -> Result<String> {
    let token_url = format!("{}/protocol/openid-connect/token", issuer);
    
    let client = reqwest::Client::new();
    let response = client
        .post(&token_url)
        .form(&[
            ("grant_type", "password"),
            ("client_id", client_id),
            ("username", username),
            ("password", password),
        ])
        .send()
        .await
        .context("Failed to request token")?;
    
    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        anyhow::bail!("Token request failed: {}", error_text);
    }
    
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
    }
    
    let token_response: TokenResponse = response.json().await
        .context("Failed to parse token response")?;
    
    Ok(token_response.access_token)
}

/// Captured webhook request
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Mock local HTTP server that captures incoming requests
pub struct MockLocalServer {
    pub addr: SocketAddr,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl MockLocalServer {
    /// Start a mock server that captures all POST requests
    pub async fn start() -> Result<Self> {
        let requests = Arc::new(Mutex::new(Vec::new()));
        
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        
        let requests_clone = requests.clone();
        
        let app = Router::new()
            .route("/{*path}", post(capture_handler))
            .route("/", post(capture_handler))
            .with_state(requests_clone);
        
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        
        Ok(Self { addr, requests })
    }
    
    /// Get all captured requests
    pub async fn get_requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().await.clone()
    }
    
    /// Wait for at least `count` requests, with timeout
    pub async fn wait_for_requests(&self, count: usize, timeout: std::time::Duration) -> Result<Vec<CapturedRequest>> {
        let start = std::time::Instant::now();
        loop {
            let requests = self.requests.lock().await.clone();
            if requests.len() >= count {
                return Ok(requests);
            }
            if start.elapsed() > timeout {
                anyhow::bail!("Timeout waiting for {} requests, got {}", count, requests.len());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

async fn capture_handler(
    State(requests): State<Arc<Mutex<Vec<CapturedRequest>>>>,
    req: axum::http::Request<axum::body::Body>,
) -> &'static str {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    
    let body = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    
    requests.lock().await.push(CapturedRequest {
        method,
        path,
        headers,
        body,
    });
    
    "OK"
}
