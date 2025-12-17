//! Webhook relay client library
//!
//! This module provides the core client functionality for connecting to a webhook
//! relay server and forwarding requests to a local endpoint.

mod grpc;
mod proxy;

pub use common::AuthProvider;
pub use proxy::Proxy;

use std::sync::Arc;

use anyhow::Result;
use grpc::GrpcClient;

/// Configuration for running the client
pub struct ClientConfig<A: AuthProvider> {
    /// gRPC server address (e.g., "http://localhost:50051")
    pub server_address: String,
    /// Authentication provider for obtaining access tokens
    pub auth_provider: A,
    /// Local endpoint to forward webhooks to (e.g., "http://localhost:3000")
    pub local_endpoint: String,
    /// Optional session ID to reuse across client runs.
    pub session_id: Option<String>,
}

/// Result of starting the client - contains the endpoint URL and a handle to stop it
pub struct ClientHandle {
    /// The webhook endpoint URL assigned by the server
    pub endpoint: String,
    /// Handle to abort the client task
    abort_handle: tokio::task::AbortHandle,
}

impl ClientHandle {
    /// Stop the client
    pub fn stop(&self) {
        self.abort_handle.abort();
    }
}

/// Start the webhook relay client.
///
/// This connects to the relay server, gets the assigned endpoint, and starts
/// forwarding webhooks to the local endpoint in the background.
///
/// Returns a handle containing the endpoint URL and a way to stop the client.
pub async fn run_client<A: AuthProvider + 'static>(config: ClientConfig<A>) -> Result<ClientHandle> {
    let auth_provider = Arc::new(config.auth_provider);
    
    // Get initial access token
    let access_token = auth_provider.get_access_token().await?;
    
    // Connect to server
    let mut grpc_client =
        GrpcClient::connect(&config.server_address, access_token, config.session_id).await?;

    // Get config (establishes session, returns endpoint)
    let client_config = grpc_client.get_config().await?;
    let endpoint = client_config.endpoint.clone();

    tracing::info!(endpoint = %endpoint, "Client connected, starting webhook stream");

    // Create proxy with route prefix for fallback forwarding
    let proxy = Proxy::new(config.local_endpoint).with_route_prefix(&endpoint);

    // Spawn the webhook stream handler
    let join_handle = tokio::spawn(async move {
        if let Err(e) = grpc_client.run_webhook_stream(proxy).await {
            tracing::error!(error = %e, "Webhook stream error");
        }
    });

    Ok(ClientHandle {
        endpoint,
        abort_handle: join_handle.abort_handle(),
    })
}
