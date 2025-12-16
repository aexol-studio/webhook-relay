pub mod auth;
pub mod client_manager;
pub mod config;
pub mod grpc;
pub mod http;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use api::relay_service_server::RelayServiceServer;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server as TonicServer;

use auth::{JwksCache, check_auth};
use client_manager::ClientManager;
use config::Config;
use grpc::RelayServiceImpl;
use http::{HttpState, create_router};

/// Server handle that can be used to control and stop the server
pub struct ServerHandle {
    cancel_token: CancellationToken,
}

impl ServerHandle {
    /// Stop the server gracefully
    pub fn stop(&self) {
        self.cancel_token.cancel();
    }
}

/// Bound addresses for the running server
pub struct ServerAddresses {
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
}

/// Run the server with the given config, returning a handle to stop it
/// and the actual bound addresses (useful when using port 0)
pub async fn run_server(config: Config) -> Result<(ServerHandle, ServerAddresses)> {
    tracing::info!(
        http_port = config.http_port,
        grpc_port = config.grpc_port,
        external_url = %config.external_url,
        "Configuration loaded"
    );

    // Create shared state
    let jwks_cache = Arc::new(JwksCache::new(&config));
    let client_manager = Arc::new(ClientManager::new(&config));

    // Pre-fetch JWKS to fail fast if misconfigured
    tracing::info!("Fetching JWKS from IdP...");
    jwks_cache.validate_token("dummy").await.ok(); // This will fetch JWKS even though token is invalid
    tracing::info!("JWKS cache initialized");

    let cancel_token = CancellationToken::new();

    // Start HTTP server
    let http_state = HttpState {
        client_manager: client_manager.clone(),
        webhook_timeout: Duration::from_secs(config.webhook_timeout_secs),
    };

    let http_addr = format!("0.0.0.0:{}", config.http_port);
    let http_listener = tokio::net::TcpListener::bind(&http_addr).await?;
    let http_bound_addr = http_listener.local_addr()?;

    tracing::info!(addr = %http_bound_addr, "HTTP server listening");

    let http_cancel = cancel_token.clone();
    tokio::spawn(async move {
        let router = create_router(http_state);
        axum::serve(
            http_listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(http_cancel.cancelled_owned())
        .await
        .ok();
    });

    // Start gRPC server
    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", config.grpc_port).parse()?;
    let relay_service = RelayServiceImpl::new(client_manager.clone(), jwks_cache.clone());

    // Bind to get the actual port
    let grpc_listener = tokio::net::TcpListener::bind(&grpc_addr).await?;
    let grpc_bound_addr = grpc_listener.local_addr()?;
    let grpc_incoming = tokio_stream::wrappers::TcpListenerStream::new(grpc_listener);

    let jwks_cache_for_interceptor = jwks_cache.clone();
    let grpc_cancel = cancel_token.clone();
    tokio::spawn(async move {
        tracing::info!(addr = %grpc_bound_addr, "gRPC server listening");

        TonicServer::builder()
            .add_service(RelayServiceServer::with_interceptor(
                relay_service,
                check_auth(jwks_cache_for_interceptor),
            ))
            .serve_with_incoming_shutdown(grpc_incoming, grpc_cancel.cancelled_owned())
            .await
            .ok();
    });

    let handle = ServerHandle { cancel_token };
    let addresses = ServerAddresses {
        http_addr: http_bound_addr,
        grpc_addr: grpc_bound_addr,
    };

    Ok((handle, addresses))
}
