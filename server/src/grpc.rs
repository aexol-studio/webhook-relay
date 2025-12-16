use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use api::{
    GetConfigRequest, GetConfigResponse, HttpRequest, HttpResponse,
    relay_service_server::RelayService,
};
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status, Streaming};

use crate::auth::{JwksCache, validate_auth};
use crate::config::Config;

const SESSION_ID_HEADER: &str = "x-session-id";

pub struct PendingRequest {
    pub response_tx: oneshot::Sender<HttpResponse>,
}

/// Connected client with its request channel and pending requests
pub struct ConnectedClient {
    pub request_tx: mpsc::Sender<HttpRequest>,
    pub pending_requests: Arc<RwLock<HashMap<String, PendingRequest>>>,
}

/// Active client connections indexed by route
pub type ClientConnections = Arc<RwLock<HashMap<String, Arc<ConnectedClient>>>>;

pub struct RelayServiceImpl {
    connections: ClientConnections,
    jwks_cache: Arc<JwksCache>,
    external_url: String,
}

impl RelayServiceImpl {
    pub fn new(connections: ClientConnections, jwks_cache: Arc<JwksCache>, config: &Config) -> Self {
        Self {
            connections,
            jwks_cache,
            external_url: config.external_url.clone().trim_end_matches('/').to_string(),
        }
    }
}

/// Generate a route from user_id and session_id using a hash
fn session_to_route(user_id: &str, session_id: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(session_id.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Generate a new session ID
fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Extract session_id from request metadata, or generate a new one
fn get_or_create_session_id<T>(request: &Request<T>) -> (String, bool) {
    if let Some(value) = request.metadata().get(SESSION_ID_HEADER) {
        if let Ok(session_id) = value.to_str() {
            return (session_id.to_string(), false);
        }
    }
    (generate_session_id(), true)
}

/// Extract session_id from request metadata
fn get_session_id<T>(request: &Request<T>) -> Result<String, Status> {
    request
        .metadata()
        .get(SESSION_ID_HEADER)
        .ok_or_else(|| Status::invalid_argument("Missing x-session-id metadata"))?
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| Status::invalid_argument("Invalid x-session-id metadata"))
}

#[tonic::async_trait]
impl RelayService for RelayServiceImpl {
    async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        let claims = validate_auth(&request, &self.jwks_cache).await?;
        let user_id = claims.user_id().to_string();

        let (session_id, is_new) = get_or_create_session_id(&request);
        let route = session_to_route(&user_id, &session_id);
        let endpoint = format!("{}/{}", self.external_url, route);

        tracing::info!(
            user_id = %user_id,
            session_id = %session_id,
            route = %route,
            is_new_session = is_new,
            "GetConfig called"
        );

        let mut response = Response::new(GetConfigResponse {
            config: Some(api::ClientConfig {
                client_id: user_id,
                endpoint,
            }),
        });

        // Always return session_id in response metadata
        response.metadata_mut().insert(
            SESSION_ID_HEADER,
            session_id.parse().map_err(|_| Status::internal("Failed to set session header"))?,
        );

        Ok(response)
    }

    type DoWebhookStream = Pin<Box<dyn Stream<Item = Result<HttpRequest, Status>> + Send>>;

    async fn do_webhook(
        &self,
        request: Request<Streaming<HttpResponse>>,
    ) -> Result<Response<Self::DoWebhookStream>, Status> {
        let claims = validate_auth(&request, &self.jwks_cache).await?;
        let user_id = claims.user_id().to_string();
        let session_id = get_session_id(&request)?;
        let route = session_to_route(&user_id, &session_id);

        let (request_tx, request_rx) = mpsc::channel::<HttpRequest>(32);
        let pending_requests = Arc::new(RwLock::new(HashMap::new()));

        let client = Arc::new(ConnectedClient {
            request_tx,
            pending_requests: pending_requests.clone(),
        });

        // Register client connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(route.clone(), client);
        }

        tracing::info!(
            user_id = %user_id,
            session_id = %session_id,
            route = %route,
            "Client connected to webhook stream"
        );

        let connections = self.connections.clone();
        let route_clone = route.clone();

        // Spawn task to handle incoming responses from client
        let mut in_stream = request.into_inner();
        tokio::spawn(async move {
            while let Some(result) = in_stream.next().await {
                match result {
                    Ok(response) => {
                        let request_id = response.request_id.clone();
                        let mut pending = pending_requests.write().await;
                        if let Some(pending_req) = pending.remove(&request_id) {
                            let _ = pending_req.response_tx.send(response);
                        } else {
                            tracing::warn!(
                                request_id = %request_id,
                                "Received response for unknown request"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Error receiving response from client");
                        break;
                    }
                }
            }

            // Client disconnected, unregister
            let mut connections = connections.write().await;
            connections.remove(&route_clone);
            tracing::info!(route = %route_clone, "Client stream ended, unregistered");
        });

        let output_stream = ReceiverStream::new(request_rx).map(Ok);

        let mut response = Response::new(Box::pin(output_stream) as Self::DoWebhookStream);
        
        // Return session_id in response metadata
        response.metadata_mut().insert(
            SESSION_ID_HEADER,
            session_id.parse().map_err(|_| Status::internal("Failed to set session header"))?,
        );

        Ok(response)
    }
}

pub async fn send_request_to_client(
    client: &Arc<ConnectedClient>,
    request: HttpRequest,
    timeout: std::time::Duration,
) -> Result<HttpResponse, Status> {
    let request_id = request.request_id.clone();

    // Create oneshot channel for response
    let (response_tx, response_rx) = oneshot::channel();

    // Register pending request
    {
        let mut pending = client.pending_requests.write().await;
        pending.insert(request_id.clone(), PendingRequest { response_tx });
    }

    // Send request to client
    client
        .request_tx
        .send(request)
        .await
        .map_err(|_| Status::unavailable("Client disconnected"))?;

    // Wait for response with timeout
    match tokio::time::timeout(timeout, response_rx).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) => {
            // Channel closed, remove pending request
            let mut pending = client.pending_requests.write().await;
            pending.remove(&request_id);
            Err(Status::unavailable(
                "Client disconnected while waiting for response",
            ))
        }
        Err(_) => {
            // Timeout, remove pending request
            let mut pending = client.pending_requests.write().await;
            pending.remove(&request_id);
            Err(Status::deadline_exceeded("Request timed out"))
        }
    }
}
