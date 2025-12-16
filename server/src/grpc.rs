use std::pin::Pin;
use std::sync::Arc;

use api::{
    GetConfigRequest, GetConfigResponse, HttpRequest, HttpResponse,
    relay_service_server::RelayService,
};
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status, Streaming};

use crate::auth::{JwksCache, validate_auth};
use crate::client_manager::{ClientManager, PendingRequest};

pub struct RelayServiceImpl {
    client_manager: Arc<ClientManager>,
    jwks_cache: Arc<JwksCache>,
}

impl RelayServiceImpl {
    pub fn new(client_manager: Arc<ClientManager>, jwks_cache: Arc<JwksCache>) -> Self {
        Self {
            client_manager,
            jwks_cache,
        }
    }
}

#[tonic::async_trait]
impl RelayService for RelayServiceImpl {
    async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        let claims = validate_auth(&request, &self.jwks_cache).await?;
        let user_id = claims.user_id().to_string();
        
        // Create a dummy channel since GetConfig doesn't actually set up streaming
        // The real channel is set up in DoWebhook
        let (tx, _rx) = mpsc::channel(1);
        
        let config = self.client_manager
            .register_client(user_id, tx)
            .await;
        
        Ok(Response::new(GetConfigResponse {
            config: Some(config),
        }))
    }
    
    type DoWebhookStream = Pin<Box<dyn Stream<Item = Result<HttpRequest, Status>> + Send>>;
    
    async fn do_webhook(
        &self,
        request: Request<Streaming<HttpResponse>>,
    ) -> Result<Response<Self::DoWebhookStream>, Status> {
        let claims = validate_auth(&request, &self.jwks_cache).await?;
        let user_id = claims.user_id().to_string();
        
        let (request_tx, request_rx) = mpsc::channel::<HttpRequest>(32);
        
        let config = self.client_manager
            .register_client(user_id.clone(), request_tx)
            .await;
        
        let route = config.endpoint.rsplit('/').next().unwrap_or("").to_string();
        
        tracing::info!(
            client_id = %user_id,
            endpoint = %config.endpoint,
            "Client connected to webhook stream"
        );
        
        // Get the client to access pending_requests
        let client = self.client_manager
            .get_client(&route)
            .await
            .ok_or_else(|| Status::internal("Client not found after registration"))?;
        
        let pending_requests = client.pending_requests.clone();
        let client_manager = self.client_manager.clone();
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
            client_manager.unregister_client(&route_clone).await;
            tracing::info!(route = %route_clone, "Client stream ended, unregistered");
        });
        
        let output_stream = ReceiverStream::new(request_rx).map(Ok);
        
        Ok(Response::new(Box::pin(output_stream)))
    }
}

pub async fn send_request_to_client(
    client: &Arc<crate::client_manager::ConnectedClient>,
    request: HttpRequest,
    timeout: std::time::Duration,
) -> Result<HttpResponse, Status> {
    let request_id = request.request_id.clone();
    
    // Create oneshot channel for response
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    
    // Register pending request
    {
        let mut pending = client.pending_requests.write().await;
        pending.insert(request_id.clone(), PendingRequest { response_tx });
    }
    
    // Send request to client
    client.request_tx
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
            Err(Status::unavailable("Client disconnected while waiting for response"))
        }
        Err(_) => {
            // Timeout, remove pending request
            let mut pending = client.pending_requests.write().await;
            pending.remove(&request_id);
            Err(Status::deadline_exceeded("Request timed out"))
        }
    }
}
