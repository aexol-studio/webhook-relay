use anyhow::{Context, Result};
use api::{
    GetConfigRequest, HttpResponse,
    relay_service_client::RelayServiceClient,
};
use tokio_stream::StreamExt;
use tonic::{
    Request,
    metadata::MetadataValue,
    transport::Channel,
};

use crate::proxy::Proxy;

pub struct GrpcClient {
    channel: Channel,
    access_token: String,
}

impl GrpcClient {
    pub async fn connect(server_address: &str, access_token: String) -> Result<Self> {
        let channel = Channel::from_shared(server_address.to_string())?
            .connect()
            .await
            .context("Failed to connect to server")?;
        
        Ok(Self {
            channel,
            access_token,
        })
    }
    
    fn create_client(&self) -> RelayServiceClient<Channel> {
        RelayServiceClient::new(self.channel.clone())
    }
    
    fn add_auth<T>(&self, request: &mut Request<T>) -> Result<()> {
        let token: MetadataValue<_> = format!("Bearer {}", self.access_token)
            .parse()
            .context("Invalid token format")?;
        request.metadata_mut().insert("authorization", token);
        Ok(())
    }
    
    pub async fn get_config(&self) -> Result<api::ClientConfig> {
        let mut client = self.create_client();
        let mut request = Request::new(GetConfigRequest {});
        self.add_auth(&mut request)?;
        
        let response = client.get_config(request).await
            .context("GetConfig RPC failed")?;
        
        response.into_inner().config
            .context("Server returned empty config")
    }
    
    pub async fn run_webhook_stream(&self, proxy: Proxy) -> Result<()> {
        let mut client = self.create_client();
        
        // Create channel for sending responses
        let (response_tx, response_rx) = tokio::sync::mpsc::channel::<HttpResponse>(32);
        let response_stream = tokio_stream::wrappers::ReceiverStream::new(response_rx);
        
        let mut request = Request::new(response_stream);
        self.add_auth(&mut request)?;
        
        let response = client.do_webhook(request).await
            .context("DoWebhook RPC failed")?;
        
        let mut request_stream = response.into_inner();
        
        tracing::info!("Connected to webhook stream");
        
        while let Some(result) = request_stream.next().await {
            match result {
                Ok(http_request) => {
                    let request_id = http_request.request_id.clone();
                    tracing::info!(
                        request_id = %request_id,
                        method = %http_request.method,
                        path = %http_request.path,
                        "Received webhook request"
                    );
                    
                    // Forward to local endpoint
                    let response = match proxy.forward(http_request).await {
                        Ok(resp) => resp,
                        Err(e) => {
                            tracing::error!(
                                request_id = %request_id,
                                error = %e,
                                "Failed to forward request"
                            );
                            // Return error response
                            HttpResponse {
                                request_id,
                                status_code: 502,
                                headers: Default::default(),
                                body: format!("Failed to forward request: {}", e).into_bytes(),
                            }
                        }
                    };
                    
                    // Send response back to server
                    if response_tx.send(response).await.is_err() {
                        tracing::error!("Failed to send response to server stream");
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Error receiving from server");
                    break;
                }
            }
        }
        
        tracing::info!("Webhook stream ended");
        Ok(())
    }
}
