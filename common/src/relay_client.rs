//! Relay client that manages gRPC connection and session state

use anyhow::{Context, Result};
use api::{
    ClientConfig, GetConfigRequest, HttpRequest, HttpResponse,
    relay_service_client::RelayServiceClient,
};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::{Request, Streaming, metadata::MetadataValue, transport::Channel};

const SESSION_ID_HEADER: &str = "x-session-id";

/// A client for the webhook relay service.
///
/// Handles session management transparently - the session ID is automatically
/// extracted from GetConfig response and included in subsequent DoWebhook calls.
pub struct RelayClient {
    channel: Channel,
    access_token: String,
    session_id: Option<String>,
}

impl RelayClient {
    /// Connect to the relay server
    pub async fn connect(server_address: &str, access_token: String) -> Result<Self> {
        Self::connect_with_session(server_address, access_token, None).await
    }

    /// Connect to the relay server with an optional predefined session ID.
    ///
    /// If `session_id` is provided, it is sent on the initial `GetConfig` call.
    /// This allows clients to resume a previously-known session deterministically.
    pub async fn connect_with_session(
        server_address: &str,
        access_token: String,
        session_id: Option<String>,
    ) -> Result<Self> {
        let mut endpoint = Channel::from_shared(server_address.to_string())?;

        // Enable TLS for HTTPS endpoints
        if server_address.starts_with("https://") {
            endpoint = endpoint
                .tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())?;
        }

        let channel = endpoint
            .connect()
            .await
            .context("Failed to connect to server")?;

        Ok(Self {
            channel,
            access_token,
            session_id,
        })
    }

    /// Create a new client from an existing channel (useful for testing)
    pub fn from_channel(channel: Channel, access_token: String) -> Self {
        Self {
            channel,
            access_token,
            session_id: None,
        }
    }

    /// Create a new client from an existing channel with a predefined session ID.
    pub fn from_channel_with_session(
        channel: Channel,
        access_token: String,
        session_id: Option<String>,
    ) -> Self {
        Self {
            channel,
            access_token,
            session_id,
        }
    }

    /// Override session ID used for subsequent requests.
    pub fn set_session_id(&mut self, session_id: Option<String>) {
        self.session_id = session_id;
    }

    /// Get current session ID, if any.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    fn create_grpc_client(&self) -> RelayServiceClient<Channel> {
        RelayServiceClient::new(self.channel.clone())
    }

    fn add_metadata<T>(&self, request: &mut Request<T>) -> Result<()> {
        // Add authorization
        let token: MetadataValue<_> = format!("Bearer {}", self.access_token)
            .parse()
            .context("Invalid token format")?;
        request.metadata_mut().insert("authorization", token);

        // Add session_id if we have one
        if let Some(session_id) = &self.session_id {
            let session_value: MetadataValue<_> =
                session_id.parse().context("Invalid session_id format")?;
            request
                .metadata_mut()
                .insert(SESSION_ID_HEADER, session_value);
        }

        Ok(())
    }

    /// Get configuration from the server. This also establishes/retrieves the session.
    /// Must be called before `do_webhook` to establish the session.
    pub async fn get_config(&mut self) -> Result<ClientConfig> {
        tracing::debug!(
            session_id = ?self.session_id,
            "Sending GetConfig request"
        );

        let mut client = self.create_grpc_client();
        let mut request = Request::new(GetConfigRequest {});
        self.add_metadata(&mut request)?;

        let response = client
            .get_config(request)
            .await
            .context("GetConfig RPC failed")?;

        // Extract session_id from response metadata
        if let Some(session_value) = response.metadata().get(SESSION_ID_HEADER) {
            if let Ok(session_id) = session_value.to_str() {
                self.session_id = Some(session_id.to_string());
                tracing::debug!(session_id = %session_id, "Received session ID from server");
            }
        }

        let resp = response.into_inner();
        let config = resp.config.context("Server returned empty config")?;

        tracing::debug!(
            client_id = %config.client_id,
            endpoint = %config.endpoint,
            session_id = ?self.session_id,
            "GetConfig response received"
        );

        Ok(config)
    }

    /// Start the webhook stream. Returns a handle to send responses and a stream of requests.
    ///
    /// `get_config` must be called first to establish the session.
    pub async fn do_webhook(&self) -> Result<(mpsc::Sender<HttpResponse>, Streaming<HttpRequest>)> {
        if self.session_id.is_none() {
            anyhow::bail!("Session not established. Call get_config first.");
        }

        tracing::debug!(session_id = ?self.session_id, "Opening webhook stream (DoWebhook)");

        let mut client = self.create_grpc_client();

        let (response_tx, response_rx) = mpsc::channel::<HttpResponse>(32);
        let response_stream = tokio_stream::wrappers::ReceiverStream::new(response_rx);

        let mut request = Request::new(response_stream);
        self.add_metadata(&mut request)?;

        let response = client
            .do_webhook(request)
            .await
            .context("DoWebhook RPC failed")?;

        tracing::debug!(session_id = ?self.session_id, "Webhook stream established");

        Ok((response_tx, response.into_inner()))
    }

    /// Convenience method to run the webhook stream with a handler function.
    ///
    /// The handler receives each incoming request and should return a response.
    pub async fn run_webhook_loop<F, Fut>(&self, handler: F) -> Result<()>
    where
        F: Fn(HttpRequest) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = HttpResponse> + Send,
    {
        let (response_tx, mut request_stream) = self.do_webhook().await?;

        tracing::info!("Connected to webhook stream");

        while let Some(result) = request_stream.next().await {
            match result {
                Ok(http_request) => {
                    let request_id = http_request.request_id.clone();
                    tracing::info!(
                        request_id = %request_id,
                        method = %http_request.method,
                        path = %http_request.path,
                        body_len = http_request.body.len(),
                        headers_len = http_request.headers.len(),
                        has_client_cert = http_request.client_certificate.is_some(),
                        "Received webhook request"
                    );

                    let response = handler(http_request).await;

                    tracing::debug!(
                        request_id = %response.request_id,
                        status_code = response.status_code,
                        response_body_len = response.body.len(),
                        response_headers_len = response.headers.len(),
                        "Sending webhook response to server"
                    );

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
