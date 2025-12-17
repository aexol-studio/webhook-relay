use api::HttpResponse;
use common::RelayClient;

use crate::proxy::Proxy;

pub struct GrpcClient {
    relay_client: RelayClient,
}

impl GrpcClient {
    pub async fn connect(
        server_address: &str,
        access_token: String,
        session_id: Option<String>,
    ) -> anyhow::Result<Self> {
        let relay_client = RelayClient::connect_with_session(server_address, access_token, session_id).await?;
        Ok(Self { relay_client })
    }

    pub async fn get_config(&mut self) -> anyhow::Result<api::ClientConfig> {
        self.relay_client.get_config().await
    }

    pub async fn run_webhook_stream(&self, proxy: Proxy) -> anyhow::Result<()> {
        self.relay_client
            .run_webhook_loop(move |http_request| {
                let proxy = proxy.clone();
                async move {
                    let request_id = http_request.request_id.clone();
                    match proxy.forward(http_request).await {
                        Ok(resp) => resp,
                        Err(e) => {
                            tracing::error!(
                                request_id = %request_id,
                                error = %e,
                                "Failed to forward request"
                            );
                            HttpResponse {
                                request_id,
                                status_code: 502,
                                headers: Default::default(),
                                body: format!("Failed to forward request: {}", e).into_bytes(),
                            }
                        }
                    }
                }
            })
            .await
    }
}
