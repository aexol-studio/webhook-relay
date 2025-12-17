use std::collections::HashMap;

use anyhow::{Context, Result};
use api::{HttpRequest, HttpResponse};
use base64::{Engine, prelude::BASE64_STANDARD};

// Headers for forwarding client certificate information
const X_CLIENT_CERT: &str = "x-client-cert";
const X_CLIENT_CERT_SUBJECT: &str = "x-client-cert-subject";
const X_CLIENT_CERT_ISSUER: &str = "x-client-cert-issuer";
const X_CLIENT_CERT_SERIAL: &str = "x-client-cert-serial";

#[derive(Clone)]
pub struct Proxy {
    client: reqwest::Client,
    local_endpoint: String,
    /// Route prefix extracted from the endpoint URL (e.g., "/abc123def456...")
    route_prefix: Option<String>,
}

impl Proxy {
    pub fn new(local_endpoint: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            local_endpoint: local_endpoint.trim_end_matches('/').to_string(),
            route_prefix: None,
        }
    }

    /// Create a new proxy with a route prefix for fallback forwarding.
    ///
    /// When forwarding requests, if the unprefixed path returns 404,
    /// the proxy will retry with the route prefix prepended to the path.
    pub fn with_route_prefix(mut self, endpoint: &str) -> Self {
        // Extract route from endpoint URL (e.g., "https://example.com/abc123" -> "/abc123")
        if let Some(pos) = endpoint.rfind('/') {
            let route = &endpoint[pos..];
            if route.len() > 1 {
                self.route_prefix = Some(route.to_string());
            }
        }
        self
    }

    pub async fn forward(&self, request: HttpRequest) -> Result<HttpResponse> {
        // First, try the unprefixed path
        let response = self.forward_to_path(&request, &request.path).await?;

        // If we got 404 and have a route prefix, try the prefixed path
        if response.status_code == 404 {
            if let Some(prefix) = &self.route_prefix {
                let prefixed_path = format!("{}{}", prefix, request.path);
                tracing::debug!(
                    request_id = %request.request_id,
                    unprefixed_path = %request.path,
                    prefixed_path = %prefixed_path,
                    "Unprefixed path returned 404, retrying with route prefix"
                );
                return self.forward_to_path(&request, &prefixed_path).await;
            }
        }

        Ok(response)
    }

    async fn forward_to_path(&self, request: &HttpRequest, path: &str) -> Result<HttpResponse> {
        let url = if request.query.is_empty() {
            format!("{}{}", self.local_endpoint, path)
        } else {
            format!("{}{}?{}", self.local_endpoint, path, request.query)
        };

        let has_client_cert = request.client_certificate.is_some();

        tracing::debug!(
            request_id = %request.request_id,
            method = %request.method,
            url = %url,
            has_client_cert = has_client_cert,
            "Forwarding request to local endpoint"
        );

        let method: reqwest::Method = request.method.parse().context("Invalid HTTP method")?;

        let mut req_builder = self.client.request(method, &url);

        // Add headers (filter out some hop-by-hop headers)
        let skip_headers = ["host", "connection", "transfer-encoding", "keep-alive"];
        for (name, value) in &request.headers {
            if !skip_headers.contains(&name.to_lowercase().as_str()) {
                req_builder = req_builder.header(name, value);
            }
        }

        // Add client certificate headers if present
        if let Some(cert) = &request.client_certificate {
            // Base64 encode the DER certificate for safe header transmission
            if !cert.certificate_der.is_empty() {
                let cert_b64 = BASE64_STANDARD.encode(&cert.certificate_der);
                req_builder = req_builder.header(X_CLIENT_CERT, cert_b64);
            }
            if !cert.subject.is_empty() {
                req_builder = req_builder.header(X_CLIENT_CERT_SUBJECT, &cert.subject);
            }
            if !cert.issuer.is_empty() {
                req_builder = req_builder.header(X_CLIENT_CERT_ISSUER, &cert.issuer);
            }
            if !cert.serial_number.is_empty() {
                req_builder = req_builder.header(X_CLIENT_CERT_SERIAL, &cert.serial_number);
            }
        }

        // Add body - clone it since we might need to retry
        if !request.body.is_empty() {
            req_builder = req_builder.body(request.body.clone());
        }

        let response = req_builder
            .send()
            .await
            .context("Failed to forward request to local endpoint")?;

        let status_code = response.status().as_u16() as u32;

        // Collect response headers
        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.to_string(), value_str.to_string());
            }
        }

        let body = response
            .bytes()
            .await
            .context("Failed to read response body")?
            .to_vec();

        tracing::debug!(
            request_id = %request.request_id,
            status_code = status_code,
            "Received response from local endpoint"
        );

        Ok(HttpResponse {
            request_id: request.request_id.clone(),
            status_code,
            headers,
            body,
        })
    }
}
