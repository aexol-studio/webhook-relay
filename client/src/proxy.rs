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
}

impl Proxy {
    pub fn new(local_endpoint: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            local_endpoint: local_endpoint.trim_end_matches('/').to_string(),
        }
    }

    pub async fn forward(&self, request: HttpRequest) -> Result<HttpResponse> {
        let url = if request.query.is_empty() {
            format!("{}{}", self.local_endpoint, request.path)
        } else {
            format!("{}{}?{}", self.local_endpoint, request.path, request.query)
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

        // Add body
        if !request.body.is_empty() {
            req_builder = req_builder.body(request.body);
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
            request_id: request.request_id,
            status_code,
            headers,
            body,
        })
    }
}
