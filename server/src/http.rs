use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use api::{ClientCertificate, HttpRequest};
use axum::{
    Extension, Router,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Method, StatusCode, header::HeaderName},
    response::IntoResponse,
    routing::{any, get},
};

use crate::grpc::{ClientConnections, send_request_to_client};

// Standard X-Forwarded headers
const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_FORWARDED_HOST: &str = "x-forwarded-host";
const X_FORWARDED_PROTO: &str = "x-forwarded-proto";

/// Client certificate extracted from TLS connection (if mTLS is enabled)
#[derive(Clone, Default)]
pub struct TlsClientCert(pub Option<Vec<u8>>);

#[derive(Clone)]
pub struct HttpState {
    pub connections: ClientConnections,
    pub webhook_timeout: Duration,
}

pub fn create_router(state: HttpState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/{route}", any(handle_webhook))
        .route("/{route}/{*path}", any(handle_webhook))
        .with_state(state)
}

async fn health_check() -> StatusCode {
    StatusCode::OK
}

async fn handle_webhook(
    State(state): State<HttpState>,
    Path(params): Path<WebhookPath>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    client_cert: Option<Extension<TlsClientCert>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let route = &params.route;
    let path = params.path.as_deref().unwrap_or("");

    // Validate route format (64 hex chars - full SHA256 hash)
    if route.len() != 64 || !route.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new());
    }

    let client = match state.connections.read().await.get(route).cloned() {
        Some(client) => client,
        None => {
            tracing::debug!(route = %route, "No client found for route");
            return (StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new());
        }
    };

    let request_id = uuid::Uuid::new_v4().to_string();

    // Build headers map with X-Forwarded headers
    let mut header_map = HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            header_map.insert(name.to_string(), value_str.to_string());
        }
    }

    // Handle X-Forwarded-For: append client IP or set if not present
    let client_ip = addr.ip().to_string();
    let forwarded_for = match header_map.get(X_FORWARDED_FOR) {
        Some(existing) => format!("{}, {}", existing, client_ip),
        None => client_ip,
    };
    header_map.insert(X_FORWARDED_FOR.to_string(), forwarded_for);

    // Handle X-Forwarded-Host: preserve existing or set from Host header
    if !header_map.contains_key(X_FORWARDED_HOST)
        && let Some(host) = header_map.get("host")
    {
        header_map.insert(X_FORWARDED_HOST.to_string(), host.clone());
    }

    // Handle X-Forwarded-Proto: preserve existing or default to http
    // In production behind TLS termination, this would typically be set by the load balancer
    if !header_map.contains_key(X_FORWARDED_PROTO) {
        header_map.insert(X_FORWARDED_PROTO.to_string(), "http".to_string());
    }

    // Extract query string from request URI
    let query = String::new(); // Query params would need to be extracted differently

    // Extract and parse client certificate if present
    let client_certificate = client_cert
        .and_then(|Extension(cert)| cert.0)
        .map(|der| parse_client_certificate(der));

    let http_request = HttpRequest {
        request_id: request_id.clone(),
        method: method.to_string(),
        path: format!("/{}", path),
        headers: header_map,
        body: body.to_vec(),
        query,
        client_certificate,
    };

    tracing::debug!(
        request_id = %request_id,
        method = %method,
        path = %path,
        route = %route,
        has_client_cert = http_request.client_certificate.is_some(),
        "Forwarding webhook to client"
    );

    match send_request_to_client(&client, http_request, state.webhook_timeout).await {
        Ok(response) => {
            let status = StatusCode::from_u16(response.status_code as u16)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            let mut response_headers = HeaderMap::new();
            for (name, value) in response.headers {
                if let (Ok(header_name), Ok(header_value)) = (
                    name.parse::<HeaderName>(),
                    value.parse(),
                ) {
                    response_headers.insert(header_name, header_value);
                }
            }

            (status, response_headers, Bytes::from(response.body))
        }
        Err(status) => {
            tracing::error!(
                request_id = %request_id,
                error = %status,
                "Failed to forward webhook"
            );

            let http_status = match status.code() {
                tonic::Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
                tonic::Code::Unavailable => StatusCode::BAD_GATEWAY,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (http_status, HeaderMap::new(), Bytes::new())
        }
    }
}

#[derive(serde::Deserialize)]
struct WebhookPath {
    route: String,
    path: Option<String>,
}

/// Parse a DER-encoded X.509 certificate and extract relevant fields
fn parse_client_certificate(der: Vec<u8>) -> ClientCertificate {
    use x509_parser::prelude::*;

    let (subject, issuer, serial_number) = match X509Certificate::from_der(&der) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let serial = cert
                .serial
                .to_bytes_be()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");
            (subject, issuer, serial)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse client certificate");
            (String::new(), String::new(), String::new())
        }
    };

    ClientCertificate {
        certificate_der: der,
        subject,
        issuer,
        serial_number,
    }
}
