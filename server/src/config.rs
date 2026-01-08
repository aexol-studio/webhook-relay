use std::env;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Config {
    pub external_url: String,
    pub http_port: u16,
    pub grpc_port: u16,
    pub jwks_url: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwks_refresh_secs: u64,
    pub webhook_timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    jwks_uri: String,
    issuer: String,
}

async fn discover_oidc(issuer: &str) -> Result<OidcDiscoveryDocument> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&discovery_url)
        .send()
        .await
        .context("Failed to fetch OIDC discovery document")?;

    if !response.status().is_success() {
        bail!("OIDC discovery failed with status: {}", response.status());
    }

    response
        .json::<OidcDiscoveryDocument>()
        .await
        .context("Failed to parse OIDC discovery document")
}

impl Config {
    pub async fn from_env() -> Result<Self> {
        let external_url =
            env::var("EXTERNAL_URL").context("EXTERNAL_URL environment variable is required")?;

        let http_port = env::var("HTTP_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .context("HTTP_PORT must be a valid port number")?;

        let grpc_port = env::var("GRPC_PORT")
            .unwrap_or_else(|_| "50051".to_string())
            .parse()
            .context("GRPC_PORT must be a valid port number")?;

        let jwt_audience =
            env::var("JWT_AUDIENCE").context("JWT_AUDIENCE environment variable is required")?;

        let jwks_refresh_secs = env::var("JWKS_REFRESH_SECS")
            .unwrap_or_else(|_| "300".to_string())
            .parse()
            .context("JWKS_REFRESH_SECS must be a valid number")?;

        let webhook_timeout_secs = env::var("WEBHOOK_TIMEOUT_SECS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .context("WEBHOOK_TIMEOUT_SECS must be a valid number")?;

        // OIDC Discovery or manual configuration
        let (jwks_url, jwt_issuer) = if let Ok(oidc_issuer) = env::var("OIDC_ISSUER") {
            tracing::info!("Performing OIDC discovery from {}", oidc_issuer);
            let discovery = discover_oidc(&oidc_issuer).await?;
            (discovery.jwks_uri, discovery.issuer)
        } else {
            let jwks_url =
                env::var("JWKS_URL").context("Either OIDC_ISSUER or JWKS_URL must be set")?;
            let jwt_issuer = env::var("JWT_ISSUER")
                .context("JWT_ISSUER is required when OIDC_ISSUER is not set")?;
            (jwks_url, jwt_issuer)
        };

        Ok(Config {
            external_url,
            http_port,
            grpc_port,
            jwks_url,
            jwt_issuer,
            jwt_audience,
            jwks_refresh_secs,
            webhook_timeout_secs,
        })
    }
}
