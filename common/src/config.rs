//! Shared configuration for webhook-relay clients

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// OAuth configuration for authentication
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    /// Port for OAuth callback server. Defaults to 19284.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
}

/// Get the config directory for webhook-relay (~/.config/webhook-relay/)
pub fn config_dir() -> Result<PathBuf> {
    let config_dir = dirs::config_dir()
        .context("Could not determine config directory")?
        .join("webhook-relay");
    
    Ok(config_dir)
}

/// Get the config file path (~/.config/webhook-relay/config.toml)
pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// Discover OAuth endpoints from OIDC well-known configuration
pub async fn discover_oauth_endpoints(oauth: &mut OAuthConfig) -> Result<()> {
    if oauth.auth_url.is_some() && oauth.token_url.is_some() {
        return Ok(());
    }
    
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        oauth.issuer.trim_end_matches('/')
    );
    
    tracing::info!("Discovering OAuth endpoints from {}", discovery_url);
    
    let client = reqwest::Client::new();
    let response = client
        .get(&discovery_url)
        .send()
        .await
        .context("Failed to fetch OIDC discovery document")?;
    
    if !response.status().is_success() {
        bail!("OIDC discovery failed with status: {}", response.status());
    }
    
    let discovery: OidcDiscoveryDocument = response
        .json()
        .await
        .context("Failed to parse OIDC discovery document")?;
    
    if oauth.auth_url.is_none() {
        oauth.auth_url = Some(discovery.authorization_endpoint);
    }
    
    if oauth.token_url.is_none() {
        oauth.token_url = Some(discovery.token_endpoint);
    }
    
    Ok(())
}
