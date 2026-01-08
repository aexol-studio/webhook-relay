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
    /// OAuth scopes to request. If empty, defaults to `openid` and `offline_access`.
    /// If provided, these scopes are used instead (all-or-nothing override).
    /// For Azure AD, typically include `openid`, `offline_access`, and
    /// `{client_id}/.default` to get an access token for your API.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
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

/// Get the sessions directory path (~/.config/webhook-relay/sessions/)
pub fn sessions_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("sessions"))
}

/// Get a session-specific config file path (~/.config/webhook-relay/sessions/<session_id>.toml)
pub fn session_config_path(session_id: &str) -> Result<PathBuf> {
    Ok(sessions_dir()?.join(format!("{}.toml", session_id)))
}

/// Ensure the sessions directory exists
pub fn ensure_sessions_dir() -> Result<PathBuf> {
    let sessions_dir = sessions_dir()?;
    std::fs::create_dir_all(&sessions_dir).context("Failed to create sessions directory")?;
    Ok(sessions_dir)
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
