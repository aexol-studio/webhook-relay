//! Client-specific configuration

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// Re-export shared types from common
pub use common::config::{
    OAuthConfig, config_dir, config_path, discover_oauth_endpoints, session_config_path,
};

/// Session-specific configuration overrides
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SessionConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    server_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth: Option<SessionOAuthConfig>,
}

/// Session-specific OAuth configuration overrides
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SessionOAuthConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    callback_port: Option<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
}

impl SessionConfig {
    fn apply_to(&self, config: &mut Config) {
        if let Some(ref server_address) = self.server_address {
            config.server_address = server_address.clone();
        }
        if let Some(ref local_endpoint) = self.local_endpoint {
            config.local_endpoint = local_endpoint.clone();
        }
        if let Some(ref oauth) = self.oauth {
            oauth.apply_to(&mut config.oauth);
        }
    }
}

impl SessionOAuthConfig {
    fn apply_to(&self, oauth: &mut OAuthConfig) {
        if let Some(ref client_id) = self.client_id {
            oauth.client_id = client_id.clone();
        }
        if let Some(ref issuer) = self.issuer {
            oauth.issuer = issuer.clone();
        }
        if let Some(ref auth_url) = self.auth_url {
            oauth.auth_url = Some(auth_url.clone());
        }
        if let Some(ref token_url) = self.token_url {
            oauth.token_url = Some(token_url.clone());
        }
        if let Some(callback_port) = self.callback_port {
            oauth.callback_port = Some(callback_port);
        }
        if !self.scopes.is_empty() {
            oauth.scopes = self.scopes.clone();
        }
    }
}

/// Full client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_address: String,
    pub local_endpoint: String,

    /// Optional session ID to reuse across client runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    #[serde(default)]
    pub oauth: OAuthConfig,
}

impl Config {
    /// Get config directory (wrapper for common::config::config_dir)
    pub fn config_dir() -> Result<PathBuf> {
        config_dir()
    }

    /// Get config path (wrapper for common::config::config_path)
    pub fn config_path() -> Result<PathBuf> {
        config_path()
    }

    /// Load configuration from the default path
    pub fn load() -> Result<Self> {
        Self::load_from(Self::config_path()?)
    }

    /// Load configuration from a specific path
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            bail!(
                "Config file not found at {}. Run with --init to create a default config.",
                path.display()
            );
        }

        let contents = std::fs::read_to_string(path).context("Failed to read config file")?;

        let mut config: Self = toml::from_str(&contents).context("Failed to parse config file")?;

        if let Some(session_id) = config.session_id.clone() {
            config.load_session_overrides(&session_id)?;
        }

        Ok(config)
    }

    /// Load session-specific config overrides for a given session ID
    pub fn load_session_overrides(&mut self, session_id: &str) -> Result<()> {
        let session_path = session_config_path(session_id)?;

        if !session_path.exists() {
            return Ok(());
        }

        tracing::info!(path = %session_path.display(), "Loading session config overrides");

        let contents =
            std::fs::read_to_string(&session_path).context("Failed to read session config file")?;

        let session_config: SessionConfig =
            toml::from_str(&contents).context("Failed to parse session config file")?;

        session_config.apply_to(self);

        Ok(())
    }

    /// Create default configuration file
    pub fn create_default() -> Result<Self> {
        let config_dir = Self::config_dir()?;
        std::fs::create_dir_all(&config_dir).context("Failed to create config directory")?;

        let config = Config {
            server_address: "http://localhost:50051".to_string(),
            local_endpoint: "http://localhost:3000".to_string(),
            session_id: None,
            oauth: OAuthConfig {
                client_id: "webhook-relay-cli".to_string(),
                issuer: "http://localhost:8180/realms/relay".to_string(),
                auth_url: None,
                token_url: None,
                callback_port: None,
                scopes: vec![],
            },
        };

        let path = Self::config_path()?;
        let contents = toml::to_string_pretty(&config).context("Failed to serialize config")?;

        std::fs::write(&path, contents).context("Failed to write config file")?;

        tracing::info!(path = %path.display(), "Created default config file");

        Ok(config)
    }

    /// Discover OAuth endpoints from OIDC well-known configuration
    pub async fn discover_oauth_endpoints(&mut self) -> Result<()> {
        discover_oauth_endpoints(&mut self.oauth).await
    }
}
