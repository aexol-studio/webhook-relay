//! Client-specific configuration

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// Re-export shared types from common
pub use common::config::{OAuthConfig, config_dir, config_path, discover_oauth_endpoints};

/// Full client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_address: String,
    pub local_endpoint: String,
    
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
        
        let contents = std::fs::read_to_string(path)
            .context("Failed to read config file")?;
        
        toml::from_str(&contents)
            .context("Failed to parse config file")
    }
    
    /// Create default configuration file
    pub fn create_default() -> Result<Self> {
        let config_dir = Self::config_dir()?;
        std::fs::create_dir_all(&config_dir)
            .context("Failed to create config directory")?;
        
        let config = Config {
            server_address: "http://localhost:50051".to_string(),
            local_endpoint: "http://localhost:3000".to_string(),
            oauth: OAuthConfig {
                client_id: "webhook-relay-cli".to_string(),
                issuer: "http://localhost:8180/realms/relay".to_string(),
                auth_url: None,
                token_url: None,
                callback_port: None,
            },
        };
        
        let path = Self::config_path()?;
        let contents = toml::to_string_pretty(&config)
            .context("Failed to serialize config")?;
        
        std::fs::write(&path, contents)
            .context("Failed to write config file")?;
        
        tracing::info!(path = %path.display(), "Created default config file");
        
        Ok(config)
    }
    
    /// Discover OAuth endpoints from OIDC well-known configuration
    pub async fn discover_oauth_endpoints(&mut self) -> Result<()> {
        discover_oauth_endpoints(&mut self.oauth).await
    }
}
