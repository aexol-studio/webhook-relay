//! Common functionality shared between client and mcp-client

pub mod auth;
pub mod config;
pub mod relay_client;

pub use auth::AuthProvider;
pub use relay_client::RelayClient;
