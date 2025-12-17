mod auth;
mod config;

use std::path::PathBuf;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use auth::AuthManager;
use config::Config;

fn print_usage() {
    eprintln!("Usage: client [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --init                 Create default config file");
    eprintln!("  --config <PATH>        Path to config file (default: ~/.config/webhook-relay/config.toml)");
    eprintln!("  --session-id <ID>      Override session_id (also supports config)");
    eprintln!("  --help                 Show this help message");
}

fn parse_args() -> Result<(Option<PathBuf>, Option<String>)> {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path: Option<PathBuf> = None;
    let mut session_id: Option<String> = None;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--init" => {
                Config::create_default()?;
                println!("Created default config at {}", Config::config_path()?.display());
                println!("Please edit the config file and run again.");
                std::process::exit(0);
            }
            "--config" | "-c" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--config requires a path argument");
                }
                config_path = Some(PathBuf::from(&args[i]));
            }
            "--session-id" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--session-id requires a value");
                }
                session_id = Some(args[i].clone());
            }
            arg if arg.starts_with('-') => {
                anyhow::bail!("Unknown option: {}", arg);
            }
            _ => {
                anyhow::bail!("Unexpected argument: {}", args[i]);
            }
        }
        i += 1;
    }

    Ok((config_path, session_id))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    // Parse arguments
    let (config_path, session_id_override) = parse_args()?;

    // Load configuration
    let mut config = match config_path {
        Some(path) => {
            tracing::info!(path = %path.display(), "Loading config from custom path");
            Config::load_from(&path)?
        }
        None => Config::load()?,
    };

    if session_id_override.is_some() {
        config.session_id = session_id_override;
    }
    
    tracing::info!(
        server_address = %config.server_address,
        local_endpoint = %config.local_endpoint,
        "Configuration loaded"
    );
    
    // Discover OAuth endpoints
    config.discover_oauth_endpoints().await?;
    
    // Create auth manager
    let auth_manager = AuthManager::new(&config.oauth)?;
    
    // Run client with auth provider
    let client_handle = client::run_client(client::ClientConfig {
        server_address: config.server_address,
        auth_provider: auth_manager,
        local_endpoint: config.local_endpoint,
        session_id: config.session_id,
    })
    .await?;
    
    println!("Connected to server.");
    println!("Your webhook endpoint: {}", client_handle.endpoint);
    println!();
    println!("Listening for webhooks... (Ctrl+C to exit)");
    
    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    
    client_handle.stop();
    
    Ok(())
}
