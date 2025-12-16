mod auth;
mod config;
mod grpc;
mod proxy;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use auth::AuthManager;
use config::Config;
use grpc::GrpcClient;
use proxy::Proxy;

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
    let args: Vec<String> = std::env::args().collect();
    
    if args.iter().any(|a| a == "--init") {
        Config::create_default()?;
        println!("Created default config at {}", Config::config_path()?.display());
        println!("Please edit the config file and run again.");
        return Ok(());
    }
    
    // Load configuration
    let mut config = Config::load()?;
    
    tracing::info!(
        server_address = %config.server_address,
        local_endpoint = %config.local_endpoint,
        "Configuration loaded"
    );
    
    // Discover OAuth endpoints
    config.discover_oauth_endpoints().await?;
    
    // Authenticate
    let auth_manager = AuthManager::new(&config.oauth)?;
    let access_token = auth_manager.get_access_token().await?;
    
    // Connect to server
    tracing::info!("Connecting to server at {}", config.server_address);
    let grpc_client = GrpcClient::connect(&config.server_address, access_token).await?;
    
    // Get config (which registers us and returns our endpoint)
    let client_config = grpc_client.get_config().await?;
    
    println!("Connected to server.");
    println!("Your webhook endpoint: {}", client_config.endpoint);
    println!();
    println!("Listening for webhooks... (Ctrl+C to exit)");
    
    // Create proxy
    let proxy = Proxy::new(config.local_endpoint);
    
    // Run webhook stream
    grpc_client.run_webhook_stream(proxy).await?;
    
    Ok(())
}
