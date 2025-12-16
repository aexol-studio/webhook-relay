use anyhow::Result;
#[cfg(target_env = "musl")]
use mimalloc::MiMalloc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use server::{config::Config, run_server};

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    tracing::info!("Starting webhook-relay server");
    
    // Load configuration
    let config = Config::from_env().await?;
    
    let (_handle, _addresses) = run_server(config).await?;
    
    // Keep running until interrupted
    tokio::signal::ctrl_c().await?;
    
    Ok(())
}
