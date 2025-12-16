//! MCP client binary for webhook-relay

use anyhow::Result;
use mcp_client::{new_shared_state, run_mcp_server};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing to stderr (stdout is for MCP protocol)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let state = new_shared_state();

    // Run the MCP server on stdio
    run_mcp_server(state).await
}
