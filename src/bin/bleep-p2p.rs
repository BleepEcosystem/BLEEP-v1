// src/bin/bleep_p2p.rs

use bleep_p2p::{P2PNode, P2PNodeConfig};
use log::{error, info};
use std::error::Error;

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("🌐 BLEEP P2P Engine Booting...");

    if let Err(e) = run_p2p_node().await {
        error!("❌ P2P engine failed: {}", e);
        std::process::exit(1);
    }
}

async fn run_p2p_node() -> Result<(), Box<dyn Error>> {
    let config = P2PNodeConfig::default();
    let (_node, _handle) = P2PNode::start(config).await?;
    info!("🔗 P2P Node initialized.");
    Ok(())
}
