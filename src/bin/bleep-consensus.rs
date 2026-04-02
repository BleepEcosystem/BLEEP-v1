// src/bin/bleep_consensus.rs

use log::{error, info};

fn main() {
    env_logger::init();
    info!("🔷 BLEEP Consensus Engine Starting...");

    if let Err(e) = bleep_consensus::run_consensus_engine() {
        error!("❌ Consensus engine failed: {}", e);
        std::process::exit(1);
    }
}
