// src/bin/bleep_state.rs

use bleep_state::state_manager::StateManager;
use log::{error, info};
use std::error::Error;

fn main() {
    env_logger::init();
    info!("📦 BLEEP State Engine Initializing...");

    if let Err(e) = run_state_engine() {
        error!("❌ State engine failed: {}", e);
        std::process::exit(1);
    }
}

fn run_state_engine() -> Result<(), Box<dyn Error>> {
    let mut state = StateManager::new();
    info!("🔄 Opened state manager.");

    state.create_snapshot()?;
    info!("💾 State snapshot saved.");

    Ok(())
}
