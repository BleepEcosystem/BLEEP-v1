//! # bleep-pat binary
//!
//! Standalone PAT engine entry point.  Rewired to use the v2
//! intent-driven PATRegistry — no more AssetTokenEngine stubs.

use bleep_pat::{PATIntent, PATRegistry};
use log::{error, info};
use std::error::Error;

fn main() {
    env_logger::init();
    info!("🪙 BLEEP PAT Engine v2 — intent-driven, BLEEP-native");

    if let Err(e) = run() {
        error!("❌ PAT engine failed: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut registry = PATRegistry::new();

    // Genesis demonstration token — proves engine is live.
    // In production this is driven by RPC / governance intents.
    let owner = [0x01u8; 32];
    let genesis = [0x00u8; 32];

    registry.execute(&PATIntent::create_token(
        owner,
        "BLP",
        "BLEEP Native Token",
        8,
        200_000_000 * 100_000_000u128, // 200M cap, 8 decimals
        0,                             // no burn on transfers
        false,                         // not freezable
    ))?;

    registry.execute(&PATIntent::mint(
        owner,
        "BLP",
        genesis,
        25_000_000 * 100_000_000u128, // 25M initial circulating
    ))?;

    info!(
        "✅ PAT Registry online — {} token(s) registered",
        registry.token_count()
    );
    info!(
        "   BLP supply: {}  burned: {}",
        registry
            .get_token("BLP")
            .map(|t| t.current_supply)
            .unwrap_or(0),
        registry
            .get_token("BLP")
            .map(|t| t.total_burned)
            .unwrap_or(0),
    );

    Ok(())
}
