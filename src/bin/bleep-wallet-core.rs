// src/bin/bleep-wallet_core.rs

use bleep_crypto::quantum_resistance::{generate_falcon_keypair, generate_kyber_keypair};
use bleep_wallet_core::wallet::{EncryptedWallet, WalletManager};

use log::{error, info};
use std::error::Error;

fn main() {
    env_logger::init();
    info!("💼 BLEEP Wallet Core Engine Initializing...");

    if let Err(e) = run_wallet_engine() {
        error!("❌ Wallet engine failed: {}", e);
        std::process::exit(1);
    }
}

fn run_wallet_engine() -> Result<(), Box<dyn Error>> {
    // Step 1: Generate new post-quantum keypairs for a wallet
    let (falcon_pk, _falcon_sk) = generate_falcon_keypair()?;
    let (kyber_pk, _kyber_sk) = generate_kyber_keypair()?;
    info!("🔐 Falcon and Kyber keypairs generated.");

    // Step 2: Initialize a new encrypted wallet
    let wallet = EncryptedWallet::new(falcon_pk, kyber_pk);
    info!("✅ Encrypted wallet instance created.");

    // Step 3: Use WalletManager to save and manage the wallet
    let mut manager = WalletManager::load_or_create()?;
    manager.save_wallet(wallet)?;
    info!("💾 Wallet saved to secure store.");

    // Step 4: Display basic wallet summary
    manager.list_wallets();

    info!("💼 BLEEP Wallet Core Engine completed successfully.");
    Ok(())
}
