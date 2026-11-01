// src/bin/bleep-wallet_core.rs

use bleep_crypto::quantum_resistance::{generate_mlkem_keypair, generate_sphincs_keypair};
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
    let (sphincs_pk, _sphincs_sk) = generate_sphincs_keypair()?;
    let (mlkem_pk, _mlkem_sk) = generate_mlkem_keypair()?;
    info!("🔐 SPHINCS+ and ML-KEM keypairs generated.");

    // Step 2: Initialize a new encrypted wallet
    let wallet = EncryptedWallet::new(sphincs_pk, mlkem_pk);
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
