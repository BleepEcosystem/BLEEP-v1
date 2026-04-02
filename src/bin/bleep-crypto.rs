// src/bin/bleep_crypto.rs

use bleep_crypto::quantum_resistance::{init_falcon, init_kyber, run_keygen_tests};
use bleep_crypto::zkp_verification::{init_zkp_systems, test_zkp_proofs};

use log::{error, info};
use std::error::Error;

fn main() {
    env_logger::init();
    info!("🔐 BLEEP Crypto Engine Initializing...");

    if let Err(e) = run_crypto_engine() {
        error!("❌ Crypto engine failed: {}", e);
        std::process::exit(1);
    }
}

fn run_crypto_engine() -> Result<(), Box<dyn Error>> {
    // Step 1: Initialize Falcon and Kyber post-quantum cryptosystems
    init_falcon()?;
    init_kyber()?;
    info!("✅ Falcon and Kyber initialized.");

    // Step 2: Initialize zero-knowledge proof system (Groth16, etc.)
    init_zkp_systems()?;
    info!("✅ zk-SNARK engine initialized.");

    // Step 3: Run internal cryptographic self-tests
    run_keygen_tests()?;
    test_zkp_proofs()?;
    info!("✅ All cryptographic self-tests passed.");

    info!("🔒 BLEEP Crypto Engine ready.");
    Ok(())
}
