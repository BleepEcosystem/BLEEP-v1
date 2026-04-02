// src/bin/transaction.rs

use bleep_core::transaction::ZKTransaction;
use bleep_crypto::quantum_secure::QuantumSecure;

use log::{error, info};
use std::env;
use std::error::Error;

fn main() {
    env_logger::init();
    info!("🔁 BLEEP Transaction Engine Starting...");

    if let Err(e) = submit_transaction() {
        error!("❌ Transaction submission failed: {}", e);
        std::process::exit(1);
    }
}

fn submit_transaction() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: transaction <recipient> <amount>");
        return Ok(());
    }
    let recipient = &args[1];
    let amount: u64 = args[2].parse()?;

    let quantum_secure = QuantumSecure::keygen();
    let tx = ZKTransaction::new("bleep:sender", recipient, amount, &quantum_secure);

    if !tx.verify() {
        error!("❌ Transaction signature verification failed.");
        return Err("Transaction signature invalid".into());
    }

    info!(
        "📝 Transaction signed and verified: {} -> {} for {}",
        "bleep:sender", recipient, amount
    );
    println!("📤 Transaction ready: {:?}", tx);
    Ok(())
}
