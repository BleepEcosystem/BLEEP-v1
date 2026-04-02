// src/bin/bleep_block.rs

use bleep_core::block::Transaction;
use bleep_core::transaction::ZKTransaction;
use bleep_core::{Block, Blockchain, Mempool, TransactionPool};
use bleep_crypto::quantum_secure::QuantumSecure;
use bleep_crypto::tx_signer::generate_tx_keypair;

use log::{error, info, warn};
use std::error::Error;

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("🔷 BLEEP Block Module Starting...");

    if let Err(e) = run_block_module().await {
        error!("❌ Block module failed: {}", e);
        std::process::exit(1);
    }
}

async fn run_block_module() -> Result<(), Box<dyn Error>> {
    let genesis_block = Block::new(0, vec![], "0".repeat(64));
    let tx_pool = TransactionPool::new(10000);
    let mut blockchain = Blockchain::new(genesis_block, Default::default(), tx_pool.clone());
    info!(
        "✅ Blockchain initialized with {} blocks",
        blockchain.chain.len()
    );

    let quantum_secure = QuantumSecure::keygen();
    let pending_tx = ZKTransaction::new("alice", "bob", 42, &quantum_secure);

    let mempool = Mempool::new();
    if !mempool.add_transaction(pending_tx.clone()).await {
        warn!("Transaction already existed in mempool");
    }

    let zk_txs = mempool.get_pending_transactions().await;
    let mut pending_txs: Vec<Transaction> = Vec::with_capacity(zk_txs.len());
    for tx in zk_txs {
        if !tx.verify() {
            warn!(
                "Skipping invalid transaction from {} to {}",
                tx.sender, tx.receiver
            );
            continue;
        }
        pending_txs.push(Transaction {
            sender: tx.sender,
            receiver: tx.receiver,
            amount: tx.amount,
            timestamp: tx.timestamp,
            signature: tx.signature,
        });
    }

    info!(
        "📦 {} transactions collected from mempool",
        pending_txs.len()
    );

    let last_block = match blockchain.chain.back() {
        Some(block) => block,
        None => {
            error!("Blockchain is empty. Cannot create a new block.");
            return Err("Blockchain is empty".into());
        }
    };
    let last_hash = last_block.compute_hash();
    let mut new_block = Block::new(last_block.index + 1, pending_txs, last_hash);

    let (_sphincs_pk, sphincs_sk) = generate_tx_keypair();
    new_block.sign_block(&sphincs_sk)?;
    info!(
        "📄 New block created with hash: {}",
        new_block.compute_hash()
    );

    if !blockchain.add_block(new_block, &[]) {
        return Err("Failed to append new block".into());
    }
    info!("✅ New block added.");

    Ok(())
}
