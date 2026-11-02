// src/bin/bleep_block.rs

use bleep_core::block::Transaction;
use bleep_core::transaction::ZKTransaction;
use bleep_core::{Block, Blockchain, Mempool, TransactionPool};
use bleep_crypto::tx_signer::{
    derive_account_address, generate_tx_keypair, sign_tx_payload, tx_payload, DEFAULT_CHAIN_ID,
};

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

    let (public_key, secret_key) = generate_tx_keypair();
    let sender = derive_account_address(&public_key);
    let timestamp = chrono::Utc::now().timestamp().max(0) as u64;
    let payload = tx_payload(DEFAULT_CHAIN_ID, &sender, "bob", 42, timestamp, 0);
    let signature = sign_tx_payload(&payload, &secret_key)?;
    let mut signed_bytes = public_key;
    signed_bytes.extend_from_slice(&signature);
    let pending_tx = ZKTransaction {
        chain_id: DEFAULT_CHAIN_ID.to_string(),
        sender,
        receiver: "bob".to_string(),
        amount: 42,
        timestamp,
        nonce: 0,
        signature: signed_bytes,
    };

    let mempool = Mempool::new(DEFAULT_CHAIN_ID, Mempool::embedded_sender_public_key);
    if !mempool.add_transaction(pending_tx.clone()).await {
        warn!("Transaction already existed in mempool");
    }

    let zk_txs = mempool.get_pending_transactions().await;
    let mut pending_txs: Vec<Transaction> = Vec::with_capacity(zk_txs.len());
    for tx in zk_txs {
        if !tx.verify_account_authorization() {
            warn!(
                "Skipping invalid transaction from {} to {}",
                tx.sender, tx.receiver
            );
            continue;
        }
        pending_txs.push(Transaction {
            chain_id: tx.chain_id,
            sender: tx.sender,
            receiver: tx.receiver,
            amount: tx.amount,
            timestamp: tx.timestamp,
            nonce: tx.nonce,
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

    let (sphincs_pk, sphincs_sk) = generate_tx_keypair();
    new_block.sign_block_with_pk(&sphincs_sk, &sphincs_pk)?;
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
