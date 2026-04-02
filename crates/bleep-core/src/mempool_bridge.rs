//! # MempoolBridge — Sprint 3
//!
//! Background task that drains `Mempool` (P2P-facing) into `TransactionPool`
//! (execution-facing), connecting the networking layer to the block producer.
//!
//! ## Why two pools?
//!
//! | Pool              | Role                                   | API           |
//! |-------------------|----------------------------------------|---------------|
//! | `Mempool`         | Receives transactions from P2P gossip  | keyed HashMap |
//! | `TransactionPool` | Feeds `BlockProducer::peek_for_block`  | FIFO VecDeque |
//!
//! The bridge periodically drains the Mempool (clearing seen tx_ids) and
//! pushes new transactions into the pool, deduplicating by tx_id.
//!
//! ## Deduplication
//! Uses a `HashSet<String>` of `tx_id = sender:receiver:amount:timestamp`.
//! The set is bounded to `MAX_SEEN` entries and rotates on overflow.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::mempool::Mempool;
use crate::transaction_pool::TransactionPool;

use tracing::{debug, info, warn};

/// Maximum entries in the seen-tx deduplication set before it is pruned.
const MAX_SEEN: usize = 100_000;

/// How often to drain the Mempool into the TransactionPool.
const BRIDGE_INTERVAL_MS: u64 = 500; // 2× per second

/// Run the Mempool → TransactionPool bridge forever.
///
/// Call this inside `tokio::spawn`. It runs until the process exits.
pub async fn run_mempool_bridge(mempool: Arc<Mempool>, tx_pool: Arc<TransactionPool>) {
    let mut seen: HashSet<String> = HashSet::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(BRIDGE_INTERVAL_MS));

    info!(
        "[MempoolBridge] Started — draining every {}ms",
        BRIDGE_INTERVAL_MS
    );

    loop {
        ticker.tick().await;

        // Drain pending transactions from the Mempool
        let pending = mempool.get_pending_transactions().await;
        if pending.is_empty() {
            continue;
        }

        let mut forwarded = 0usize;

        for tx in pending {
            let tx_id = format!(
                "{}:{}:{}:{}",
                tx.sender, tx.receiver, tx.amount, tx.timestamp
            );

            // Deduplication: skip if already seen
            if seen.contains(&tx_id) {
                continue;
            }

            // Forward into TransactionPool
            if tx_pool.add_transaction(tx.clone()).await {
                seen.insert(tx_id.clone());
                forwarded += 1;
            } else {
                debug!("[MempoolBridge] tx_pool rejected {}", tx_id);
            }

            // Remove from Mempool after forwarding
            mempool.remove_transaction(&tx_id).await;
        }

        if forwarded > 0 {
            debug!(
                "[MempoolBridge] Forwarded {} txs to TransactionPool",
                forwarded
            );
        }

        // Prune seen set on overflow to prevent unbounded growth
        if seen.len() > MAX_SEEN {
            let keep: HashSet<String> = seen.iter().cloned().take(MAX_SEEN / 2).collect();
            let pruned = seen.len() - keep.len();
            seen = keep;
            warn!("[MempoolBridge] Pruned {} entries from seen-set", pruned);
        }
    }
}
