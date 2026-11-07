//! # TransactionPool
//!
use crate::transaction::{
    compare_fee_priority, pending_admission_allowed, transaction_size, ZKTransaction,
    MAX_POOL_BYTES, MIN_TRANSACTION_FEE,
};
use bleep_state::state_manager::StateManager;
use hex;
use parking_lot::Mutex as StateMutex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Expected SPHINCS+ public key length for sphincsshake256fsimple: 64 bytes
const SPHINCS_PK_LEN: usize = 64;
const SPHINCS_SIG_LEN: usize = 49_856;
const DURABLE_MEMPOOL_PREFIX: &str = "mempool/pending/";

// ── TransactionPool ───────────────────────────────────────────────────────────

/// Fee-prioritized transaction pool with SPHINCS+ verification on admission.
pub struct TransactionPool {
    /// Ordered queue of validated, pending transactions.
    pool: Mutex<Vec<ZKTransaction>>,
    /// SHA-256 hashes of pending payloads (committed nonces prevent replay).
    seen_hashes: Mutex<HashSet<[u8; 32]>>,
    /// Chain ID this pool admits transactions for.
    chain_id: String,
    /// Maximum number of pending transactions.
    max_size: usize,
    state: Option<Arc<StateMutex<StateManager>>>,
    pool_bytes: AtomicUsize,
}

fn pool_size_bytes(transactions: &[ZKTransaction]) -> usize {
    transactions.iter().fold(0usize, |total, tx| {
        total.saturating_add(transaction_size(tx))
    })
}

fn transaction_payload_hash(transaction: &ZKTransaction) -> [u8; 32] {
    let payload = bleep_crypto::tx_signer::tx_payload_v2(
        &transaction.chain_id,
        &transaction.sender,
        &transaction.receiver,
        transaction.amount,
        transaction.fee,
        transaction.timestamp,
        transaction.nonce,
    );
    Sha256::digest(payload).into()
}

fn durable_transaction_key(transaction_id: &str) -> String {
    format!("{DURABLE_MEMPOOL_PREFIX}{transaction_id}")
}

impl TransactionPool {
    /// Create a new pool with the given capacity limit.
    pub fn new(max_size: usize) -> Arc<Self> {
        Self::new_with_chain_id(max_size, bleep_crypto::DEFAULT_CHAIN_ID)
    }

    /// Create a pool pinned to an explicit network chain ID.
    pub fn new_with_chain_id(max_size: usize, chain_id: impl Into<String>) -> Arc<Self> {
        Self::new_with_state(max_size, chain_id, None)
    }

    /// Create a pool with the live ledger required for balance and nonce checks.
    /// Pools created without state fail closed on admission.
    pub fn new_with_state(
        max_size: usize,
        chain_id: impl Into<String>,
        state: Option<Arc<StateMutex<StateManager>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            pool: Mutex::new(Vec::with_capacity(max_size.min(65_536))),
            seen_hashes: Mutex::new(HashSet::new()),
            chain_id: chain_id.into(),
            max_size,
            state,
            pool_bytes: AtomicUsize::new(0),
        })
    }

    /// Validate and admit a transaction into the pool.
    ///
    /// Checks capacity, required fields, signature format and sender ownership,
    /// cryptographic signature validity, and duplicate payloads.
    ///
    /// Returns `true` if the transaction was admitted, `false` otherwise.
    pub async fn add_transaction(&self, transaction: ZKTransaction) -> bool {
        if transaction.sender.is_empty() {
            log::error!("[TxPool] Rejected: sender is empty");
            return false;
        }
        if transaction.chain_id != self.chain_id {
            log::error!(
                "[TxPool] Rejected: chain ID mismatch (expected {}, got {})",
                self.chain_id,
                transaction.chain_id
            );
            return false;
        }
        if transaction.receiver.is_empty() {
            log::error!("[TxPool] Rejected: receiver is empty");
            return false;
        }
        if transaction.sender == transaction.receiver {
            log::error!(
                "[TxPool] Rejected: sender == receiver ({})",
                transaction.sender
            );
            return false;
        }
        if transaction.amount == 0 {
            log::error!(
                "[TxPool] Rejected: zero-amount tx from {}",
                transaction.sender
            );
            return false;
        }
        if transaction.version != 2 || transaction.fee < MIN_TRANSACTION_FEE {
            log::warn!("[TxPool] Rejected: transaction is not fee-bearing V2");
            return false;
        }
        if transaction.timestamp == 0 {
            log::error!(
                "[TxPool] Rejected: zero timestamp from {}",
                transaction.sender
            );
            return false;
        }

        // ── Step 3: Signature length check ────────────────────────────────────
        // Reject obviously truncated SPHINCS+ key/signature blobs before verification.
        if transaction.signature.len() != SPHINCS_PK_LEN + SPHINCS_SIG_LEN {
            log::error!(
                "[TxPool] Rejected: invalid signature length ({} bytes, expected {}) from {}",
                transaction.signature.len(),
                SPHINCS_PK_LEN + SPHINCS_SIG_LEN,
                transaction.sender
            );
            return false;
        }

        // ── Step 4: S-07 — SPHINCS+ cryptographic verification ───────────────
        //
        if !transaction.verify_account_authorization() {
            log::error!(
                "[TxPool] Rejected: SPHINCS+ authorization failed — tx from {} to {} amount {}",
                transaction.sender,
                transaction.receiver,
                transaction.amount
            );
            return false;
        }

        // ── Step 5: S-09 — Duplicate detection via payload hash ──────────────
        //
        // Hash the canonical payload (same bytes that were signed).
        // This catches exact replays (same sender/receiver/amount/timestamp).
        let tx_hash = transaction_payload_hash(&transaction);
        let mut pool = self.pool.lock().await;
        let mut seen = self.seen_hashes.lock().await;
        if seen.contains(&tx_hash) {
            log::warn!(
                "[TxPool] S-09: Duplicate tx rejected (hash={}…) from {}",
                hex::encode(&tx_hash[..4]),
                transaction.sender
            );
            return false;
        }

        let Some(state) = self.state.as_ref() else {
            log::warn!("[TxPool] Rejected transaction: state-backed admission unavailable");
            return false;
        };
        let mut state = state.lock();
        if let Err(error) = state.validate_transaction_timestamp(transaction.timestamp) {
            log::warn!("[TxPool] Rejected transaction: {error}");
            return false;
        }
        let sender_pending: Vec<_> = pool
            .iter()
            .filter(|tx| tx.sender == transaction.sender)
            .cloned()
            .collect();
        if !pending_admission_allowed(&state, &sender_pending, &transaction) {
            log::warn!(
                "[TxPool] Rejected transaction: balance, nonce, or sender limit failed for {}",
                transaction.sender
            );
            return false;
        }

        if self.max_size == 0 {
            return false;
        }
        let transaction_bytes = transaction_size(&transaction);
        if transaction_bytes > MAX_POOL_BYTES {
            return false;
        }
        let mut projected_count = pool.len().saturating_add(1);
        let mut projected_bytes = self
            .pool_bytes
            .load(Ordering::Relaxed)
            .saturating_add(transaction_bytes);
        let mut evict_count = 0;
        while projected_count > self.max_size || projected_bytes > MAX_POOL_BYTES {
            let Some(lowest_index) = pool.len().checked_sub(evict_count + 1) else {
                return false;
            };
            let Some(lowest) = pool.get(lowest_index) else {
                return false;
            };
            if compare_fee_priority(&transaction, lowest) != std::cmp::Ordering::Greater {
                return false;
            }
            evict_count += 1;
            projected_count -= 1;
            projected_bytes = projected_bytes.saturating_sub(transaction_size(lowest));
        }
        let mut changes = pool
            .iter()
            .rev()
            .take(evict_count)
            .map(|evicted| (durable_transaction_key(&evicted.get_hash()), None))
            .collect::<Vec<_>>();
        let serialized = match serde_json::to_vec(&transaction) {
            Ok(serialized) => serialized,
            Err(error) => {
                log::error!(
                    "[TxPool] Could not serialize transaction for durable admission: {error}"
                );
                return false;
            }
        };
        changes.push((
            durable_transaction_key(&transaction.get_hash()),
            Some(serialized),
        ));
        if let Err(error) = state.update_application_data(&changes) {
            log::error!("[TxPool] Durable transaction admission failed: {error}");
            return false;
        }
        for _ in 0..evict_count {
            let evicted = pool.pop().expect("planned transaction eviction");
            self.pool_bytes
                .fetch_sub(transaction_size(&evicted), Ordering::Relaxed);
            seen.remove(&transaction_payload_hash(&evicted));
        }
        let insert_at = pool
            .binary_search_by(|existing| compare_fee_priority(existing, &transaction).reverse())
            .unwrap_or_else(|index| index);
        pool.insert(insert_at, transaction);
        self.pool_bytes
            .fetch_add(transaction_bytes, Ordering::Relaxed);
        seen.insert(tx_hash);
        log::debug!(
            "[TxPool] Admitted tx — pool {}/{}",
            pool.len(),
            self.max_size
        );
        true
    }

    pub async fn restore_pending_transactions(&self) -> Result<(usize, usize), String> {
        let Some(state) = self.state.as_ref() else {
            return Err("Cannot restore pending transactions without state storage".into());
        };
        let records = state
            .lock()
            .application_data_with_prefix(DURABLE_MEMPOOL_PREFIX)
            .map_err(|error| format!("Failed to read durable mempool: {error}"))?;
        let mut restored = 0usize;
        let mut dropped = 0usize;
        let mut pending = Vec::with_capacity(records.len());
        for (key, bytes) in records {
            let transaction = match serde_json::from_slice::<ZKTransaction>(&bytes) {
                Ok(transaction) => transaction,
                Err(error) => {
                    log::error!(
                        "[TxPool] Dropping corrupt durable pending transaction {}: {error}",
                        key
                    );
                    state
                        .lock()
                        .update_application_data(&[(key, None)])
                        .map_err(|error| {
                            format!("Failed to remove corrupt mempool record: {error}")
                        })?;
                    dropped += 1;
                    continue;
                }
            };
            pending.push((key, transaction));
        }
        pending.sort_by(|left, right| {
            left.1
                .sender
                .cmp(&right.1.sender)
                .then_with(|| left.1.nonce.cmp(&right.1.nonce))
        });
        for (key, transaction) in pending {
            if self.add_transaction(transaction.clone()).await {
                restored += 1;
            } else {
                log::warn!(
                    "[TxPool] Explicitly dropped invalid or expired durable pending transaction {}",
                    transaction.get_hash()
                );
                state
                    .lock()
                    .update_application_data(&[(key, None)])
                    .map_err(|error| format!("Failed to remove invalid mempool record: {error}"))?;
                dropped += 1;
            }
        }
        Ok((restored, dropped))
    }

    /// Retrieve all pending transactions (read-only snapshot).
    pub async fn get_transactions(&self) -> Vec<ZKTransaction> {
        let pool = self.pool.lock().await;
        pool.iter().cloned().collect()
    }

    /// Remove all pending transactions (called after a block is committed).
    pub async fn clear_pool(&self) {
        let mut pool = self.pool.lock().await;
        if let Some(state) = self.state.as_ref() {
            let changes = pool
                .iter()
                .map(|transaction| (durable_transaction_key(&transaction.get_hash()), None))
                .collect::<Vec<_>>();
            if let Err(error) = state.lock().update_application_data(&changes) {
                log::error!("[TxPool] Failed to clear durable mempool: {error}");
                return;
            }
        }
        pool.clear();
        self.pool_bytes.store(0, Ordering::Relaxed);
        self.seen_hashes.lock().await.clear();
    }

    /// Remove transactions older than the supplied age.
    pub async fn prune_expired(&self, max_age: chrono::Duration) -> usize {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let max_age_secs = max_age.num_seconds().max(0) as u64;
        let mut pool = self.pool.lock().await;
        let before = pool.len();
        let expired = pool
            .iter()
            .filter(|tx| tx.timestamp > now || now.saturating_sub(tx.timestamp) > max_age_secs)
            .map(|transaction| (durable_transaction_key(&transaction.get_hash()), None))
            .collect::<Vec<_>>();
        if let Some(state) = self.state.as_ref() {
            if let Err(error) = state.lock().update_application_data(&expired) {
                log::error!("[TxPool] Failed to prune durable mempool: {error}");
                return 0;
            }
        }
        pool.retain(|tx| tx.timestamp <= now && now.saturating_sub(tx.timestamp) <= max_age_secs);
        self.pool_bytes
            .store(pool_size_bytes(&pool), Ordering::Relaxed);
        let active_hashes: HashSet<_> = pool.iter().map(transaction_payload_hash).collect();
        self.seen_hashes
            .lock()
            .await
            .retain(|hash| active_hashes.contains(hash));
        before - pool.len()
    }

    /// Current pool depth.
    pub async fn pool_size(&self) -> usize {
        self.pool.lock().await.len()
    }

    /// Return the next contiguous nonce for a sender, including pending transactions.
    pub async fn next_nonce(&self, sender: &str, committed_nonce: u64) -> Option<u64> {
        let pool = self.pool.lock().await;
        let pending_nonces: BTreeSet<u64> = pool
            .iter()
            .filter(|tx| tx.sender == sender && tx.nonce >= committed_nonce)
            .map(|tx| tx.nonce)
            .collect();

        let mut next_nonce = committed_nonce;
        while pending_nonces.contains(&next_nonce) {
            next_nonce = next_nonce.checked_add(1)?;
        }
        Some(next_nonce)
    }

    /// Remove a confirmed transaction by its canonical ID.
    pub async fn remove_confirmed(&self, tx_id: &str) {
        let mut pool = self.pool.lock().await;
        let before = pool.len();
        let removed = pool
            .iter()
            .filter(|transaction| transaction.get_hash() == tx_id)
            .map(|_| (durable_transaction_key(tx_id), None))
            .collect::<Vec<_>>();
        if let Some(state) = self.state.as_ref() {
            if let Err(error) = state.lock().update_application_data(&removed) {
                log::error!(
                    "[TxPool] Failed to remove confirmed transaction from durable mempool: {error}"
                );
            }
        }
        pool.retain(|tx| tx.get_hash() != tx_id);
        self.pool_bytes
            .store(pool_size_bytes(&pool), Ordering::Relaxed);
        let active_hashes: HashSet<_> = pool.iter().map(transaction_payload_hash).collect();
        self.seen_hashes
            .lock()
            .await
            .retain(|hash| active_hashes.contains(hash));
        log::debug!(
            "[TxPool] remove_confirmed '{}': {} → {} pending",
            tx_id,
            before,
            pool.len()
        );
    }

    /// Peek at up to `limit` transactions for block production.
    pub async fn peek_for_block(&self, limit: usize) -> Vec<ZKTransaction> {
        let pool = self.pool.lock().await;
        let Some(state) = self.state.as_ref() else {
            return pool.iter().take(limit).cloned().collect();
        };
        let mut next_nonce = HashMap::<String, u64>::new();
        let mut selected = Vec::with_capacity(limit.min(pool.len()));
        let mut included = HashSet::new();
        while selected.len() < limit {
            let candidate = pool.iter().find(|tx| {
                if included.contains(&tx.get_hash()) {
                    return false;
                }
                let expected = *next_nonce
                    .entry(tx.sender.clone())
                    .or_insert_with(|| state.lock().get_nonce(&tx.sender));
                tx.nonce == expected
            });
            let Some(candidate) = candidate else {
                break;
            };
            let tx = candidate.clone();
            included.insert(tx.get_hash());
            next_nonce.insert(tx.sender.clone(), tx.nonce.saturating_add(1));
            selected.push(tx);
        }
        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_crypto::tx_signer::{generate_tx_keypair, sign_tx_payload};
    use proptest::prelude::*;

    fn test_state() -> StateManager {
        static NEXT_STATE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bleep-txpool-test-{}-{}",
            std::process::id(),
            NEXT_STATE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        StateManager::open(path).expect("open test state")
    }

    fn funded_pool(max_size: usize, sender: &str, balance: u128) -> Arc<TransactionPool> {
        let state = Arc::new(StateMutex::new(test_state()));
        state
            .lock()
            .set_balance(sender, balance)
            .expect("fund test sender");
        TransactionPool::new_with_state(max_size, bleep_crypto::DEFAULT_CHAIN_ID, Some(state))
    }

    #[tokio::test]
    async fn prune_expired_removes_stale_and_future_transactions() {
        let pool = TransactionPool::new(4);
        let now = chrono::Utc::now().timestamp() as u64;
        let transaction = |timestamp| ZKTransaction {
            version: 2,
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            sender: "sender".into(),
            receiver: "receiver".into(),
            amount: 1,
            fee: 1,
            timestamp,
            nonce: timestamp,
            signature: vec![],
        };
        pool.pool.lock().await.extend([
            transaction(now),
            transaction(now.saturating_sub(61)),
            transaction(now.saturating_add(60)),
        ]);

        assert_eq!(pool.prune_expired(chrono::Duration::seconds(60)).await, 2);
        assert_eq!(pool.pool_size().await, 1);
    }

    fn make_signed_tx(sender: &str, receiver: &str, amount: u64, timestamp: u64) -> ZKTransaction {
        let (pk, sk) = generate_tx_keypair();
        let sender = if sender.is_empty() {
            String::new()
        } else {
            bleep_crypto::derive_account_address(&pk)
        };
        make_signed_tx_with_key(&pk, &sk, &sender, receiver, amount, 1, timestamp, 0)
    }

    fn make_signed_tx_with_key(
        pk: &[u8],
        sk: &[u8],
        sender: &str,
        receiver: &str,
        amount: u64,
        fee: u64,
        timestamp: u64,
        nonce: u64,
    ) -> ZKTransaction {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let timestamp = if current_time.abs_diff(timestamp) > 30 {
            current_time.saturating_add(timestamp % 20)
        } else {
            timestamp
        };
        let chain_id = bleep_crypto::DEFAULT_CHAIN_ID.to_string();
        let payload = bleep_crypto::tx_signer::tx_payload_v2(
            &chain_id, &sender, receiver, amount, fee, timestamp, nonce,
        );
        let sig = sign_tx_payload(&payload, sk).expect("sign");
        let mut signature = Vec::with_capacity(pk.len() + sig.len());
        signature.extend_from_slice(pk);
        signature.extend_from_slice(&sig);
        ZKTransaction {
            version: 2,
            chain_id,
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            amount,
            fee,
            timestamp,
            nonce,
            signature,
        }
    }

    #[tokio::test]
    async fn test_valid_tx_admitted() {
        let tx = make_signed_tx("alice", "bob", 500, 1_700_000_000);
        let pool = funded_pool(100, &tx.sender, 10_000);
        assert!(pool.add_transaction(tx).await);
        assert_eq!(pool.pool_size().await, 1);
    }

    #[tokio::test]
    async fn test_s07_empty_signature_rejected() {
        let pool = TransactionPool::new(100);
        let tx = ZKTransaction {
            version: 2,
            sender: "alice".into(),
            receiver: "bob".into(),
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            amount: 100,
            fee: 1,
            timestamp: 1_700_000_001,
            nonce: 0,
            signature: vec![],
        };
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_s07_short_signature_rejected() {
        let pool = TransactionPool::new(100);
        let tx = ZKTransaction {
            version: 2,
            sender: "alice".into(),
            receiver: "bob".into(),
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            amount: 100,
            fee: 1,
            timestamp: 1_700_000_002,
            nonce: 0,
            signature: vec![0u8; 10], // too short
        };
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_s07_invalid_sphincs_signature_rejected() {
        let pool = TransactionPool::new(100);
        let tx = ZKTransaction {
            version: 2,
            sender: "alice".into(),
            receiver: "bob".into(),
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            amount: 100,
            fee: 1,
            timestamp: 1_700_000_003,
            nonce: 0,
            signature: vec![0u8; SPHINCS_PK_LEN + SPHINCS_SIG_LEN],
        };
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_s07_tampered_signature_rejected() {
        let pool = TransactionPool::new(100);
        let mut tx = make_signed_tx("alice", "bob", 200, 1_700_000_004);
        tx.signature[SPHINCS_PK_LEN] ^= 0xFF;
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_s07_wrong_amount_rejected() {
        let pool = TransactionPool::new(100);
        let mut tx = make_signed_tx("alice", "bob", 200, 1_700_000_005);
        tx.amount = 999;
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_sender_must_match_signing_key_address() {
        let pool = TransactionPool::new(100);
        let mut tx = make_signed_tx("attacker", "attacker-receiver", 500, 1_700_000_006);
        tx.sender = "BLEEP1victim".to_string();
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_wrong_chain_id_rejected() {
        let pool = TransactionPool::new(100);
        let mut tx = make_signed_tx("alice", "bob", 500, 1_700_000_007);
        tx.chain_id = "BLEEP-Mainnet".to_string();
        assert!(!pool.add_transaction(tx).await);
    }

    // ── S-09: duplicate detection ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_s09_exact_duplicate_rejected() {
        let tx1 = make_signed_tx("alice", "bob", 300, 1_700_000_010);
        let pool = funded_pool(100, &tx1.sender, 10_000);
        // Build an identical tx with the same payload (same sender/receiver/amount/timestamp)
        // by re-signing with a different key — same payload hash, so should be caught
        let tx2 = tx1.clone();
        assert!(pool.add_transaction(tx1).await, "First tx admitted");
        assert!(
            !pool.add_transaction(tx2).await,
            "S-09: exact duplicate rejected"
        );
    }

    #[tokio::test]
    async fn test_s09_different_timestamp_admitted() {
        let tx1 = make_signed_tx("alice", "bob", 300, 1_700_000_020);
        let tx2 = make_signed_tx("alice", "bob", 300, 1_700_000_021);
        let state = Arc::new(StateMutex::new(test_state()));
        state
            .lock()
            .set_balance(&tx1.sender, 10_000)
            .expect("fund first sender");
        state
            .lock()
            .set_balance(&tx2.sender, 10_000)
            .expect("fund second sender");
        let pool =
            TransactionPool::new_with_state(100, bleep_crypto::DEFAULT_CHAIN_ID, Some(state));
        assert!(pool.add_transaction(tx1).await);
        assert!(pool.add_transaction(tx2).await);
        assert_eq!(pool.pool_size().await, 2);
    }

    #[tokio::test]
    async fn rejects_duplicate_nonce_even_with_different_signed_payload() {
        let (public_key, secret_key) = generate_tx_keypair();
        let sender = bleep_crypto::derive_account_address(&public_key);
        let first = make_signed_tx_with_key(
            &public_key,
            &secret_key,
            &sender,
            "recipient-a",
            100,
            1,
            1_700_000_025,
            0,
        );
        let second = make_signed_tx_with_key(
            &public_key,
            &secret_key,
            &sender,
            "recipient-b",
            100,
            1,
            1_700_000_026,
            0,
        );
        let state = Arc::new(StateMutex::new(test_state()));
        state
            .lock()
            .set_balance(&first.sender, 10_000)
            .expect("fund sender");
        let pool = TransactionPool::new_with_state(10, bleep_crypto::DEFAULT_CHAIN_ID, Some(state));
        assert!(pool.add_transaction(first).await);
        assert!(!pool.add_transaction(second).await);
        assert_eq!(pool.pool_size().await, 1);
    }

    #[tokio::test]
    async fn rejects_nonce_gap_until_missing_transaction_arrives() {
        let (public_key, secret_key) = generate_tx_keypair();
        let sender = bleep_crypto::derive_account_address(&public_key);
        let nonce_zero = make_signed_tx_with_key(
            &public_key,
            &secret_key,
            &sender,
            "recipient-zero",
            100,
            1,
            1_700_000_025,
            0,
        );
        let nonce_one = make_signed_tx_with_key(
            &public_key,
            &secret_key,
            &sender,
            "recipient-one",
            100,
            1,
            1_700_000_026,
            1,
        );
        let state = Arc::new(StateMutex::new(test_state()));
        state
            .lock()
            .set_balance(&sender, 10_000)
            .expect("fund sender");
        let pool = TransactionPool::new_with_state(10, bleep_crypto::DEFAULT_CHAIN_ID, Some(state));

        assert!(!pool.add_transaction(nonce_one.clone()).await);
        assert!(pool.add_transaction(nonce_zero).await);
        assert!(pool.add_transaction(nonce_one).await);
        assert_eq!(pool.pool_size().await, 2);
    }

    proptest! {
        #[test]
        fn random_pending_nonces_are_unique_and_bounded(nonces in prop::collection::vec(any::<u64>(), 0..160)) {
            let mut state = test_state();
            state.set_balance("sender", 10_000).expect("fund sender");
            let mut pending = Vec::new();
            for nonce in nonces {
                let candidate = ZKTransaction {
                    version: 2,
                    chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
                    sender: "sender".into(),
                    receiver: format!("recipient-{nonce}"),
                    amount: 1,
                    fee: 1,
                    timestamp: 1,
                    nonce,
                    signature: Vec::new(),
                };
                if pending_admission_allowed(&state, &pending, &candidate) {
                    pending.push(candidate);
                }
            }

            let accepted_nonces: BTreeSet<_> = pending.iter().map(|tx| tx.nonce).collect();
            prop_assert_eq!(accepted_nonces.len(), pending.len());
            prop_assert!(pending.len() <= crate::transaction::MAX_PENDING_PER_SENDER);
            for (expected, nonce) in accepted_nonces.iter().enumerate() {
                prop_assert_eq!(*nonce, expected as u64);
            }
        }
    }

    #[tokio::test]
    async fn evicts_lowest_fee_transaction_when_pool_is_full() {
        let (low_pk, low_sk) = generate_tx_keypair();
        let low_sender = bleep_crypto::derive_account_address(&low_pk);
        let low_fee = make_signed_tx_with_key(
            &low_pk,
            &low_sk,
            &low_sender,
            "recipient",
            1,
            1,
            1_700_000_040,
            0,
        );
        let (high_pk, high_sk) = generate_tx_keypair();
        let high_sender = bleep_crypto::derive_account_address(&high_pk);
        let high_fee = make_signed_tx_with_key(
            &high_pk,
            &high_sk,
            &high_sender,
            "recipient",
            1,
            10,
            1_700_000_041,
            0,
        );
        let state = Arc::new(StateMutex::new(test_state()));
        state
            .lock()
            .set_balance(&low_fee.sender, 100)
            .expect("fund low-fee sender");
        state
            .lock()
            .set_balance(&high_fee.sender, 100)
            .expect("fund high-fee sender");
        let pool = TransactionPool::new_with_state(1, bleep_crypto::DEFAULT_CHAIN_ID, Some(state));
        assert!(pool.add_transaction(low_fee.clone()).await);
        assert!(pool.add_transaction(high_fee.clone()).await);
        let retained = pool.get_transactions().await;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].sender, high_fee.sender);
        assert_ne!(retained[0].sender, low_fee.sender);
    }

    #[tokio::test]
    async fn tenfold_capacity_load_retains_highest_fee_transactions() {
        let state = Arc::new(StateMutex::new(test_state()));
        let pool = TransactionPool::new_with_state(
            2,
            bleep_crypto::DEFAULT_CHAIN_ID,
            Some(Arc::clone(&state)),
        );
        let free_transaction = ZKTransaction {
            version: 2,
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            sender: "unfunded".into(),
            receiver: "recipient".into(),
            amount: 1,
            fee: 0,
            timestamp: 1_700_000_039,
            nonce: 0,
            signature: vec![],
        };
        assert!(!pool.add_transaction(free_transaction).await);

        for fee in 1..=20 {
            let (public_key, secret_key) = generate_tx_keypair();
            let sender = bleep_crypto::derive_account_address(&public_key);
            state
                .lock()
                .set_balance(&sender, 100)
                .expect("fund load-test sender");
            let transaction = make_signed_tx_with_key(
                &public_key,
                &secret_key,
                &sender,
                "load-test-recipient",
                1,
                fee,
                1_700_000_040 + fee,
                0,
            );
            assert!(pool.add_transaction(transaction).await);
        }

        let retained = pool.get_transactions().await;
        assert_eq!(retained.len(), 2);
        assert_eq!(
            retained.iter().map(|tx| tx.fee).collect::<BTreeSet<_>>(),
            [19, 20].into_iter().collect()
        );
        assert!(pool.pool_size().await <= 2);
    }

    #[tokio::test]
    async fn test_empty_sender_rejected() {
        let pool = TransactionPool::new(100);
        assert!(
            !pool
                .add_transaction(make_signed_tx("", "bob", 100, 1_700_000_030))
                .await
        );
    }

    #[tokio::test]
    async fn test_zero_amount_rejected() {
        let pool = TransactionPool::new(100);
        let tx = ZKTransaction {
            version: 2,
            sender: "alice".into(),
            receiver: "bob".into(),
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            amount: 0,
            fee: 1,
            timestamp: 1_700_000_031,
            nonce: 0,
            signature: vec![1u8; SPHINCS_PK_LEN + SPHINCS_SIG_LEN],
        };
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_self_transfer_rejected() {
        let pool = TransactionPool::new(100);
        let mut tx = make_signed_tx("alice", "alice", 100, 1_700_000_032);
        tx.receiver = tx.sender.clone();
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_capacity_limit() {
        let (first_pk, first_sk) = generate_tx_keypair();
        let first_sender = bleep_crypto::derive_account_address(&first_pk);
        let first = make_signed_tx_with_key(
            &first_pk,
            &first_sk,
            &first_sender,
            "b",
            1,
            3,
            1_700_100_001,
            0,
        );
        let (second_pk, second_sk) = generate_tx_keypair();
        let second_sender = bleep_crypto::derive_account_address(&second_pk);
        let second = make_signed_tx_with_key(
            &second_pk,
            &second_sk,
            &second_sender,
            "d",
            1,
            2,
            1_700_100_002,
            0,
        );
        let (third_pk, third_sk) = generate_tx_keypair();
        let third_sender = bleep_crypto::derive_account_address(&third_pk);
        let third = make_signed_tx_with_key(
            &third_pk,
            &third_sk,
            &third_sender,
            "f",
            1,
            1,
            1_700_100_003,
            0,
        );
        let state = Arc::new(StateMutex::new(test_state()));
        state
            .lock()
            .set_balance(&first.sender, 100)
            .expect("fund first sender");
        state
            .lock()
            .set_balance(&second.sender, 100)
            .expect("fund second sender");
        state
            .lock()
            .set_balance(&third.sender, 100)
            .expect("fund third sender");
        let pool = TransactionPool::new_with_state(2, bleep_crypto::DEFAULT_CHAIN_ID, Some(state));
        assert!(pool.add_transaction(first).await);
        assert!(pool.add_transaction(second).await);
        assert_eq!(pool.pool_size().await, 2);
        assert!(!pool.add_transaction(third).await);
    }

    #[tokio::test]
    async fn test_peek_for_block() {
        let transactions: Vec<_> = [(1, 1_700_200_001), (2, 1_700_200_002), (3, 1_700_200_003)]
            .into_iter()
            .map(|(amount, timestamp)| make_signed_tx("a", "b", amount, timestamp))
            .collect();
        let state = Arc::new(StateMutex::new(test_state()));
        for transaction in &transactions {
            state
                .lock()
                .set_balance(&transaction.sender, 10_000)
                .expect("fund sender");
        }
        let pool =
            TransactionPool::new_with_state(100, bleep_crypto::DEFAULT_CHAIN_ID, Some(state));
        for transaction in transactions {
            assert!(pool.add_transaction(transaction).await);
        }
        assert_eq!(pool.peek_for_block(2).await.len(), 2);
        assert_eq!(pool.pool_size().await, 3);
    }

    #[tokio::test]
    async fn pending_transactions_are_restored_and_removed_durably() {
        let path = std::env::temp_dir().join(format!(
            "bleep-txpool-restart-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let mut initial_state = test_state_at(&path);
        let (public_key, secret_key) = generate_tx_keypair();
        let sender = bleep_crypto::derive_account_address(&public_key);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let transaction =
            make_signed_tx_with_key(&public_key, &secret_key, &sender, "bob", 1, 1, timestamp, 0);
        let next_transaction = make_signed_tx_with_key(
            &public_key,
            &secret_key,
            &sender,
            "carol",
            1,
            1,
            timestamp + 1,
            1,
        );
        initial_state.set_balance(&sender, 10).expect("fund sender");
        initial_state
            .commit_block()
            .expect("persist sender balance");
        let initial_state = Arc::new(StateMutex::new(initial_state));
        let initial_pool = TransactionPool::new_with_state(
            10,
            bleep_crypto::DEFAULT_CHAIN_ID,
            Some(Arc::clone(&initial_state)),
        );
        assert!(initial_pool.add_transaction(transaction.clone()).await);
        assert!(initial_pool.add_transaction(next_transaction.clone()).await);
        drop(initial_pool);
        drop(initial_state);

        let reopened = Arc::new(StateMutex::new(
            StateManager::open(&path).expect("reopen persisted state"),
        ));
        let restored_pool = TransactionPool::new_with_state(
            10,
            bleep_crypto::DEFAULT_CHAIN_ID,
            Some(Arc::clone(&reopened)),
        );
        assert_eq!(
            restored_pool.restore_pending_transactions().await.unwrap(),
            (2, 0)
        );
        let restored = restored_pool.get_transactions().await;
        assert_eq!(restored.len(), 2);
        assert_eq!(restored_pool.peek_for_block(2).await.len(), 2);
        assert_eq!(restored_pool.next_nonce(&sender, 0).await, Some(2));

        restored_pool
            .remove_confirmed(&transaction.get_hash())
            .await;
        restored_pool
            .remove_confirmed(&next_transaction.get_hash())
            .await;
        assert!(reopened
            .lock()
            .application_data_with_prefix(DURABLE_MEMPOOL_PREFIX)
            .unwrap()
            .is_empty());
        drop(restored_pool);
        drop(reopened);
        let _ = std::fs::remove_dir_all(path);
    }

    fn test_state_at(path: &std::path::Path) -> StateManager {
        StateManager::open(path).expect("open explicit test state")
    }
}
