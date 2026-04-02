//! # TransactionPool
//!
use crate::transaction::ZKTransaction;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Minimum signature length: 32-byte pk + at least 1 byte of sig material.
const MIN_SIG_LEN: usize = 33;

/// Expected full signature length: 32-byte pk + 49856-byte SPHINCS+ detached sig.
const SPHINCS_PK_LEN: usize = 32;

// ── TransactionPool ───────────────────────────────────────────────────────────

/// FIFO transaction pool with SPHINCS+ signature verification on admission.
pub struct TransactionPool {
    /// Ordered queue of validated, pending transactions.
    pool: Mutex<VecDeque<ZKTransaction>>,
    /// SHA-256 hashes of all transactions ever seen (prevents replay).
    seen_hashes: Mutex<HashSet<[u8; 32]>>,
    /// Maximum number of pending transactions.
    max_size: usize,
}

impl TransactionPool {
    /// Create a new pool with the given capacity limit.
    pub fn new(max_size: usize) -> Arc<Self> {
        Arc::new(Self {
            pool: Mutex::new(VecDeque::with_capacity(max_size.min(65_536))),
            seen_hashes: Mutex::new(HashSet::new()),
            max_size,
        })
    }

    /// Validate and admit a transaction into the pool.
    ///
    /// Checks (in order):
    /// 1. Pool capacity
    /// 2. Required fields (sender, receiver non-empty; amount > 0; sender ≠ receiver)
    /// 3. Signature present and structurally valid length
    /// 4. **S-07**: SPHINCS+ cryptographic signature verification
    /// 5. **S-09**: Duplicate detection via SHA-256 payload hash
    ///
    /// Returns `true` if the transaction was admitted, `false` otherwise.
    pub async fn add_transaction(&self, transaction: ZKTransaction) -> bool {
        // ── Step 1: Capacity check ────────────────────────────────────────────
        {
            let pool = self.pool.lock().await;
            if pool.len() >= self.max_size {
                log::warn!(
                    "[TxPool] At capacity ({}/{}), rejecting tx from {}",
                    pool.len(),
                    self.max_size,
                    transaction.sender
                );
                return false;
            }
        }

        // ── Step 2: Structural field validation ───────────────────────────────
        if transaction.sender.is_empty() {
            log::error!("[TxPool] Rejected: sender is empty");
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
        if transaction.timestamp == 0 {
            log::error!(
                "[TxPool] Rejected: zero timestamp from {}",
                transaction.sender
            );
            return false;
        }

        // ── Step 3: Signature length check ────────────────────────────────────
        if transaction.signature.len() < MIN_SIG_LEN {
            log::error!(
                "[TxPool] Rejected: signature too short ({} bytes, need ≥ {}) from {}",
                transaction.signature.len(),
                MIN_SIG_LEN,
                transaction.sender
            );
            return false;
        }

        // ── Step 4: S-07 — SPHINCS+ cryptographic verification ───────────────
        //
        // Wire format: signature = pk_bytes(32) || sphincs_detached_sig(49856)
        // Canonical payload: SHA3-256(sender || receiver || amount_le8 || timestamp_le8)
        //
        // We split the signature blob into (pk, sig) and verify using the same
        // tx_payload() function used at signing time.
        let pk_bytes = &transaction.signature[..SPHINCS_PK_LEN];
        let sig_bytes = &transaction.signature[SPHINCS_PK_LEN..];

        let payload = bleep_crypto::tx_signer::tx_payload(
            &transaction.sender,
            &transaction.receiver,
            transaction.amount,
            transaction.timestamp,
        );

        if !bleep_crypto::tx_signer::verify_tx_signature(&payload, sig_bytes, pk_bytes) {
            log::error!(
                "[TxPool] S-07: SPHINCS+ verification FAILED — tx from {} to {} amount {} rejected",
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
        let tx_hash: [u8; 32] = Sha256::digest(&payload).into();

        {
            let mut seen = self.seen_hashes.lock().await;
            if seen.contains(&tx_hash) {
                log::warn!(
                    "[TxPool] S-09: Duplicate tx rejected (hash={}…) from {}",
                    hex::encode(&tx_hash[..4]),
                    transaction.sender
                );
                return false;
            }
            seen.insert(tx_hash);
        }

        // ── Admit ─────────────────────────────────────────────────────────────
        let mut pool = self.pool.lock().await;
        pool.push_back(transaction);
        log::debug!(
            "[TxPool] Admitted tx — pool {}/{}",
            pool.len(),
            self.max_size
        );
        true
    }

    /// Retrieve all pending transactions (read-only snapshot).
    pub async fn get_transactions(&self) -> Vec<ZKTransaction> {
        let pool = self.pool.lock().await;
        pool.iter().cloned().collect()
    }

    /// Remove all pending transactions (called after a block is committed).
    pub async fn clear_pool(&self) {
        let mut pool = self.pool.lock().await;
        pool.clear();
        // Note: seen_hashes is NOT cleared — previously seen hashes must remain
        // invalid to prevent cross-block replay attacks.
    }

    /// Current pool depth.
    pub async fn pool_size(&self) -> usize {
        self.pool.lock().await.len()
    }

    /// Remove a confirmed transaction by its canonical ID.
    ///
    /// The canonical ID string is `"sender:receiver:amount:timestamp"`.
    /// This is called after a block containing the transaction is finalised.
    pub async fn remove_confirmed(&self, tx_id: &str) {
        let mut pool = self.pool.lock().await;
        let before = pool.len();
        pool.retain(|tx| {
            format!(
                "{}:{}:{}:{}",
                tx.sender, tx.receiver, tx.amount, tx.timestamp
            ) != tx_id
        });
        log::debug!(
            "[TxPool] remove_confirmed '{}': {} → {} pending",
            tx_id,
            before,
            pool.len()
        );
    }

    /// Peek at up to `limit` transactions for block production.
    ///
    /// Transactions remain in the pool until `remove_confirmed` is called
    /// after the block is accepted by consensus.
    pub async fn peek_for_block(&self, limit: usize) -> Vec<ZKTransaction> {
        let pool = self.pool.lock().await;
        pool.iter().take(limit).cloned().collect()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_crypto::tx_signer::{generate_tx_keypair, sign_tx_payload, tx_payload};

    /// Build a properly-signed ZKTransaction.
    fn make_signed_tx(sender: &str, receiver: &str, amount: u64, timestamp: u64) -> ZKTransaction {
        let (pk, sk) = generate_tx_keypair();
        let payload = tx_payload(sender, receiver, amount, timestamp);
        let sig = sign_tx_payload(&payload, &sk).expect("sign");
        // Wire format: pk(32) || sphincs_sig
        let mut full_sig = Vec::with_capacity(pk.len() + sig.len());
        full_sig.extend_from_slice(&pk);
        full_sig.extend_from_slice(&sig);
        ZKTransaction {
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            amount,
            timestamp,
            signature: full_sig,
        }
    }

    #[tokio::test]
    async fn test_valid_tx_admitted() {
        let pool = TransactionPool::new(100);
        let tx = make_signed_tx("alice", "bob", 500, 1_700_000_000);
        assert!(
            pool.add_transaction(tx).await,
            "Valid signed tx must be admitted"
        );
        assert_eq!(pool.pool_size().await, 1);
    }

    // ── S-07: signature verification ─────────────────────────────────────────

    #[tokio::test]
    async fn test_s07_empty_signature_rejected() {
        let pool = TransactionPool::new(100);
        let tx = ZKTransaction {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 100,
            timestamp: 1_700_000_001,
            signature: vec![],
        };
        assert!(
            !pool.add_transaction(tx).await,
            "S-07: empty sig must be rejected"
        );
    }

    #[tokio::test]
    async fn test_s07_short_signature_rejected() {
        let pool = TransactionPool::new(100);
        let tx = ZKTransaction {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 100,
            timestamp: 1_700_000_002,
            signature: vec![0u8; 10], // too short
        };
        assert!(
            !pool.add_transaction(tx).await,
            "S-07: short sig must be rejected"
        );
    }

    #[tokio::test]
    async fn test_s07_invalid_sphincs_signature_rejected() {
        let pool = TransactionPool::new(100);
        // Correct length but all zeros — will fail SPHINCS+ verification
        let tx = ZKTransaction {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 100,
            timestamp: 1_700_000_003,
            signature: vec![0u8; SPHINCS_PK_LEN + 49856],
        };
        assert!(
            !pool.add_transaction(tx).await,
            "S-07: forged sig must fail SPHINCS+ verify"
        );
    }

    #[tokio::test]
    async fn test_s07_tampered_signature_rejected() {
        let pool = TransactionPool::new(100);
        let mut tx = make_signed_tx("alice", "bob", 200, 1_700_000_004);
        tx.signature[50] ^= 0xFF; // flip a byte in the sig portion
        assert!(
            !pool.add_transaction(tx).await,
            "S-07: tampered sig must be rejected"
        );
    }

    #[tokio::test]
    async fn test_s07_wrong_amount_rejected() {
        // Sign for amount=200 but submit with amount=999
        let pool = TransactionPool::new(100);
        let mut tx = make_signed_tx("alice", "bob", 200, 1_700_000_005);
        tx.amount = 999; // mismatch with signed payload
        assert!(
            !pool.add_transaction(tx).await,
            "S-07: mutated amount must fail SPHINCS+ verify"
        );
    }

    // ── S-09: duplicate detection ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_s09_exact_duplicate_rejected() {
        let pool = TransactionPool::new(100);
        let tx1 = make_signed_tx("alice", "bob", 300, 1_700_000_010);
        // Build an identical tx with the same payload (same sender/receiver/amount/timestamp)
        // by re-signing with a different key — same payload hash, so should be caught
        let tx2 = make_signed_tx("alice", "bob", 300, 1_700_000_010);
        assert!(pool.add_transaction(tx1).await, "First tx admitted");
        assert!(
            !pool.add_transaction(tx2).await,
            "S-09: exact duplicate rejected"
        );
    }

    #[tokio::test]
    async fn test_s09_different_timestamp_admitted() {
        // Different timestamps → different payload → different hash → both admitted
        let pool = TransactionPool::new(100);
        let tx1 = make_signed_tx("alice", "bob", 300, 1_700_000_020);
        let tx2 = make_signed_tx("alice", "bob", 300, 1_700_000_021);
        assert!(pool.add_transaction(tx1).await);
        assert!(
            pool.add_transaction(tx2).await,
            "S-09: different timestamp must be admitted"
        );
        assert_eq!(pool.pool_size().await, 2);
    }

    // ── Field validation ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_empty_sender_rejected() {
        let pool = TransactionPool::new(100);
        let tx = make_signed_tx("", "bob", 100, 1_700_000_030);
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_zero_amount_rejected() {
        let pool = TransactionPool::new(100);
        let tx = ZKTransaction {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 0,
            timestamp: 1_700_000_031,
            signature: vec![1u8; MIN_SIG_LEN + 10],
        };
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_self_transfer_rejected() {
        let pool = TransactionPool::new(100);
        let tx = make_signed_tx("alice", "alice", 100, 1_700_000_032);
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_capacity_limit() {
        let pool = TransactionPool::new(2);
        let tx1 = make_signed_tx("a", "b", 1, 1_700_100_001);
        let tx2 = make_signed_tx("a", "b", 2, 1_700_100_002);
        let tx3 = make_signed_tx("a", "b", 3, 1_700_100_003);
        assert!(pool.add_transaction(tx1).await);
        assert!(pool.add_transaction(tx2).await);
        assert!(
            !pool.add_transaction(tx3).await,
            "Pool at capacity must reject"
        );
    }

    #[tokio::test]
    async fn test_peek_for_block() {
        let pool = TransactionPool::new(100);
        let tx1 = make_signed_tx("a", "b", 1, 1_700_200_001);
        let tx2 = make_signed_tx("a", "b", 2, 1_700_200_002);
        let tx3 = make_signed_tx("a", "b", 3, 1_700_200_003);
        pool.add_transaction(tx1).await;
        pool.add_transaction(tx2).await;
        pool.add_transaction(tx3).await;
        let peeked = pool.peek_for_block(2).await;
        assert_eq!(peeked.len(), 2, "peek_for_block must respect limit");
        assert_eq!(pool.pool_size().await, 3, "peek must not remove txs");
    }
}
