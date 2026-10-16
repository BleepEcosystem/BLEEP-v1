//! # TransactionPool
//!
use crate::transaction::ZKTransaction;
use hex;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Expected SPHINCS+ public key length for sphincsshake256fsimple: 64 bytes
const SPHINCS_PK_LEN: usize = 64;
/// SPHINCS+-SHAKE-256f-simple detached signature length.
const SPHINCS_SIG_LEN: usize = 49_856;
const FULL_SIG_LEN: usize = SPHINCS_PK_LEN + SPHINCS_SIG_LEN;

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
    /// Checks capacity, required fields, signature format and sender ownership,
    /// cryptographic signature validity, and duplicate payloads.
    ///
    /// Returns `true` if the transaction was admitted, `false` otherwise.
    pub async fn add_transaction(&self, transaction: ZKTransaction) -> bool {
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

        if transaction.signature.len() != FULL_SIG_LEN {
            log::error!(
                "[TxPool] Rejected: invalid SPHINCS+ signature length (need {}, got {})",
                FULL_SIG_LEN,
                transaction.signature.len()
            );
            return false;
        }

        let pk_bytes = &transaction.signature[..SPHINCS_PK_LEN];
        let sig_bytes = &transaction.signature[SPHINCS_PK_LEN..];
        if bleep_crypto::tx_signer::derive_address(pk_bytes) != transaction.sender {
            log::error!(
                "[TxPool] Rejected: signer public key does not own sender address {}",
                transaction.sender
            );
            return false;
        }

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

        let tx_hash: [u8; 32] = Sha256::digest(payload).into();
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
        // Seen hashes remain to prevent cross-block replay attacks.
    }

    /// Current pool depth.
    pub async fn pool_size(&self) -> usize {
        self.pool.lock().await.len()
    }

    /// Remove a confirmed transaction by its canonical ID.
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
    pub async fn peek_for_block(&self, limit: usize) -> Vec<ZKTransaction> {
        let pool = self.pool.lock().await;
        pool.iter().take(limit).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_crypto::tx_signer::{generate_tx_keypair, sign_tx_payload, tx_payload};

    fn make_signed_tx(sender: &str, receiver: &str, amount: u64, timestamp: u64) -> ZKTransaction {
        let (pk, sk) = generate_tx_keypair();
        let sender = if sender.is_empty() || sender == receiver {
            sender.to_string()
        } else {
            bleep_crypto::tx_signer::derive_address(&pk)
        };
        let payload = tx_payload(&sender, receiver, amount, timestamp);
        let sig = sign_tx_payload(&payload, &sk).expect("sign");
        let mut signature = Vec::with_capacity(pk.len() + sig.len());
        signature.extend_from_slice(&pk);
        signature.extend_from_slice(&sig);
        ZKTransaction {
            sender,
            receiver: receiver.to_string(),
            amount,
            timestamp,
            signature,
        }
    }

    #[tokio::test]
    async fn test_valid_tx_admitted() {
        let pool = TransactionPool::new(100);
        let tx = make_signed_tx("alice", "bob", 500, 1_700_000_000);
        assert!(pool.add_transaction(tx).await);
        assert_eq!(pool.pool_size().await, 1);
    }

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
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_s07_short_signature_rejected() {
        let pool = TransactionPool::new(100);
        let tx = ZKTransaction {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 100,
            timestamp: 1_700_000_002,
            signature: vec![0u8; 10],
        };
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_s07_invalid_sphincs_signature_rejected() {
        let pool = TransactionPool::new(100);
        let tx = ZKTransaction {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 100,
            timestamp: 1_700_000_003,
            signature: vec![0u8; FULL_SIG_LEN],
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
        let mut tx = make_signed_tx("ignored", "receiver", 500, 1_700_000_006);
        tx.sender = "BLEEP1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_s09_exact_duplicate_rejected() {
        let pool = TransactionPool::new(100);
        let tx = make_signed_tx("alice", "bob", 300, 1_700_000_010);
        assert!(pool.add_transaction(tx.clone()).await);
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_s09_different_timestamp_admitted() {
        let pool = TransactionPool::new(100);
        let tx1 = make_signed_tx("alice", "bob", 300, 1_700_000_020);
        let tx2 = make_signed_tx("alice", "bob", 300, 1_700_000_021);
        assert!(pool.add_transaction(tx1).await);
        assert!(pool.add_transaction(tx2).await);
        assert_eq!(pool.pool_size().await, 2);
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
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 0,
            timestamp: 1_700_000_031,
            signature: vec![1u8; FULL_SIG_LEN],
        };
        assert!(!pool.add_transaction(tx).await);
    }

    #[tokio::test]
    async fn test_self_transfer_rejected() {
        let pool = TransactionPool::new(100);
        assert!(
            !pool
                .add_transaction(make_signed_tx("alice", "alice", 100, 1_700_000_032))
                .await
        );
    }

    #[tokio::test]
    async fn test_capacity_limit() {
        let pool = TransactionPool::new(2);
        assert!(
            pool.add_transaction(make_signed_tx("a", "b", 1, 1_700_100_001))
                .await
        );
        assert!(
            pool.add_transaction(make_signed_tx("a", "b", 2, 1_700_100_002))
                .await
        );
        assert!(
            !pool
                .add_transaction(make_signed_tx("a", "b", 3, 1_700_100_003))
                .await
        );
    }

    #[tokio::test]
    async fn test_peek_for_block() {
        let pool = TransactionPool::new(100);
        for (amount, timestamp) in [(1, 1_700_200_001), (2, 1_700_200_002), (3, 1_700_200_003)] {
            assert!(
                pool.add_transaction(make_signed_tx("a", "b", amount, timestamp))
                    .await
            );
        }
        assert_eq!(pool.peek_for_block(2).await.len(), 2);
        assert_eq!(pool.pool_size().await, 3);
    }
}
