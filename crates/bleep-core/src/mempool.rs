use crate::block::{SPHINCS_PK_LEN, SPHINCS_SIG_LEN};
use crate::transaction::ZKTransaction;
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Maximum pending transactions and corresponding seen IDs retained by the
/// P2P-facing mempool.
pub const MAX_MEMPOOL_ENTRIES: usize = 100_000;

type SenderPublicKeyResolver = dyn Fn(&str, &[u8]) -> Option<Vec<u8>> + Send + Sync + 'static;

/// The Mempool stores validated, unconfirmed transactions before block inclusion.
pub struct Mempool {
    transactions: Mutex<HashMap<String, ZKTransaction>>,
    seen_transactions: Mutex<HashSet<String>>,
    chain_id: String,
    sender_public_key: Arc<SenderPublicKeyResolver>,
    max_entries: usize,
}

impl Mempool {
    /// Initializes a mempool for one chain with a sender-key resolver.
    pub fn new(
        chain_id: impl Into<String>,
        sender_public_key: impl Fn(&str, &[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::with_capacity(
            chain_id.into(),
            Arc::new(sender_public_key),
            MAX_MEMPOOL_ENTRIES,
        )
    }

    fn with_capacity(
        chain_id: String,
        sender_public_key: Arc<SenderPublicKeyResolver>,
        max_entries: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            transactions: Mutex::new(HashMap::new()),
            seen_transactions: Mutex::new(HashSet::new()),
            chain_id,
            sender_public_key,
            max_entries,
        })
    }

    /// Resolve a sender key from the public key prefix carried in the
    /// transaction signature, requiring it to derive the claimed sender.
    ///
    /// This is the production resolver: account addresses are key-derived and
    /// this repository has no separate general-account public-key registry.
    pub fn embedded_sender_public_key(sender: &str, signature: &[u8]) -> Option<Vec<u8>> {
        let public_key = signature.get(..SPHINCS_PK_LEN)?;
        (bleep_crypto::derive_account_address(public_key) == sender).then(|| public_key.to_vec())
    }

    /// Adds a transaction after checking its chain, account binding, and
    /// SPHINCS+ signature.
    pub async fn add_transaction(&self, transaction: ZKTransaction) -> bool {
        if transaction.sender.is_empty() || transaction.receiver.is_empty() {
            log::error!("Transaction validation failed: missing sender or receiver");
            return false;
        }
        if transaction.amount == 0 {
            log::error!("Transaction validation failed: zero amount");
            return false;
        }
        if transaction.sender == transaction.receiver {
            log::error!("Transaction validation failed: sender cannot equal receiver");
            return false;
        }
        if transaction.chain_id != self.chain_id {
            log::error!(
                "Transaction validation failed: chain_id '{}' != node chain_id '{}'",
                transaction.chain_id,
                self.chain_id
            );
            return false;
        }
        if transaction.signature.len() != SPHINCS_PK_LEN + SPHINCS_SIG_LEN {
            log::error!("Transaction validation failed: invalid signature length");
            return false;
        }

        let Some(sender_pk) = (self.sender_public_key)(&transaction.sender, &transaction.signature)
        else {
            log::error!(
                "Transaction validation failed: unknown sender '{}'",
                transaction.sender
            );
            return false;
        };
        if sender_pk.len() != SPHINCS_PK_LEN
            || bleep_crypto::derive_account_address(&sender_pk) != transaction.sender
        {
            log::error!("Transaction validation failed: sender key does not match address");
            return false;
        }

        let payload = bleep_crypto::tx_signer::tx_payload(
            &transaction.chain_id,
            &transaction.sender,
            &transaction.receiver,
            transaction.amount,
            transaction.timestamp,
            transaction.nonce,
        );
        if !bleep_crypto::tx_signer::verify_tx_signature(
            &payload,
            &transaction.signature[SPHINCS_PK_LEN..],
            &sender_pk,
        ) {
            log::error!("Transaction validation failed: invalid signature");
            return false;
        }

        let tx_id = transaction.get_hash();
        let mut transactions = self.transactions.lock().await;
        let mut seen_transactions = self.seen_transactions.lock().await;

        if seen_transactions.contains(&tx_id) {
            log::warn!("Attempting to add duplicate transaction: {}", tx_id);
            return false;
        }
        if transactions.len() >= self.max_entries || seen_transactions.len() >= self.max_entries {
            log::warn!(
                "Mempool at capacity ({}), rejecting transaction",
                self.max_entries
            );
            return false;
        }

        seen_transactions.insert(tx_id.clone());
        transactions.insert(tx_id, transaction);
        log::debug!(
            "Transaction added to mempool. Total: {}",
            transactions.len()
        );
        true
    }

    /// Removes a transaction after it is included in a block.
    pub async fn remove_transaction(&self, tx_id: &str) {
        let mut transactions = self.transactions.lock().await;
        let mut seen_transactions = self.seen_transactions.lock().await;
        transactions.remove(tx_id);
        seen_transactions.remove(tx_id);
    }

    /// Returns a list of pending transactions for block inclusion.
    pub async fn get_pending_transactions(&self) -> Vec<ZKTransaction> {
        let transactions = self.transactions.lock().await;
        transactions.values().cloned().collect()
    }

    /// Checks if a transaction already exists in the mempool.
    pub async fn transaction_exists(&self, tx_id: &str) -> bool {
        let transactions = self.transactions.lock().await;
        transactions.contains_key(tx_id)
    }

    /// Clears expired transactions and their corresponding duplicate IDs.
    pub async fn clear_old_transactions(&self) {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let mut transactions = self.transactions.lock().await;
        transactions.retain(|_, tx| tx.timestamp.saturating_add(600) > now);
        let mut seen_transactions = self.seen_transactions.lock().await;
        seen_transactions.retain(|tx_id| transactions.contains_key(tx_id));
    }
}

impl ZKTransaction {
    /// Generates a transaction ID from its signed representation.
    pub fn get_hash(&self) -> String {
        hex::encode(Sha3_256::digest(&self.signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_crypto::tx_signer::{generate_tx_keypair, sign_tx_payload, tx_payload};

    fn mempool_with_capacity(max_entries: usize) -> Arc<Mempool> {
        Mempool::with_capacity(
            bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            Arc::new(Mempool::embedded_sender_public_key),
            max_entries,
        )
    }

    fn signed_transaction(receiver: &str, amount: u64, nonce: u64) -> ZKTransaction {
        let (public_key, secret_key) = generate_tx_keypair();
        let sender = bleep_crypto::derive_account_address(&public_key);
        let chain_id = bleep_crypto::DEFAULT_CHAIN_ID.to_string();
        let timestamp = chrono::Utc::now().timestamp().max(0) as u64;
        let payload = tx_payload(&chain_id, &sender, receiver, amount, timestamp, nonce);
        let signature = sign_tx_payload(&payload, &secret_key).expect("sign transaction");
        let mut signed_bytes = public_key;
        signed_bytes.extend_from_slice(&signature);
        ZKTransaction {
            chain_id,
            sender,
            receiver: receiver.to_string(),
            amount,
            timestamp,
            nonce,
            signature: signed_bytes,
        }
    }

    #[tokio::test]
    async fn mempool_rejects_forged_signature() {
        let mempool = mempool_with_capacity(10);
        let mut transaction = signed_transaction("recipient", 10, 0);
        *transaction.signature.last_mut().unwrap() ^= 1;
        assert!(!mempool.add_transaction(transaction).await);
    }

    #[tokio::test]
    async fn mempool_rejects_wrong_chain_id() {
        let mempool = mempool_with_capacity(10);
        let mut transaction = signed_transaction("recipient", 10, 0);
        transaction.chain_id = "BLEEP-Mainnet".into();
        assert!(!mempool.add_transaction(transaction).await);
    }

    #[tokio::test]
    async fn mempool_seen_set_is_bounded() {
        let mempool = mempool_with_capacity(2);
        assert!(
            mempool
                .add_transaction(signed_transaction("recipient", 10, 0))
                .await
        );
        assert!(
            mempool
                .add_transaction(signed_transaction("recipient", 11, 1))
                .await
        );
        assert!(
            !mempool
                .add_transaction(signed_transaction("recipient", 12, 2))
                .await
        );
        assert_eq!(mempool.transactions.lock().await.len(), 2);
        assert_eq!(mempool.seen_transactions.lock().await.len(), 2);
    }
}
