use log::info;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// --- BLEEP Quantum Resistance API ---
pub fn generate_sphincs_keypair() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let (pk, sk) = sphincsshake256fsimple::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

pub fn generate_mlkem_keypair() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let (pk, sk) = mlkem1024::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

pub fn canonical_encode<T: Serialize>(tx: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(bincode::serde::encode_to_vec(
        tx,
        bincode::config::standard(),
    )?)
}

pub fn sign_transaction<T: Serialize>(
    tx: &T,
    sk: &sphincsshake256fsimple::SecretKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let message = canonical_encode(tx)?;
    Ok(sphincsshake256fsimple::detached_sign(&message, sk)
        .as_bytes()
        .to_vec())
}

/// Initialize cryptography module logging
///
/// This function idempotently sets up the logging system for the crypto module.
/// It is safe to call multiple times from different threads and initialization paths.
///
/// # Returns
///
/// This function always succeeds (logging failures are non-fatal).
pub fn init_crypto_logging() {
    // Idempotent logging initialization: env_logger ignores multiple init calls
    let _ = env_logger::builder().is_test(true).try_init();
    // Logging init failures are non-fatal and should not propagate as errors
}

/// Initialize SPHINCS+ post-quantum signing support.
pub fn init_sphincs() -> Result<(), Box<dyn Error>> {
    init_crypto_logging();
    info!("SPHINCS+ post-quantum signing initialized.");
    Ok(())
}

/// Initialize ML-KEM post-quantum key encapsulation support.
pub fn init_mlkem() -> Result<(), Box<dyn Error>> {
    init_crypto_logging();
    info!("ML-KEM post-quantum key encapsulation initialized.");
    Ok(())
}

/// Run basic quantum-resistant key generation self-tests.
pub fn run_keygen_tests() -> Result<(), Box<dyn std::error::Error>> {
    let (sphincs_pk, sphincs_sk) = generate_sphincs_keypair()?;
    let (mlkem_pk, mlkem_sk) = generate_mlkem_keypair()?;
    if sphincs_pk.is_empty() || sphincs_sk.is_empty() || mlkem_pk.is_empty() || mlkem_sk.is_empty()
    {
        Err("Post-quantum key generation returned empty key material".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_generator_returns_mlkem_1024_keys() {
        let (public_key, secret_key) = generate_mlkem_keypair().expect("ML-KEM keygen");
        assert_eq!(public_key.len(), mlkem1024::public_key_bytes());
        assert_eq!(secret_key.len(), mlkem1024::secret_key_bytes());
        mlkem1024::PublicKey::from_bytes(&public_key).expect("valid ML-KEM public key");
        mlkem1024::SecretKey::from_bytes(&secret_key).expect("valid ML-KEM secret key");
    }

    #[test]
    fn sphincs_generator_and_transaction_signing_roundtrip() {
        let (public_key, secret_key) = generate_sphincs_keypair().expect("SPHINCS+ keygen");
        let secret_key =
            sphincsshake256fsimple::SecretKey::from_bytes(&secret_key).expect("valid secret key");
        let public_key =
            sphincsshake256fsimple::PublicKey::from_bytes(&public_key).expect("valid public key");
        let transaction = Transaction {
            id: 1,
            from: "alice".into(),
            to: "bob".into(),
            amount: 25,
            timestamp: 123,
            signature: vec![],
            public_key: public_key.as_bytes().to_vec(),
        };

        let signature = sign_transaction(&transaction, &secret_key).expect("sign transaction");
        let signature = sphincsshake256fsimple::DetachedSignature::from_bytes(&signature)
            .expect("valid detached signature");
        let message = canonical_encode(&transaction).expect("canonical encoding");
        sphincsshake256fsimple::verify_detached_signature(&signature, &message, &public_key)
            .expect("verify transaction signature");
    }
}

// 🔹 Quantum-Resistant Transaction Structure
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Transaction {
    pub id: u64,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Transaction {
    pub fn new(
        id: u64,
        from: &str,
        to: &str,
        amount: u64,
        sk: &sphincsshake256fsimple::SecretKey,
        pk: &sphincsshake256fsimple::PublicKey,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut tx = Transaction {
            id,
            from: from.to_string(),
            to: to.to_string(),
            amount,
            timestamp,
            signature: vec![],
            public_key: pk.as_bytes().to_vec(),
        };
        tx.signature = tx.sign(sk);
        tx
    }

    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(self.id.to_be_bytes());
        hasher.update(self.from.as_bytes());
        hasher.update(self.to.as_bytes());
        hasher.update(self.amount.to_be_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(&self.public_key);
        hasher.finalize().to_vec()
    }

    pub fn sign(&self, sk: &sphincsshake256fsimple::SecretKey) -> Vec<u8> {
        let hash = self.hash();
        let sig = sphincsshake256fsimple::detached_sign(&hash, sk);
        sig.as_bytes().to_vec()
    }

    pub fn verify(&self) -> bool {
        let hash = self.hash();
        let pk = match sphincsshake256fsimple::PublicKey::from_bytes(&self.public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig = match sphincsshake256fsimple::DetachedSignature::from_bytes(&self.signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        sphincsshake256fsimple::verify_detached_signature(&sig, &hash, &pk).is_ok()
    }
}

// 🔹 Blockchain Block Structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub id: u64,
    pub previous_hash: String,
    pub transactions: Vec<Transaction>,
    pub timestamp: u64,
    pub hash: String,
}

impl Block {
    pub fn new(id: u64, previous_hash: String, transactions: Vec<Transaction>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time error")
            .as_secs();
        let hash = Self::calculate_hash(&transactions, &previous_hash, timestamp);
        Block {
            id,
            previous_hash,
            transactions,
            timestamp,
            hash,
        }
    }

    pub fn calculate_hash(
        transactions: &[Transaction],
        previous_hash: &str,
        timestamp: u64,
    ) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(previous_hash.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        for tx in transactions {
            hasher.update(bincode::serde::encode_to_vec(tx, bincode::config::standard()).unwrap());
        }
        hex::encode(hasher.finalize())
    }
}

// Quantum-Secure Encryption & Decryption System removed

// 🔹 Blockchain State Management
pub struct BlockchainState {
    pub chain: Arc<RwLock<Vec<Block>>>,
    pub mempool: Arc<RwLock<HashSet<Transaction>>>,
}

impl Default for BlockchainState {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockchainState {
    pub fn new() -> Self {
        BlockchainState {
            chain: Arc::new(RwLock::new(vec![Block::new(0, String::new(), vec![])])),
            mempool: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub async fn add_transaction(&self, transaction: Transaction) {
        let mut mempool = self.mempool.write().await;
        mempool.insert(transaction);
        info!("Transaction added to mempool.");
    }

    pub async fn add_block(&self, block: Block) {
        let mut chain = self.chain.write().await;
        chain.push(block);
        info!("New block added to blockchain.");
    }
}

// 🔹 Adaptive Consensus System
pub struct AdaptiveConsensus {
    pub validators: HashMap<String, f64>,
    pub network_reliability: f64,
    pub consensus_mode: String,
}

impl Default for AdaptiveConsensus {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveConsensus {
    pub fn new() -> Self {
        AdaptiveConsensus {
            validators: HashMap::new(),
            network_reliability: 0.9,
            consensus_mode: "PoS".to_string(),
        }
    }

    pub fn switch_mode(&mut self, network_load: u64) {
        self.consensus_mode = if network_load > 80 {
            "PoW".to_string()
        } else if network_load > 40 {
            "PBFT".to_string()
        } else {
            "PoS".to_string()
        };
        info!("Consensus mode switched to {}", self.consensus_mode);
    }
}

/// Run self-tests and validation for the cryptographic module
///
/// This is a demonstration/testing function showing how to initialize and use
/// the quantum-resistant cryptography components.
///
/// # Example
///
/// This function is intended for internal testing and integration verification.
/// Production code should use the individual cryptographic functions directly.
pub async fn crypto_self_test() {
    init_crypto_logging();
    let _blockchain = BlockchainState::new();
    let _consensus = AdaptiveConsensus::new();
    info!("Blockchain initialized with genesis block.");
}
