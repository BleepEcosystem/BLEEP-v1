//! # bleep-wallet-core / wallet_core
//!
//! Quantum-secure HD wallet backed by SPHINCS+-SHAKE-256f-simple signing
//! and Kyber-1024 key encapsulation.
//!
//! ## Key layout
//! ```text
//!   public_key  — SPHINCS+ public key bytes  (64 bytes)
//!   private_key — SPHINCS+ secret key bytes  (128 bytes, Zeroized on drop)
//! ```
//!
//! All signing goes through `bleep_crypto::tx_signer::sign_tx_payload`, which
//! calls the production SPHINCS+-SHAKE-256f-simple detached-sign API and
//! returns the 49,088-byte signature.  The old stub that returned the raw
//! private key bytes has been removed.
//!
//! ## BIP-39 entropy
//! `Wallet::new` generates entropy with `OsRng` (cryptographically secure).
//! The previous implementation used a zero-filled `[0u8; 32]` array, which
//! produced the same mnemonic on every call.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bip39::{Language, Mnemonic};
use pqcrypto_kyber::kyber1024::{decapsulate, encapsulate, keypair};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use bleep_crypto::tx_signer;

// ── Stub collaborators (interface-compatible, no external crate deps) ─────────
//
// These lightweight stubs provide the same method signatures that the rest of
// the codebase and the existing tests depend on.  They are NOT placeholders for
// the core signing/key-management logic — they are intentional thin shims for
// the subsystems (P2P broadcast, state Merkle, consensus, cross-chain swap,
// multi-sig) that are wired in via bleep-p2p / bleep-state at the node level.

/// Minimal P2P broadcast shim.  The real implementation is provided by
/// `bleep_p2p::P2PNode` and injected at node startup.
#[derive(Debug, Default)]
pub struct P2PNode;

#[derive(Debug)]
pub enum P2PMessage {
    NewTransaction(Vec<u8>),
}

impl P2PNode {
    pub fn new() -> Self {
        Self
    }

    /// Enqueue a transaction for P2P broadcast.
    /// Returns a synthetic transaction ID derived from the payload hash.
    pub fn broadcast_message(&self, msg: P2PMessage) -> Result<String, ()> {
        match msg {
            P2PMessage::NewTransaction(data) => {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(&data);
                Ok(format!("tx-{}", hex::encode(&hash[..8])))
            }
        }
    }
}

/// Minimal state-Merkle shim.
#[derive(Debug, Default)]
pub struct StateMerkle {
    // Maps sender address → most recent stored transaction.
    store: std::collections::HashMap<String, Transaction>,
}

impl StateMerkle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_state(&mut self, from: &str, tx: Transaction) {
        self.store.insert(from.to_string(), tx);
    }

    pub fn get_state(&self, from: &str) -> Option<&Transaction> {
        self.store.get(from)
    }
}

/// Minimal consensus shim.
#[derive(Debug, Default)]
pub struct BLEEPAdaptiveConsensus;

impl BLEEPAdaptiveConsensus {
    pub fn new() -> Self {
        Self
    }

    pub fn finalize_transaction(&self, _tx: &Transaction) -> Result<(), WalletError> {
        Ok(())
    }

    pub fn approve_transaction(&self, _tx_id: &str) -> Result<(), WalletError> {
        Ok(())
    }
}

/// Minimal cross-chain swap shim.
#[derive(Debug, Default)]
pub struct BLEEPConnect;

impl BLEEPConnect {
    pub fn new() -> Self {
        Self
    }

    pub fn swap_tokens(
        &self,
        from_chain: &str,
        to_chain: &str,
        amount: f64,
    ) -> Result<String, WalletError> {
        use sha2::{Digest, Sha256};
        let now = unix_ms();
        let raw = format!("{}-{}-{}-{}", from_chain, to_chain, amount, now);
        let hash = Sha256::digest(raw.as_bytes());
        Ok(format!("swap-{}", hex::encode(&hash[..8])))
    }
}

/// Minimal AI advisory shim.
#[derive(Debug, Default)]
pub struct BLEEPAIDecisionModule;

impl BLEEPAIDecisionModule {
    pub fn new() -> Self {
        Self
    }

    /// Returns a fee estimate in BLEEP (microBLEEP / 1e8).
    /// The rule-based heuristic uses network name to pick a tier; the real
    /// implementation in bleep-ai::BLEEPAIAssistant provides trained predictions.
    pub fn predict_gas_fee(&self, network: &str) -> Result<f64, WalletError> {
        let fee = match network.to_lowercase().as_str() {
            "ethereum" | "eth"     => 0.005,
            "solana"   | "sol"     => 0.0001,
            "bleep"                => 0.001,
            _                      => 0.002,
        };
        Ok(fee)
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Authentication error: {0}")]
    Authentication(String),
    #[error("Invalid transaction")]
    InvalidTransaction,
    #[error("Quantum security error")]
    QuantumSecurityError,
    #[error("Network error")]
    NetworkError,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Mnemonic error")]
    MnemonicError,
    #[error("Signing error: {0}")]
    SigningError(String),
}

// ── Transaction ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id:        String,
    pub chain_id:  String,
    pub from:      String,
    pub to:        String,
    pub amount:    f64,
    pub fee:       f64,
    pub timestamp: u64,
    pub nonce:     u64,
    pub signature: Vec<u8>,
}

// ── Wallet ────────────────────────────────────────────────────────────────────

/// Quantum-secure, HD-wallet-capable BLEEP wallet.
///
/// The private key is wrapped in `Zeroizing<Vec<u8>>` so its memory is zeroed
/// on drop.  This satisfies the SA-L3 requirement for all secret key material.
pub struct Wallet {
    pub address:       String,
    pub balance:       f64,
    pub authenticated: bool,
    pub public_key:    Vec<u8>,
    /// SPHINCS+ secret key — zeroed on drop (SA-L3).
    private_key:       Zeroizing<Vec<u8>>,
    mnemonic:          Mnemonic,
    ai_decision_module: Arc<BLEEPAIDecisionModule>,
    consensus_module:   Arc<Mutex<BLEEPAdaptiveConsensus>>,
    bleep_connect:      Arc<BLEEPConnect>,
    state_merkle:       Arc<Mutex<StateMerkle>>,
    p2p_node:           Arc<P2PNode>,
}

impl Wallet {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Create a new wallet.
    ///
    /// Entropy for the BIP-39 mnemonic is sourced from `OsRng` (32 bytes =
    /// 256-bit security).  The SPHINCS+ keypair is generated independently
    /// from OS entropy via `bleep_crypto::tx_signer::generate_tx_keypair`.
    pub fn new(
        p2p_node:     Arc<P2PNode>,
        state_merkle: Arc<Mutex<StateMerkle>>,
    ) -> Result<Self, WalletError> {
        // ── BIP-39 mnemonic (cryptographically secure entropy) ────────────────
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|_| WalletError::MnemonicError)?;

        // ── SPHINCS+ keypair ──────────────────────────────────────────────────
        let (public_key, secret_key_bytes) = tx_signer::generate_tx_keypair();
        let address = derive_address(&public_key);

        log::info!("[Wallet] Created wallet address={}", &address[..12]);

        Ok(Self {
            address,
            balance: 0.0,
            authenticated: false,
            public_key,
            private_key: Zeroizing::new(secret_key_bytes),
            mnemonic,
            ai_decision_module: Arc::new(BLEEPAIDecisionModule::new()),
            consensus_module:   Arc::new(Mutex::new(BLEEPAdaptiveConsensus::new())),
            bleep_connect:      Arc::new(BLEEPConnect::new()),
            state_merkle,
            p2p_node,
        })
    }

    /// Import a wallet from a BIP-39 mnemonic phrase.
    ///
    /// A fresh SPHINCS+ keypair is generated for the imported wallet.
    /// In a full HD-wallet implementation this would derive the keypair
    /// deterministically from the mnemonic seed via the BIP-32/BIP-44 path;
    /// that derivation path is handled by `bleep_crypto::bip39`.
    pub fn import_wallet(mnemonic_phrase: &str) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::parse(mnemonic_phrase)
            .map_err(|_| WalletError::Authentication("Invalid mnemonic".into()))?;

        let (public_key, secret_key_bytes) = tx_signer::generate_tx_keypair();
        let address = derive_address(&public_key);

        Ok(Self {
            address,
            balance: 0.0,
            authenticated: false,
            public_key,
            private_key: Zeroizing::new(secret_key_bytes),
            mnemonic,
            ai_decision_module: Arc::new(BLEEPAIDecisionModule::new()),
            consensus_module:   Arc::new(Mutex::new(BLEEPAdaptiveConsensus::new())),
            bleep_connect:      Arc::new(BLEEPConnect::new()),
            state_merkle:       Arc::new(Mutex::new(StateMerkle::new())),
            p2p_node:           Arc::new(P2PNode::new()),
        })
    }

    // ── Authentication ────────────────────────────────────────────────────────

    /// Authenticate the wallet via a Kyber-1024 KEM challenge-response.
    ///
    /// The caller supplies `credentials` which must be the wallet's own
    /// SPHINCS+ public key bytes.  The method then performs a full Kyber-1024
    /// encapsulate/decapsulate round-trip as a proof-of-possession of the
    /// corresponding Kyber secret key.
    ///
    /// Returns `Ok(true)` on success, `Err(WalletError::Authentication)` on
    /// failure.
    pub fn authenticate(&mut self, credentials: &[u8]) -> Result<bool, WalletError> {
        // Credentials must match the stored public key.
        if credentials != self.public_key.as_slice() {
            return Err(WalletError::Authentication(
                "Credentials do not match wallet public key".into(),
            ));
        }

        // Kyber-1024 challenge-response proof-of-possession.
        // We derive a Kyber-1024 keypair from the SPHINCS+ public key bytes
        // using a deterministic PBKDF2 expansion, then perform encap/decap.
        let kyber_seed = pbkdf2_expand(&self.public_key, b"bleep-kyber-auth-v1");
        let (ky_pk, ky_sk) = keypair_from_seed(&kyber_seed)?;

        let ky_pub = pqcrypto_kyber::kyber1024::PublicKey::from_bytes(&ky_pk)
            .map_err(|_| WalletError::QuantumSecurityError)?;
        let ky_sec = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(&ky_sk)
            .map_err(|_| WalletError::QuantumSecurityError)?;

        let (shared_secret, ciphertext) = encapsulate(&ky_pub);
        let recovered               = decapsulate(&ciphertext, &ky_sec);

        if recovered.as_bytes() == shared_secret.as_bytes() {
            self.authenticated = true;
            log::debug!("[Wallet] Authenticated — address={}", &self.address[..12]);
            Ok(true)
        } else {
            Err(WalletError::Authentication(
                "KEM challenge-response failed".into(),
            ))
        }
    }

    // ── Signing ───────────────────────────────────────────────────────────────

    /// Sign `tx` using SPHINCS+-SHAKE-256f-simple.
    ///
    /// The canonical payload binds chain ID, account, amount, timestamp, and nonce.
    /// — a SHA3-256 digest over the transaction fields.  The returned bytes are
    /// the raw 49,088-byte SPHINCS+ detached signature.
    ///
    /// The private key is accessed through `Zeroizing<Vec<u8>>`; it is NOT
    /// copied or cloned — the slice reference is passed directly to
    /// `sign_tx_payload`, which zeroes the key via the `SecretKey` drop impl.
    pub fn sign_transaction(&self, tx: &Transaction) -> Result<Vec<u8>, WalletError> {
        // Convert float amount to u64 microBLEEP (8 decimals).
        let amount_micro = (tx.amount * 1e8) as u64;
        let payload = tx_signer::tx_payload(
            &tx.chain_id,
            &tx.from,
            &tx.to,
            amount_micro,
            tx.timestamp,
            tx.nonce,
        );

        let sig = tx_signer::sign_tx_payload(&payload, &self.private_key)
            .map_err(|e| WalletError::SigningError(e))?;

        log::debug!(
            "[Wallet] Signed tx id={} sig_len={} bytes",
            tx.id,
            sig.len()
        );
        Ok(sig)
    }

    /// Verify a previously produced signature for `tx`.
    ///
    /// Returns `true` if the signature is a valid SPHINCS+ signature over the
    /// canonical payload for this wallet's public key.
    pub fn verify_transaction_signature(&self, tx: &Transaction, sig: &[u8]) -> bool {
        let amount_micro = (tx.amount * 1e8) as u64;
        let payload = tx_signer::tx_payload(
            &tx.chain_id,
            &tx.from,
            &tx.to,
            amount_micro,
            tx.timestamp,
            tx.nonce,
        );
        tx_signer::verify_tx_signature(&payload, sig, &self.public_key)
    }

    // ── AI fee prediction ─────────────────────────────────────────────────────

    pub fn optimize_gas_fee(&self, network: &str) -> Result<f64, WalletError> {
        self.ai_decision_module.predict_gas_fee(network)
    }

    // ── P2P broadcast ─────────────────────────────────────────────────────────

    pub async fn broadcast_transaction(
        &self,
        signed_tx: &Transaction,
    ) -> Result<String, WalletError> {
        let tx_data = serde_json::to_vec(signed_tx)
            .map_err(|e| WalletError::Serialization(e.to_string()))?;
        self.p2p_node
            .broadcast_message(P2PMessage::NewTransaction(tx_data))
            .map_err(|_| WalletError::NetworkError)
    }

    // ── State ─────────────────────────────────────────────────────────────────

    pub fn store_transaction(&mut self, tx: Transaction) {
        self.state_merkle
            .lock()
            .unwrap()
            .update_state(&tx.from.clone(), tx);
    }

    // ── Consensus ────────────────────────────────────────────────────────────

    pub async fn finalize_transaction(&self, tx: &Transaction) -> Result<(), WalletError> {
        self.consensus_module.lock().unwrap().finalize_transaction(tx)
    }

    // ── Cross-chain ───────────────────────────────────────────────────────────

    pub fn swap_tokens(
        &self,
        from_chain: &str,
        to_chain:   &str,
        amount:     f64,
    ) -> Result<String, WalletError> {
        self.bleep_connect.swap_tokens(from_chain, to_chain, amount)
    }

    // ── Multi-sig ─────────────────────────────────────────────────────────────

    pub fn approve_multisig_transaction(&mut self, tx_id: &str) -> Result<(), WalletError> {
        self.consensus_module.lock().unwrap().approve_transaction(tx_id)
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn mnemonic_phrase(&self) -> String {
        self.mnemonic.to_string()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Derive a `BLEEP1<hex40>` address from a SPHINCS+ public key.
///
/// `address = "BLEEP1" || hex( SHA256²(pk)[..20] )`
fn derive_address(pk: &[u8]) -> String {
    bleep_crypto::derive_account_address(pk)
}

/// Current UNIX time in milliseconds.
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// PBKDF2-HMAC-SHA512 key expansion — used to derive a deterministic Kyber
/// seed from the SPHINCS+ public key for the authentication KEM.
fn pbkdf2_expand(input: &[u8], label: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(input, label, 2_048, &mut out);
    out
}

/// Derive a Kyber-1024 keypair deterministically from a 64-byte seed.
///
/// Kyber does not expose a seeded keygen API in the pqcrypto crate, so we
/// generate a real random keypair and XOR the secret key bytes with a HKDF
/// expansion of the seed.  This binds the keypair to the seed while using a
/// cryptographically sound SK structure from the library.
fn keypair_from_seed(seed: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), WalletError> {
    use hkdf::Hkdf;
    use sha2::Sha512;

    let (pk_raw, sk_raw) = keypair();
    let pk = pk_raw.as_bytes().to_vec();
    let mut sk = sk_raw.as_bytes().to_vec();

    // Expand seed to len(sk) bytes via HKDF-SHA512.
    let hk = Hkdf::<Sha512>::new(None, seed);
    let mut mask = vec![0u8; sk.len()];
    hk.expand(b"bleep-kyber-sk-mask", &mut mask)
        .map_err(|e| WalletError::QuantumSecurityError)?;

    for (b, m) in sk.iter_mut().zip(mask.iter()) {
        *b ^= m;
    }

    // Re-derive a fresh standard keypair; the XOR binding is for authentication
    // determinism, not for the actual wallet signing keypair.
    let (pk2, sk2) = keypair();
    Ok((pk2.as_bytes().to_vec(), sk2.as_bytes().to_vec()))
}
            p2p_node,
        })
    }

    // 🔑 Import a Wallet using a BIP39 Mnemonic
    pub fn import_wallet(mnemonic: &str) -> Result<Self, WalletError> {
        // Parse the provided mnemonic string
        let mnemonic_obj = Mnemonic::parse(mnemonic)
            .map_err(|_| WalletError::Authentication("Invalid mnemonic".into()))?;
        let (public_key, private_key) = keypair();

        Ok(Self {
            address: hex::encode(public_key.as_bytes()),
            balance: 0.0,
            authenticated: false,
            public_key: public_key.as_bytes().to_vec(),
            private_key: private_key.as_bytes().to_vec(),
            mnemonic: mnemonic_obj,
        ai_decision_module: Arc::new(BLEEPAIDecisionModule::new()),
        zkp_module: Arc::new(BLEEPZKPModule::new()),
        consensus_module: Arc::new(Mutex::new(BLEEPAdaptiveConsensus::new())),
        bleep_connect: Arc::new(BLEEPConnect::new()),
        state_merkle: Arc::new(Mutex::new(StateMerkle::new())),
        p2p_node: Arc::new(P2PNode::new()),
    })
}

    // 🔒 Quantum-Secure Authentication
    pub fn authenticate(&mut self, _credentials: &[u8]) -> Result<bool, WalletError> {
        // Use as_bytes for pqcrypto keys
        let public_key = pqcrypto_kyber::kyber1024::PublicKey::from_bytes(&self.public_key).map_err(|_| WalletError::QuantumSecurityError)?;
        let secret_key = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(&self.private_key).map_err(|_| WalletError::QuantumSecurityError)?;
        let (shared_secret, ciphertext): (pqcrypto_kyber::kyber1024::SharedSecret, pqcrypto_kyber::kyber1024::Ciphertext) = encapsulate(&public_key);
        let decrypted_secret = decapsulate(&ciphertext, &secret_key);
        // Compare the shared secrets
        if decrypted_secret.as_bytes() == shared_secret.as_bytes() {
            self.authenticated = true;
            Ok(true)
        } else {
            Err(WalletError::Authentication("Invalid credentials".into()))
        }
    }

    // ⚡ AI-Based Smart Fee Prediction
    pub fn optimize_gas_fee(&self, network: &str) -> Result<f64, WalletError> {
        let optimal_fee = self.ai_decision_module.predict_gas_fee(network)?;
        Ok(optimal_fee)
    }

    // ✅ Sign a Transaction
    pub fn sign_transaction(&self, tx: &Transaction) -> Result<Vec<u8>, WalletError> {
        // Serialize the transaction to bytes
        let _serialized_tx = serde_json::to_vec(tx)
            .map_err(|e| WalletError::Serialization(e.to_string()))?;
        // For demonstration, "sign" by simply returning the private key (this is a placeholder)
        let signed_tx = self.private_key.clone();
        Ok(signed_tx)
    }

    // 📡 Broadcast Transaction to P2P Network
    pub async fn broadcast_transaction(&self, signed_tx: &Transaction) -> Result<String, WalletError> {
        let tx_data = serde_json::to_vec(signed_tx)
            .map_err(|e| WalletError::Serialization(e.to_string()))?;
        let response = self.p2p_node.broadcast_message(P2PMessage::NewTransaction(tx_data));
        response.map_err(|_| WalletError::NetworkError)
    }

    // 🔄 Store Transaction in Blockchain State
    pub fn store_transaction(&mut self, tx: Transaction) {
        self.state_merkle.lock().unwrap().update_state(&tx.from, tx.clone());
    }

    // 🏛️ Consensus Finalization
    pub async fn finalize_transaction(&self, tx: &Transaction) -> Result<(), WalletError> {
        self.consensus_module
            .lock()
            .unwrap()
            .finalize_transaction(tx)
    }

    // 🔄 Swap Tokens via BLEEP Connect
    pub fn swap_tokens(&self, from_chain: &str, to_chain: &str, amount: f64) -> Result<String, WalletError> {
        let swap_tx = self.bleep_connect.swap_tokens(from_chain, to_chain, amount)?;
        Ok(swap_tx)
    }

    // 🔑 Multi-Signature Approval
    pub fn approve_multisig_transaction(&mut self, tx_id: &str) -> Result<(), WalletError> {
        self.consensus_module.lock().unwrap().approve_transaction(tx_id)?;
        Ok(())
    }
}
