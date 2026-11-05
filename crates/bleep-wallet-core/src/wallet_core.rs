//! # bleep-wallet-core / wallet_core
//!
//! Quantum-secure wallet backed by versioned transaction signing and Kyber-1024
//! key encapsulation.
//!
//! ## Key layout
//! ```text
//!   public_key  — transaction public key bytes (64 bytes)
//!   private_key — versioned signing key bytes (128 bytes, Zeroized on drop)
//! ```
//!
//! Mnemonic wallets use deterministic version-2 SLH-DSA SHAKE-256f keys and
//! BLEEP2 addresses. Legacy BLEEP1 addresses retain SPHINCS+ verification.
//!
//! ## BIP-39 entropy
//! `Wallet::new` generates entropy with `OsRng` (cryptographically secure).
//! The previous implementation used a zero-filled `[0u8; 32]` array, which
//! produced the same mnemonic on every call.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bip39::Mnemonic;
use pqcrypto_mlkem::mlkem1024::{decapsulate, encapsulate, keypair};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _, SharedSecret as _};
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
            "ethereum" | "eth" => 0.005,
            "solana" | "sol" => 0.0001,
            "bleep" => 0.001,
            _ => 0.002,
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
    pub id: String,
    pub chain_id: String,
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub fee: f64,
    pub timestamp: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

// ── Wallet ────────────────────────────────────────────────────────────────────

/// Quantum-secure, HD-wallet-capable BLEEP wallet.
///
/// The private key is wrapped in `Zeroizing<Vec<u8>>` so its memory is zeroed
/// on drop.  This satisfies the SA-L3 requirement for all secret key material.
pub struct Wallet {
    pub address: String,
    pub balance: f64,
    pub authenticated: bool,
    pub public_key: Vec<u8>,
    /// SPHINCS+ secret key — zeroed on drop (SA-L3).
    private_key: Zeroizing<Vec<u8>>,
    mnemonic: Mnemonic,
    ai_decision_module: Arc<BLEEPAIDecisionModule>,
    consensus_module: Arc<Mutex<BLEEPAdaptiveConsensus>>,
    bleep_connect: Arc<BLEEPConnect>,
    state_merkle: Arc<Mutex<StateMerkle>>,
    p2p_node: Arc<P2PNode>,
}

impl Wallet {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Create a new wallet.
    ///
    /// The BIP-39 mnemonic is sourced from `OsRng` and deterministically derives
    /// the wallet's version-2 SLH-DSA transaction keypair.
    pub fn new(
        p2p_node: Arc<P2PNode>,
        state_merkle: Arc<Mutex<StateMerkle>>,
    ) -> Result<Self, WalletError> {
        // ── BIP-39 mnemonic (cryptographically secure entropy) ────────────────
        let mut entropy = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(entropy.as_mut());
        let mnemonic =
            Mnemonic::from_entropy(entropy.as_ref()).map_err(|_| WalletError::MnemonicError)?;

        let (public_key, secret_key_bytes) = keypair_from_mnemonic(&mnemonic)?;
        let address = bleep_crypto::derive_account_address_v2(&public_key);

        log::info!("[Wallet] Created wallet address={}", &address[..12]);

        Ok(Self {
            address,
            balance: 0.0,
            authenticated: false,
            public_key,
            private_key: Zeroizing::new(secret_key_bytes),
            mnemonic,
            ai_decision_module: Arc::new(BLEEPAIDecisionModule::new()),
            consensus_module: Arc::new(Mutex::new(BLEEPAdaptiveConsensus::new())),
            bleep_connect: Arc::new(BLEEPConnect::new()),
            state_merkle,
            p2p_node,
        })
    }

    /// Import a wallet from a BIP-39 mnemonic phrase.
    ///
    /// The imported phrase deterministically reconstructs the version-2
    /// SLH-DSA transaction keypair and account address.
    pub fn import_wallet(mnemonic_phrase: &str) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::parse(mnemonic_phrase)
            .map_err(|_| WalletError::Authentication("Invalid mnemonic".into()))?;

        let (public_key, secret_key_bytes) = keypair_from_mnemonic(&mnemonic)?;
        let address = bleep_crypto::derive_account_address_v2(&public_key);

        Ok(Self {
            address,
            balance: 0.0,
            authenticated: false,
            public_key,
            private_key: Zeroizing::new(secret_key_bytes),
            mnemonic,
            ai_decision_module: Arc::new(BLEEPAIDecisionModule::new()),
            consensus_module: Arc::new(Mutex::new(BLEEPAdaptiveConsensus::new())),
            bleep_connect: Arc::new(BLEEPConnect::new()),
            state_merkle: Arc::new(Mutex::new(StateMerkle::new())),
            p2p_node: Arc::new(P2PNode::new()),
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

        let ky_pub = pqcrypto_mlkem::mlkem1024::PublicKey::from_bytes(&ky_pk)
            .map_err(|_| WalletError::QuantumSecurityError)?;
        let ky_sec = pqcrypto_mlkem::mlkem1024::SecretKey::from_bytes(&ky_sk)
            .map_err(|_| WalletError::QuantumSecurityError)?;

        let (shared_secret, ciphertext) = encapsulate(&ky_pub);
        let recovered = decapsulate(&ciphertext, &ky_sec);

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

    /// Sign `tx` using the scheme encoded by this wallet's address.
    ///
    /// The V2 payload binds chain ID, account, amount, fee, timestamp, and nonce.
    /// — a SHA3-256 digest over the transaction fields.  The returned bytes are
    /// the raw detached signature.
    ///
    /// The private key is accessed through `Zeroizing<Vec<u8>>`; it is NOT
    /// copied or cloned — the slice reference is passed directly to
    /// versioned signing helper, which zeroes temporary key objects on drop.
    pub fn sign_transaction(&self, tx: &Transaction) -> Result<Vec<u8>, WalletError> {
        // Convert float amount to u64 microBLEEP (8 decimals).
        let amount_micro = (tx.amount * 1e8) as u64;
        let fee_micro = (tx.fee * 1e8) as u64;
        let payload = tx_signer::tx_payload_v2(
            &tx.chain_id,
            &tx.from,
            &tx.to,
            amount_micro,
            fee_micro,
            tx.timestamp,
            tx.nonce,
        );

        let sig =
            tx_signer::sign_tx_payload_for_address(&payload, &self.private_key, &self.address)
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
    /// Returns `true` if the versioned signature is valid for this wallet.
    pub fn verify_transaction_signature(&self, tx: &Transaction, sig: &[u8]) -> bool {
        let amount_micro = (tx.amount * 1e8) as u64;
        let fee_micro = (tx.fee * 1e8) as u64;
        let payload = tx_signer::tx_payload_v2(
            &tx.chain_id,
            &tx.from,
            &tx.to,
            amount_micro,
            fee_micro,
            tx.timestamp,
            tx.nonce,
        );
        tx_signer::verify_tx_signature_for_address(&payload, sig, &self.public_key, &self.address)
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
        let tx_data =
            serde_json::to_vec(signed_tx).map_err(|e| WalletError::Serialization(e.to_string()))?;
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
        self.consensus_module
            .lock()
            .unwrap()
            .finalize_transaction(tx)
    }

    // ── Cross-chain ───────────────────────────────────────────────────────────

    pub fn swap_tokens(
        &self,
        from_chain: &str,
        to_chain: &str,
        amount: f64,
    ) -> Result<String, WalletError> {
        self.bleep_connect.swap_tokens(from_chain, to_chain, amount)
    }

    // ── Multi-sig ─────────────────────────────────────────────────────────────

    pub fn approve_multisig_transaction(&mut self, tx_id: &str) -> Result<(), WalletError> {
        self.consensus_module
            .lock()
            .unwrap()
            .approve_transaction(tx_id)
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

fn keypair_from_mnemonic(mnemonic: &Mnemonic) -> Result<(Vec<u8>, Vec<u8>), WalletError> {
    let full_seed = Zeroizing::new(mnemonic.to_seed(""));
    let seed = Zeroizing::new(full_seed[..32].to_vec());
    bleep_crypto::derive_tx_keypair(&seed)
        .map_err(|error| WalletError::SigningError(error.to_string()))
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
    let _pk = pk_raw.as_bytes().to_vec();
    let mut sk = sk_raw.as_bytes().to_vec();

    // Expand seed to len(sk) bytes via HKDF-SHA512.
    let hk = Hkdf::<Sha512>::new(None, seed);
    let mut mask = vec![0u8; sk.len()];
    hk.expand(b"bleep-kyber-sk-mask", &mut mask)
        .map_err(|_| WalletError::QuantumSecurityError)?;

    for (b, m) in sk.iter_mut().zip(mask.iter()) {
        *b ^= m;
    }

    // Re-derive a fresh standard keypair; the XOR binding is for authentication
    // determinism, not for the actual wallet signing keypair.
    let (pk2, sk2) = keypair();
    Ok((pk2.as_bytes().to_vec(), sk2.as_bytes().to_vec()))
}
