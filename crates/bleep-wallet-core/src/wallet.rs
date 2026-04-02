//! # Wallet
//!
//! AES-256-GCM encryption-at-rest for the signing key.
//!
//! ## Key storage model
//! ```text
//! EncryptedWallet.signing_key  ← AES-256-GCM ciphertext of SPHINCS+ SK
//!                                Layout: [nonce(12) || ciphertext || tag(16)]
//!
//! Encryption key = SHA3-256(password_utf8 || address_utf8)   (32 bytes)
//! ```
//!
//! `lock(sk, password)` encrypts; `unlock(password)` decrypts.
//! Wallets without a signing key (legacy) remain functional for balance
//! queries; only signing is gated behind `can_sign()`.

use std::error::Error;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;

// ─── EncryptedWallet ──────────────────────────────────────────────────────────

/// One wallet record persisted to disk.
///
/// `falcon_keys`  — SPHINCS+ public key (address derivation).
/// `kyber_keys`   — Kyber KEM public key.
/// `signing_key`  — AES-256-GCM encrypted SPHINCS+ secret key, or empty if
///                  no signing key has been imported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// SPHINCS+ public key bytes.
    pub falcon_keys: Vec<u8>,
    /// Kyber KEM public key bytes.
    pub kyber_keys: Vec<u8>,
    /// AES-256-GCM ciphertext of the SPHINCS+ secret key.
    /// Layout: `nonce(12 bytes) || ciphertext || GCM-tag(16 bytes)`.
    /// Empty if no signing key is stored.
    #[serde(default)]
    pub signing_key: Vec<u8>,
    /// BLEEP1<hex40> address derived from `falcon_keys`.
    pub address: String,
    /// Human-readable label (optional).
    pub label: Option<String>,
}

impl EncryptedWallet {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create a wallet from a public key only (no signing capability).
    pub fn new(falcon_keys: Vec<u8>, kyber_keys: Vec<u8>) -> Self {
        let address = Self::derive_address(&falcon_keys);
        Self {
            falcon_keys,
            kyber_keys,
            signing_key: vec![],
            address,
            label: None,
        }
    }

    /// Create a wallet and immediately encrypt the secret key.
    ///
    /// `password` — passphrase used to derive the AES encryption key.
    /// Use an empty string for no password (still encrypted, but trivially).
    pub fn with_signing_key_encrypted(
        falcon_pk: Vec<u8>,
        falcon_sk: &[u8],
        kyber_keys: Vec<u8>,
        password: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let address = Self::derive_address(&falcon_pk);
        let signing_key = encrypt_key(falcon_sk, password, &address)?;
        Ok(Self {
            falcon_keys: falcon_pk,
            kyber_keys,
            signing_key,
            address,
            label: None,
        })
    }

    /// Legacy constructor — stores the SK in plaintext.
    /// Prefer `with_signing_key_encrypted` in new code.
    pub fn with_signing_key(falcon_pk: Vec<u8>, falcon_sk: Vec<u8>, kyber_keys: Vec<u8>) -> Self {
        let address = Self::derive_address(&falcon_pk);
        Self {
            falcon_keys: falcon_pk,
            kyber_keys,
            signing_key: falcon_sk,
            address,
            label: None,
        }
    }

    // ── Key encryption / decryption ───────────────────────────────────────────

    /// Encrypt and store `sk_bytes` as the wallet's signing key.
    ///
    /// Replaces any previously stored signing key ciphertext.
    pub fn lock(&mut self, sk_bytes: &[u8], password: &str) -> Result<(), Box<dyn Error>> {
        self.signing_key = encrypt_key(sk_bytes, password, &self.address)?;
        Ok(())
    }

    /// Decrypt and return the plaintext signing key bytes.
    ///
    /// Returns `Err` if no signing key is stored, if decryption fails
    /// (wrong password), or if the ciphertext is malformed.
    pub fn unlock(&self, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        if self.signing_key.is_empty() {
            return Err("No signing key stored in this wallet".into());
        }
        decrypt_key(&self.signing_key, password, &self.address)
    }

    // ── Address derivation ────────────────────────────────────────────────────

    /// `BLEEP1<hex40>` — SHA256²(pk) truncated to 20 bytes.
    pub fn derive_address(public_key: &[u8]) -> String {
        let first = Sha256::digest(public_key);
        let second = Sha256::digest(&first);
        format!("BLEEP1{}", hex::encode(&second[..20]))
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn pk_short(&self) -> String {
        hex::encode(&self.falcon_keys[..self.falcon_keys.len().min(8)])
    }

    /// Returns `true` if a (possibly encrypted) signing key is stored.
    pub fn can_sign(&self) -> bool {
        !self.signing_key.is_empty()
    }
}

// ── AES-256-GCM helpers ───────────────────────────────────────────────────────

/// Derive a 32-byte AES-256 key from a password + wallet address.
///
/// `key = SHA3-256(password_bytes || address_bytes)`
fn derive_aes_key(password: &str, address: &str) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(password.as_bytes());
    h.update(address.as_bytes());
    h.finalize().into()
}

/// Encrypt `plaintext` with AES-256-GCM.
///
/// Returns `nonce(12) || ciphertext || tag(16)`.
pub fn encrypt_key(
    plaintext: &[u8],
    password: &str,
    address: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let aes_key = derive_aes_key(password, address);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("AES-GCM encrypt failed: {}", e))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by `encrypt_key`.
///
/// Expects `nonce(12) || ciphertext || tag(16)` layout.
pub fn decrypt_key(blob: &[u8], password: &str, address: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if blob.len() < 12 + 16 {
        return Err(format!("Signing key blob too short: {} bytes (min 28)", blob.len()).into());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let aes_key = derive_aes_key(password, address);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "AES-GCM decryption failed — wrong password or corrupted key".into())
}

// ─── WalletManager ────────────────────────────────────────────────────────────

/// Manages a collection of wallets persisted as JSON.
///
/// Default path: `~/.bleep/wallets.json`
pub struct WalletManager {
    wallets: Vec<EncryptedWallet>,
    path: Option<PathBuf>,
}

impl WalletManager {
    pub fn load_or_create() -> Result<Self, Box<dyn Error>> {
        Self::load_or_create_at(Self::default_path())
    }

    pub fn load_or_create_at<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let wallets = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str::<Vec<EncryptedWallet>>(&raw).unwrap_or_default()
        } else {
            Vec::new()
        };
        log::info!(
            "WalletManager: loaded {} wallets from {:?}",
            wallets.len(),
            path
        );
        Ok(Self {
            wallets,
            path: Some(path),
        })
    }

    pub fn save_wallet(&mut self, wallet: EncryptedWallet) -> Result<(), Box<dyn Error>> {
        if self.wallets.iter().any(|w| w.address == wallet.address) {
            log::warn!("Wallet {} already exists, skipping", wallet.address);
            return Ok(());
        }
        self.wallets.push(wallet);
        self.persist()
    }

    pub fn list_wallets(&self) -> &[EncryptedWallet] {
        &self.wallets
    }

    pub fn find_by_address(&self, address: &str) -> Option<&EncryptedWallet> {
        self.wallets.iter().find(|w| w.address == address)
    }

    pub fn remove_wallet(&mut self, address: &str) -> Result<bool, Box<dyn Error>> {
        let before = self.wallets.len();
        self.wallets.retain(|w| w.address != address);
        if self.wallets.len() < before {
            self.persist()?;
        }
        Ok(self.wallets.len() < before)
    }

    fn persist(&self) -> Result<(), Box<dyn Error>> {
        if let Some(path) = &self.path {
            let json = serde_json::to_string_pretty(&self.wallets)?;
            std::fs::write(path, json)?;
        }
        Ok(())
    }

    fn default_path() -> PathBuf {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".bleep").join("wallets.json")
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let sk = b"super_secret_key_material_32bytes!!";
        let pw = "correct-horse-battery-staple";
        let addr = "BLEEP1deadbeef0000000000000000000000000000";
        let blob = encrypt_key(sk, pw, addr).unwrap();
        let out = decrypt_key(&blob, pw, addr).unwrap();
        assert_eq!(out, sk);
    }

    #[test]
    fn wrong_password_fails() {
        let sk = b"my_signing_key";
        let addr = "BLEEP1test";
        let blob = encrypt_key(sk, "right", addr).unwrap();
        assert!(decrypt_key(&blob, "wrong", addr).is_err());
    }

    #[test]
    fn nonce_is_random_so_blobs_differ() {
        let sk = b"same_key";
        let addr = "BLEEP1test";
        let b1 = encrypt_key(sk, "pw", addr).unwrap();
        let b2 = encrypt_key(sk, "pw", addr).unwrap();
        assert_ne!(b1, b2); // different nonces each call
    }

    #[test]
    fn wallet_lock_unlock() {
        let pk = vec![0xAAu8; 32];
        let sk = vec![0xBBu8; 32];
        let mut w = EncryptedWallet::new(pk.clone(), vec![]);
        w.lock(&sk, "password").unwrap();
        assert!(w.can_sign());
        let recovered = w.unlock("password").unwrap();
        assert_eq!(recovered, sk);
    }

    #[test]
    fn wallet_unlock_wrong_password() {
        let pk = vec![0xCCu8; 32];
        let sk = vec![0xDDu8; 32];
        let mut w = EncryptedWallet::new(pk, vec![]);
        w.lock(&sk, "secret").unwrap();
        assert!(w.unlock("wrong").is_err());
    }

    #[test]
    fn with_signing_key_encrypted_roundtrip() {
        let pk = vec![0x01u8; 32];
        let sk = vec![0x02u8; 64];
        let w =
            EncryptedWallet::with_signing_key_encrypted(pk, &sk, vec![], "my-password").unwrap();
        assert!(w.can_sign());
        assert_eq!(w.unlock("my-password").unwrap(), sk);
    }
}
