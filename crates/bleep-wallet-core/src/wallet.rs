//! # Wallet
//!
//! Argon2id + AES-256-GCM encryption-at-rest for the signing key.
//!
//! ## Key storage model
//! ```text
//! EncryptedWallet.signing_key  ← AES-256-GCM ciphertext of SPHINCS+ SK
//!                                Layout: ["BWK2" || salt(16) || nonce(12) ||
//!                                         ciphertext || tag(16)]
//! ```
//!
//! `lock(sk, password)` encrypts; `unlock(password)` decrypts.
//! Wallets without a signing key (legacy) remain functional for balance
//! queries; only signing is gated behind `can_sign()`.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

const ENCRYPTED_KEY_MAGIC: &[u8; 4] = b"BWK2";
const ARGON2_SALT_LEN: usize = 16;
const AES_GCM_NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum KeyProtection {
    Argon2id,
    PlaintextDev,
    Legacy,
}

impl Default for KeyProtection {
    fn default() -> Self {
        Self::Legacy
    }
}

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
    /// Argon2id format: magic(4) || salt(16) || nonce(12) || ciphertext || tag(16).
    /// Empty if no signing key is stored.
    #[serde(default)]
    pub signing_key: Vec<u8>,
    /// How `signing_key` is protected. Missing values identify legacy wallet files.
    #[serde(default)]
    key_protection: KeyProtection,
    /// Persisted wallet balance as a decimal string.
    #[serde(default = "default_balance")]
    pub balance: String,
    /// BLEEP1<hex40> address derived from `falcon_keys`.
    pub address: String,
    /// Human-readable label (optional).
    pub label: Option<String>,
}

impl Drop for EncryptedWallet {
    fn drop(&mut self) {
        self.signing_key.zeroize();
    }
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
            key_protection: KeyProtection::Legacy,
            balance: default_balance(),
            address,
            label: None,
        }
    }

    /// Create a wallet and immediately encrypt the secret key.
    ///
    /// `password` must be non-empty and is processed with Argon2id.
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
            key_protection: KeyProtection::Argon2id,
            balance: default_balance(),
            address,
            label: None,
        })
    }

    /// Store a signing key in plaintext for explicitly enabled development networks only.
    pub fn with_signing_key_plaintext_dev(
        falcon_pk: Vec<u8>,
        falcon_sk: &[u8],
        kyber_keys: Vec<u8>,
    ) -> Result<Self, Box<dyn Error>> {
        if !plaintext_dev_mode_enabled() {
            return Err(
                "Plaintext wallet mode requires BLEEP_WALLET_PLAINTEXT_DEV=1 and a dev/test network"
                    .into(),
            );
        }
        let address = Self::derive_address(&falcon_pk);
        Ok(Self {
            falcon_keys: falcon_pk,
            kyber_keys,
            signing_key: falcon_sk.to_vec(),
            key_protection: KeyProtection::PlaintextDev,
            balance: default_balance(),
            address,
            label: None,
        })
    }

    // ── Key encryption / decryption ───────────────────────────────────────────

    /// Encrypt and store `sk_bytes` as the wallet's signing key.
    ///
    /// Replaces any previously stored signing key ciphertext.
    pub fn lock(&mut self, sk_bytes: &[u8], password: &str) -> Result<(), Box<dyn Error>> {
        let encrypted = encrypt_key(sk_bytes, password, &self.address)?;
        self.signing_key.zeroize();
        self.signing_key = encrypted;
        self.key_protection = KeyProtection::Argon2id;
        Ok(())
    }

    /// Decrypt and return the plaintext signing key bytes.
    ///
    /// Returns `Err` if no signing key is stored, if decryption fails
    /// (wrong password), or if the ciphertext is malformed.
    pub fn unlock(&self, password: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
        if self.signing_key.is_empty() {
            return Err("No signing key stored in this wallet".into());
        }
        match self.key_protection {
            KeyProtection::Argon2id => decrypt_key(&self.signing_key, password, &self.address),
            KeyProtection::PlaintextDev if plaintext_dev_mode_enabled() => {
                Ok(Zeroizing::new(self.signing_key.clone()))
            }
            KeyProtection::PlaintextDev => {
                Err("Plaintext wallet unlock is disabled outside explicit dev/test mode".into())
            }
            KeyProtection::Legacy => decrypt_legacy_key(&self.signing_key, password, &self.address),
        }
    }

    // ── Address derivation ────────────────────────────────────────────────────

    /// Derive the canonical BLEEP account address from its SPHINCS+ key.
    pub fn derive_address(public_key: &[u8]) -> String {
        bleep_crypto::derive_account_address(public_key)
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

    pub fn is_plaintext_dev(&self) -> bool {
        self.key_protection == KeyProtection::PlaintextDev
    }
}

pub fn plaintext_dev_mode_enabled() -> bool {
    let enabled = std::env::var("BLEEP_WALLET_PLAINTEXT_DEV")
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true"))
        .unwrap_or(false);
    let network = std::env::var("BLEEP_NETWORK_MODE").unwrap_or_default();
    enabled && is_dev_or_test_network(&network)
}

fn is_dev_or_test_network(network: &str) -> bool {
    matches!(
        network.trim().to_ascii_lowercase().as_str(),
        "dev" | "development" | "test" | "testnet" | "pretestnet"
    )
}

/// Derive an AES-256 key with Argon2id using a fresh per-wallet salt.
fn derive_aes_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
    if password.is_empty() {
        return Err("Wallet password must not be empty".into());
    }
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(key)
}

/// The pre-Argon2 key derivation is retained only for unlocking legacy files.
fn derive_legacy_aes_key(password: &str, address: &str) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(password.as_bytes());
    h.update(address.as_bytes());
    Zeroizing::new(h.finalize().into())
}

/// Encrypt `plaintext` with AES-256-GCM.
///
/// Returns `nonce(12) || ciphertext || tag(16)`.
pub fn encrypt_key(
    plaintext: &[u8],
    password: &str,
    address: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if password.is_empty() {
        return Err("Wallet password must not be empty".into());
    }
    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let aes_key = derive_aes_key(password, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key.as_ref()));
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: address.as_bytes(),
            },
        )
        .map_err(|e| format!("AES-GCM encrypt failed: {}", e))?;

    let mut out = Vec::with_capacity(
        ENCRYPTED_KEY_MAGIC.len() + salt.len() + nonce_bytes.len() + ciphertext.len(),
    );
    out.extend_from_slice(ENCRYPTED_KEY_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by `encrypt_key`.
///
/// Expects `nonce(12) || ciphertext || tag(16)` layout.
pub fn decrypt_key(
    blob: &[u8],
    password: &str,
    address: &str,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    if password.is_empty() {
        return Err("Wallet password must not be empty".into());
    }
    let header_len = ENCRYPTED_KEY_MAGIC.len() + ARGON2_SALT_LEN + AES_GCM_NONCE_LEN;
    if blob.len() < header_len + 16 || !blob.starts_with(ENCRYPTED_KEY_MAGIC) {
        return Err("Invalid Argon2id wallet key format".into());
    }
    let salt_start = ENCRYPTED_KEY_MAGIC.len();
    let nonce_start = salt_start + ARGON2_SALT_LEN;
    let ciphertext_start = nonce_start + AES_GCM_NONCE_LEN;
    let salt = &blob[salt_start..nonce_start];
    let nonce_bytes = &blob[nonce_start..ciphertext_start];
    let ciphertext = &blob[ciphertext_start..];
    let nonce = Nonce::from_slice(nonce_bytes);
    let aes_key = derive_aes_key(password, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key.as_ref()));

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: address.as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| "AES-GCM decryption failed — wrong password or corrupted key".into())
}

fn decrypt_legacy_key(
    blob: &[u8],
    password: &str,
    address: &str,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    if password.is_empty() {
        return Err("Wallet password must not be empty".into());
    }
    if blob.len() < AES_GCM_NONCE_LEN + 16 {
        return Err("Legacy wallet key blob is invalid".into());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(AES_GCM_NONCE_LEN);
    let aes_key = derive_legacy_aes_key(password, address);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key.as_ref()));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| "Legacy wallet decryption failed — wrong password or corrupted key".into())
}

fn default_balance() -> String {
    "0".to_string()
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
            Self::create_private_dir_all(parent)?;
        }
        let wallets = if path.exists() {
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("Wallet path must be a regular file, not a symlink".into());
            }
            Self::ensure_private_file_permissions(&path, &metadata)?;
            let raw = Zeroizing::new(fs::read_to_string(&path)?);
            serde_json::from_str::<Vec<EncryptedWallet>>(&raw)?
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

    pub fn update_balance(
        &mut self,
        address: &str,
        balance: impl Into<String>,
    ) -> Result<bool, Box<dyn Error>> {
        let Some(wallet) = self.wallets.iter_mut().find(|w| w.address == address) else {
            return Ok(false);
        };

        wallet.balance = balance.into();
        self.persist()?;
        Ok(true)
    }

    fn persist(&self) -> Result<(), Box<dyn Error>> {
        if let Some(path) = &self.path {
            let json = Zeroizing::new(serde_json::to_string_pretty(&self.wallets)?);
            if let Some(parent) = path.parent() {
                Self::create_private_dir_all(parent)?;
            }
            let temp_path = Self::temporary_path(path);
            let result = (|| -> Result<(), Box<dyn Error>> {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                Self::set_private_file_mode(&mut options);
                let mut file = options.open(&temp_path)?;
                file.write_all(json.as_bytes())?;
                file.sync_all()?;
                fs::rename(&temp_path, path)?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temp_path);
            }
            result?;
        }
        Ok(())
    }

    fn temporary_path(path: &Path) -> PathBuf {
        let nonce = rand::random::<u64>();
        let mut temp_name = path.file_name().unwrap_or_default().to_os_string();
        temp_name.push(format!(".{}.{}.tmp", std::process::id(), nonce));
        path.with_file_name(temp_name)
    }

    #[cfg(unix)]
    fn set_private_file_mode(options: &mut OpenOptions) {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    #[cfg(not(unix))]
    fn set_private_file_mode(_options: &mut OpenOptions) {}

    #[cfg(unix)]
    fn create_private_dir_all(path: &Path) -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn create_private_dir_all(path: &Path) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn ensure_private_file_permissions(
        path: &Path,
        metadata: &fs::Metadata,
    ) -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn ensure_private_file_permissions(
        _path: &Path,
        _metadata: &fs::Metadata,
    ) -> Result<(), Box<dyn Error>> {
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
        assert_eq!(out.as_slice(), sk);
        assert!(blob.starts_with(ENCRYPTED_KEY_MAGIC));
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
    fn empty_wallet_password_is_rejected() {
        let addr = "BLEEP1test";
        assert!(encrypt_key(b"key", "", addr).is_err());
        assert!(decrypt_key(b"invalid", "", addr).is_err());
    }

    #[test]
    fn argon2id_salt_is_random_per_encryption() {
        let addr = "BLEEP1test";
        let first = encrypt_key(b"same key", "password", addr).unwrap();
        let second = encrypt_key(b"same key", "password", addr).unwrap();
        let salt_start = ENCRYPTED_KEY_MAGIC.len();
        let salt_end = salt_start + ARGON2_SALT_LEN;
        assert_ne!(&first[salt_start..salt_end], &second[salt_start..salt_end]);
    }

    #[test]
    fn plaintext_wallet_requires_explicit_dev_network() {
        assert!(is_dev_or_test_network("test"));
        assert!(is_dev_or_test_network("PRETESTNET"));
        assert!(!is_dev_or_test_network("mainnet"));
        assert!(!is_dev_or_test_network(""));
    }

    #[test]
    fn plaintext_dev_wallet_requires_opt_in_and_zeroizes_unlock_buffer() {
        let previous_enabled = std::env::var_os("BLEEP_WALLET_PLAINTEXT_DEV");
        let previous_network = std::env::var_os("BLEEP_NETWORK_MODE");
        std::env::set_var("BLEEP_WALLET_PLAINTEXT_DEV", "1");
        std::env::set_var("BLEEP_NETWORK_MODE", "test");

        let wallet =
            EncryptedWallet::with_signing_key_plaintext_dev(vec![1, 2, 3], b"dev-secret", vec![])
                .unwrap();
        let unlocked = wallet.unlock("").unwrap();
        assert_eq!(unlocked.as_slice(), b"dev-secret");

        if let Some(value) = previous_enabled {
            std::env::set_var("BLEEP_WALLET_PLAINTEXT_DEV", value);
        } else {
            std::env::remove_var("BLEEP_WALLET_PLAINTEXT_DEV");
        }
        if let Some(value) = previous_network {
            std::env::set_var("BLEEP_NETWORK_MODE", value);
        } else {
            std::env::remove_var("BLEEP_NETWORK_MODE");
        }
    }

    #[test]
    fn legacy_wallet_json_defaults_balance_to_zero() {
        let json = r#"{
            "falcon_keys": [1, 2, 3],
            "kyber_keys": [4, 5, 6],
            "signing_key": [],
            "address": "BLEEP1legacy",
            "label": null
        }"#;

        let wallet: EncryptedWallet = serde_json::from_str(json).unwrap();

        assert_eq!(wallet.balance, "0");
        assert_eq!(wallet.address, "BLEEP1legacy");
    }

    #[test]
    fn wallet_lock_unlock() {
        let pk = vec![0xAAu8; 32];
        let sk = vec![0xBBu8; 32];
        let mut w = EncryptedWallet::new(pk.clone(), vec![]);
        w.lock(&sk, "password").unwrap();
        assert!(w.can_sign());
        let recovered = w.unlock("password").unwrap();
        assert_eq!(recovered.as_slice(), sk);
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
        assert_eq!(w.unlock("my-password").unwrap().as_slice(), sk);
    }

    #[cfg(unix)]
    #[test]
    fn wallet_file_is_created_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallets.json");
        let mut manager = WalletManager::load_or_create_at(&path).unwrap();
        let wallet =
            EncryptedWallet::with_signing_key_encrypted(vec![1, 2, 3], b"secret", vec![], "pass")
                .unwrap();
        manager.save_wallet(wallet).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            WalletManager::load_or_create_at(path)
                .unwrap()
                .list_wallets()
                .len(),
            1
        );
    }

    #[test]
    fn malformed_wallet_file_is_not_silently_ignored() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallets.json");
        fs::write(&path, b"invalid json").unwrap();

        assert!(WalletManager::load_or_create_at(path).is_err());
    }
}
