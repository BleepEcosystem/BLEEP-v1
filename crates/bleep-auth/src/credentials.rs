// ============================================================================
// BLEEP-AUTH: Credential Storage
//
// Stores salted SHA3-256 credential hashes. Every credential is a unique
// (salt, hash) pair; the plaintext secret is zeroed immediately after hashing
// via the `Zeroizing` wrapper.
//
// Production note: Replace the SHA3-256 password hasher with Argon2id
// for memory-hard password stretching before mainnet. The abstraction here
// (CredentialStore::store_password / verify_password) makes that a one-line
// swap without touching callers.
//
// SAFETY INVARIANTS:
//   1. Salts are 32 bytes of OS-backed CSPRNG (rand::thread_rng).
//   2. Comparison is always constant-time to prevent timing attacks.
//   3. Plaintext passwords are zeroed via Zeroizing before being dropped.
//   4. Old password credentials are deactivated before a new one is stored.
// ============================================================================

use crate::errors::{AuthError, AuthResult};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialKind {
    PasswordHash,
    ApiKeyHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub identity_id: String,
    pub kind: CredentialKind,
    /// 32-byte CSPRNG salt, hex-encoded
    pub salt: String,
    /// SHA3-256(salt ∥ secret), hex-encoded
    pub hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_verified: Option<chrono::DateTime<chrono::Utc>>,
    pub active: bool,
}

impl Credential {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Hash a password into a new `Credential`.
    ///
    /// Returns `Err(PasswordTooWeak)` if `password.len() < 12`.
    /// The plaintext is wrapped in `Zeroizing` so it is zeroed on drop.
    pub fn new_password(identity_id: String, password: String) -> AuthResult<Self> {
        if password.len() < 12 {
            return Err(AuthError::PasswordTooWeak);
        }
        let password_z = Zeroizing::new(password.into_bytes());
        let (salt_hex, hash_hex) = Self::derive_hash(&password_z);
        Ok(Self {
            identity_id,
            kind: CredentialKind::PasswordHash,
            salt: salt_hex,
            hash: hash_hex,
            created_at: chrono::Utc::now(),
            last_verified: None,
            active: true,
        })
    }

    /// Hash a raw API-key byte slice into a new `Credential`.
    pub fn new_api_key(identity_id: String, raw_key: &[u8]) -> AuthResult<Self> {
        let key_z = Zeroizing::new(raw_key.to_vec());
        let (salt_hex, hash_hex) = Self::derive_hash(&key_z);
        Ok(Self {
            identity_id,
            kind: CredentialKind::ApiKeyHash,
            salt: salt_hex,
            hash: hash_hex,
            created_at: chrono::Utc::now(),
            last_verified: None,
            active: true,
        })
    }

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    /// Constant-time password verification. Updates `last_verified` on success.
    pub fn verify_password(&mut self, password: &str) -> AuthResult<()> {
        if !self.active {
            return Err(AuthError::InvalidCredentials);
        }
        let password_z = Zeroizing::new(password.as_bytes().to_vec());
        self.verify_secret(&password_z)
    }

    /// Constant-time secret verification (works for both passwords and API keys).
    pub fn verify_secret(&mut self, secret: &[u8]) -> AuthResult<()> {
        if !self.active {
            return Err(AuthError::InvalidCredentials);
        }
        let salt = hex::decode(&self.salt)
            .map_err(|e| AuthError::CryptoError(format!("salt decode: {e}")))?;
        let expected = hex::decode(&self.hash)
            .map_err(|e| AuthError::CryptoError(format!("hash decode: {e}")))?;

        let computed = {
            let mut h = Sha3_256::new();
            h.update(&salt);
            h.update(secret);
            h.finalize()
        };

        if constant_time_eq::constant_time_eq(&computed, &expected) {
            self.last_verified = Some(chrono::Utc::now());
            Ok(())
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn derive_hash(secret: &[u8]) -> (String, String) {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut h = Sha3_256::new();
        h.update(&salt);
        h.update(secret);
        let hash = h.finalize();
        (hex::encode(salt), hex::encode(hash))
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Thread-safe in-memory credential store.
///
/// Back this with an encrypted database in production (SQLCipher / pgcrypto).
pub struct CredentialStore {
    /// identity_id → list of credential records (multiple kinds supported)
    inner: HashMap<String, Vec<Credential>>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    /// Store a password, deactivating any existing active password first.
    pub fn store_password(&mut self, identity_id: &str, password: String) -> AuthResult<()> {
        let cred = Credential::new_password(identity_id.to_string(), password)?;
        let bucket = self.inner.entry(identity_id.to_string()).or_default();
        for c in bucket.iter_mut() {
            if c.kind == CredentialKind::PasswordHash {
                c.active = false;
            }
        }
        bucket.push(cred);
        Ok(())
    }

    /// Issue a fresh random API key. Returns the raw key string (shown once).
    pub fn issue_api_key(&mut self, identity_id: &str) -> AuthResult<String> {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let raw_hex = hex::encode(raw);
        let cred = Credential::new_api_key(identity_id.to_string(), raw_hex.as_bytes())?;
        self.inner
            .entry(identity_id.to_string())
            .or_default()
            .push(cred);
        Ok(raw_hex)
    }

    /// Revoke all credentials for an identity.
    pub fn revoke_all(&mut self, identity_id: &str) {
        if let Some(bucket) = self.inner.get_mut(identity_id) {
            for c in bucket.iter_mut() {
                c.active = false;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Read / Verify
    // -----------------------------------------------------------------------

    pub fn verify_password(&mut self, identity_id: &str, password: &str) -> AuthResult<()> {
        let bucket = self
            .inner
            .get_mut(identity_id)
            .ok_or_else(|| AuthError::IdentityNotFound(identity_id.to_string()))?;
        let cred = bucket
            .iter_mut()
            .find(|c| c.kind == CredentialKind::PasswordHash && c.active)
            .ok_or(AuthError::InvalidCredentials)?;
        cred.verify_password(password)
    }

    pub fn verify_api_key(&mut self, identity_id: &str, raw_key: &str) -> AuthResult<()> {
        let bucket = self
            .inner
            .get_mut(identity_id)
            .ok_or_else(|| AuthError::IdentityNotFound(identity_id.to_string()))?;
        for cred in bucket
            .iter_mut()
            .filter(|c| c.kind == CredentialKind::ApiKeyHash && c.active)
        {
            if cred.verify_secret(raw_key.as_bytes()).is_ok() {
                return Ok(());
            }
        }
        Err(AuthError::InvalidCredentials)
    }

    pub fn credential_count(&self) -> usize {
        self.inner.values().map(|v| v.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let mut c = Credential::new_password("u1".into(), "correct-horse-battery".into()).unwrap();
        assert!(c.verify_password("correct-horse-battery").is_ok());
        assert!(c.verify_password("wrong-pass").is_err());
    }

    #[test]
    fn weak_password_rejected() {
        assert!(Credential::new_password("u1".into(), "short".into()).is_err());
    }

    #[test]
    fn two_salts_differ() {
        let c1 = Credential::new_password("u1".into(), "same-password-here".into()).unwrap();
        let c2 = Credential::new_password("u1".into(), "same-password-here".into()).unwrap();
        assert_ne!(c1.salt, c2.salt);
        assert_ne!(c1.hash, c2.hash);
    }

    #[test]
    fn store_and_verify() {
        let mut store = CredentialStore::new();
        store
            .store_password("op1", "strong-passphrase-123".into())
            .unwrap();
        assert!(store
            .verify_password("op1", "strong-passphrase-123")
            .is_ok());
        assert!(store.verify_password("op1", "wrong").is_err());
    }

    #[test]
    fn api_key_round_trip() {
        let mut store = CredentialStore::new();
        let key = store.issue_api_key("dapp1").unwrap();
        assert!(store.verify_api_key("dapp1", &key).is_ok());
        assert!(store.verify_api_key("dapp1", "badkey").is_err());
    }

    #[test]
    fn password_rotation_deactivates_old() {
        let mut store = CredentialStore::new();
        store
            .store_password("op2", "first-password-here".into())
            .unwrap();
        store
            .store_password("op2", "second-password-here".into())
            .unwrap();
        assert!(
            store.verify_password("op2", "first-password-here").is_err(),
            "old password must be rejected"
        );
        assert!(store.verify_password("op2", "second-password-here").is_ok());
    }
}
