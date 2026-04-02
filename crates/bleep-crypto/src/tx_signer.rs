//! # Transaction Signer
//!
//! Provides SPHINCS+-SHAKE-256 signing for BLEEP transactions.
//!
//! The `TxSigner` wraps the pqcrypto SPHINCS+ implementation and exposes
//! a simple sign/verify interface tied to ZKTransaction payloads.
//!
//! ## Key layout
//! ```text
//!   Public key  (SK in wallet): raw SPHINCS+ public key bytes (~32 bytes)
//!   Secret key (SK, not stored on disk): raw SPHINCS+ secret key bytes
//! ```
//!
//! ## Usage in bleep-cli
//! 1. On `wallet create`: store (pk_bytes, sk_bytes) together in EncryptedWallet
//! 2. On `tx send`: load sk_bytes, call `TxSigner::sign_tx_payload()`
//! 3. On receipt validation: call `TxSigner::verify_tx_signature()`

use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha3::{Digest, Sha3_256};

/// Sign a transaction payload using SPHINCS+-SHAKE-256.
///
/// `payload`    — deterministic encoding of the transaction fields.
/// `sk_bytes`   — raw SPHINCS+ secret key bytes.
///
/// Returns the raw detached signature bytes on success.
pub fn sign_tx_payload(payload: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let sk = sphincsshake256fsimple::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| format!("Invalid SPHINCS+ secret key: {:?}", e))?;
    let sig = sphincsshake256fsimple::detached_sign(payload, &sk);
    Ok(sig.as_bytes().to_vec())
}

/// Verify a transaction signature using SPHINCS+-SHAKE-256.
///
/// `payload`    — same deterministic encoding used during signing.
/// `sig_bytes`  — raw detached signature bytes.
/// `pk_bytes`   — raw SPHINCS+ public key bytes.
///
/// Returns `true` if the signature is valid.
pub fn verify_tx_signature(payload: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool {
    let pk = match sphincsshake256fsimple::PublicKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match sphincsshake256fsimple::DetachedSignature::from_bytes(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sphincsshake256fsimple::verify_detached_signature(&sig, payload, &pk).is_ok()
}

/// Build a deterministic byte payload for a transaction.
///
/// This is the canonical encoding that MUST be used for both signing
/// and verification to ensure they agree on the message bytes.
///
/// Layout: `sha3_256( sender_bytes || receiver_bytes || amount_le8 || timestamp_le8 )`
pub fn tx_payload(sender: &str, receiver: &str, amount: u64, timestamp: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(sender.as_bytes());
    h.update(receiver.as_bytes());
    h.update(&amount.to_le_bytes());
    h.update(&timestamp.to_le_bytes());
    h.finalize().into()
}

/// Generate a fresh SPHINCS+ keypair.
///
/// Returns `(public_key_bytes, secret_key_bytes)`.
pub fn generate_tx_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = sphincsshake256fsimple::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (pk, sk) = generate_tx_keypair();
        let payload = tx_payload("alice", "bob", 1000, 12345);
        let sig = sign_tx_payload(&payload, &sk).unwrap();
        assert!(verify_tx_signature(&payload, &sig, &pk));
    }

    #[test]
    fn test_bad_signature_rejected() {
        let (pk, sk) = generate_tx_keypair();
        let payload = tx_payload("alice", "bob", 1000, 12345);
        let mut sig = sign_tx_payload(&payload, &sk).unwrap();
        // Flip a byte in the signature
        sig[0] ^= 0xFF;
        assert!(!verify_tx_signature(&payload, &sig, &pk));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (_, sk1) = generate_tx_keypair();
        let (pk2, _) = generate_tx_keypair();
        let payload = tx_payload("alice", "bob", 1000, 12345);
        let sig = sign_tx_payload(&payload, &sk1).unwrap();
        // Verify with wrong public key
        assert!(!verify_tx_signature(&payload, &sig, &pk2));
    }

    #[test]
    fn test_tx_payload_deterministic() {
        let p1 = tx_payload("alice", "bob", 1000, 99999);
        let p2 = tx_payload("alice", "bob", 1000, 99999);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_tx_payload_changes_on_amount() {
        let p1 = tx_payload("alice", "bob", 1000, 99999);
        let p2 = tx_payload("alice", "bob", 2000, 99999);
        assert_ne!(p1, p2);
    }
}
