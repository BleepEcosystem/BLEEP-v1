//! # Transaction Signer
//!
//! Provides SPHINCS+-SHAKE-256 signing for BLEEP transactions.
//!
//! The `TxSigner` wraps the pqcrypto SPHINCS+ implementation and exposes
//! a simple sign/verify interface tied to ZKTransaction payloads.
//!
//! ## Key layout
//! ```text
//!   Public key  (SK in wallet): raw SPHINCS+ public key bytes (64 bytes)
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
use sha2::Sha256;

const TX_DOMAIN: &[u8] = b"BLEEP:TRANSACTION:V1\0";
const ACCOUNT_DOMAIN: &[u8] = b"BLEEP:ACCOUNT:ADDRESS:V1\0";
pub const DEFAULT_CHAIN_ID: &str = "BLEEP-PreTestnet-001";

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

/// Derive the canonical BLEEP account address from a SPHINCS+ public key.
///
/// The address is `BLEEP1` followed by the first 20 bytes of SHA256² over a
/// domain-separated, length-delimited public key.
pub fn derive_account_address(pk_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ACCOUNT_DOMAIN);
    hasher.update((pk_bytes.len() as u64).to_le_bytes());
    hasher.update(pk_bytes);
    let first = hasher.finalize();
    let second = Sha256::digest(first);
    format!("BLEEP1{}", hex::encode(&second[..20]))
}

/// Build the canonical, domain-separated byte payload for a transaction.
///
/// This is the canonical encoding that MUST be used for both signing
/// and verification to ensure they agree on the message bytes.
///
/// Variable-length fields are prefixed with their little-endian u64 length.
/// Amount, timestamp, and nonce are encoded as little-endian u64 values.
pub fn tx_payload(
    chain_id: &str,
    sender: &str,
    receiver: &str,
    amount: u64,
    timestamp: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(TX_DOMAIN);
    h.update((chain_id.len() as u64).to_le_bytes());
    h.update(chain_id.as_bytes());
    h.update((sender.len() as u64).to_le_bytes());
    h.update(sender.as_bytes());
    h.update((receiver.len() as u64).to_le_bytes());
    h.update(receiver.as_bytes());
    h.update(amount.to_le_bytes());
    h.update(timestamp.to_le_bytes());
    h.update(nonce.to_le_bytes());
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
        let payload = tx_payload("BLEEP-PreTestnet", "alice", "bob", 1000, 12345, 0);
        let sig = sign_tx_payload(&payload, &sk).unwrap();
        assert!(verify_tx_signature(&payload, &sig, &pk));
    }

    #[test]
    fn test_bad_signature_rejected() {
        let (pk, sk) = generate_tx_keypair();
        let payload = tx_payload("BLEEP-PreTestnet", "alice", "bob", 1000, 12345, 0);
        let mut sig = sign_tx_payload(&payload, &sk).unwrap();
        // Flip a byte in the signature
        sig[0] ^= 0xFF;
        assert!(!verify_tx_signature(&payload, &sig, &pk));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (_, sk1) = generate_tx_keypair();
        let (pk2, _) = generate_tx_keypair();
        let payload = tx_payload("BLEEP-PreTestnet", "alice", "bob", 1000, 12345, 0);
        let sig = sign_tx_payload(&payload, &sk1).unwrap();
        // Verify with wrong public key
        assert!(!verify_tx_signature(&payload, &sig, &pk2));
    }

    #[test]
    fn test_tx_payload_deterministic() {
        let p1 = tx_payload("BLEEP-PreTestnet", "alice", "bob", 1000, 99999, 0);
        let p2 = tx_payload("BLEEP-PreTestnet", "alice", "bob", 1000, 99999, 0);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_tx_payload_changes_on_amount() {
        let p1 = tx_payload("BLEEP-PreTestnet", "alice", "bob", 1000, 99999, 0);
        let p2 = tx_payload("BLEEP-PreTestnet", "alice", "bob", 2000, 99999, 0);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_tx_payload_binds_chain_and_nonce() {
        let baseline = tx_payload("BLEEP-PreTestnet", "alice", "bob", 1000, 99999, 0);
        assert_ne!(baseline, tx_payload("BLEEP-Mainnet", "alice", "bob", 1000, 99999, 0));
        assert_ne!(baseline, tx_payload("BLEEP-PreTestnet", "alice", "bob", 1000, 99999, 1));
    }

    #[test]
    fn test_account_address_is_deterministic_and_key_bound() {
        let (pk, _) = generate_tx_keypair();
        let (other_pk, _) = generate_tx_keypair();
        let address = derive_account_address(&pk);
        assert_eq!(address, derive_account_address(&pk));
        assert!(address.starts_with("BLEEP1"));
        assert_ne!(address, derive_account_address(&other_pk));
    }
}
