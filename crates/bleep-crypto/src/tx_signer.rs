//! # Transaction Signer
//!
//! Provides versioned SPHINCS+-SHAKE-256 and SLH-DSA transaction signing.
//!
//! The `TxSigner` wraps the pqcrypto SPHINCS+ implementation and exposes
//! a simple sign/verify interface tied to ZKTransaction payloads.
//!
//! ## Key layout
//! ```text
//!   BLEEP1: SPHINCS+-SHAKE-256f-simple key material
//!   BLEEP2: SLH-DSA SHAKE-256f key material
//! ```
//!
//! ## Usage in bleep-cli
//! Signing and verification dispatch by the address prefix.

use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

const TX_DOMAIN: &[u8] = b"BLEEP:TRANSACTION:V1\0";
const ACCOUNT_DOMAIN: &[u8] = b"BLEEP:ACCOUNT:ADDRESS:V1\0";
const ACCOUNT_DOMAIN_V2: &[u8] = b"BLEEP:ACCOUNT:ADDRESS:V2\0";
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

/// Sign with the version-2 FIPS 205 SLH-DSA SHAKE-256f key scheme.
pub fn sign_tx_payload_v2(payload: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    use slh_dsa::signature::Signer;

    let sk = slh_dsa::SigningKey::<slh_dsa::Shake256f>::try_from(sk_bytes)
        .map_err(|error| format!("Invalid version-2 SLH-DSA secret key: {error}"))?;
    let signature = sk
        .try_sign(payload)
        .map_err(|error| format!("SLH-DSA signing failed: {error}"))?;
    Ok(signature.to_vec())
}

/// Verify a version-2 FIPS 205 SLH-DSA SHAKE-256f signature.
pub fn verify_tx_signature_v2(payload: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool {
    use slh_dsa::signature::Verifier;

    let Ok(pk) = slh_dsa::VerifyingKey::<slh_dsa::Shake256f>::try_from(pk_bytes) else {
        return false;
    };
    let Ok(signature) = slh_dsa::Signature::<slh_dsa::Shake256f>::try_from(sig_bytes) else {
        return false;
    };
    pk.verify(payload, &signature).is_ok()
}

/// Sign according to the derivation version encoded by the account address.
pub fn sign_tx_payload_for_address(
    payload: &[u8],
    sk_bytes: &[u8],
    address: &str,
) -> Result<Vec<u8>, String> {
    match address {
        address if address.starts_with("BLEEP1") => sign_tx_payload(payload, sk_bytes),
        address if address.starts_with("BLEEP2") => sign_tx_payload_v2(payload, sk_bytes),
        _ => Err("Unsupported BLEEP account address version".into()),
    }
}

/// Verify a signature according to the derivation version encoded by the address.
pub fn verify_tx_signature_for_address(
    payload: &[u8],
    sig_bytes: &[u8],
    pk_bytes: &[u8],
    address: &str,
) -> bool {
    match address {
        address if address.starts_with("BLEEP1") => {
            verify_tx_signature(payload, sig_bytes, pk_bytes)
        }
        address if address.starts_with("BLEEP2") => {
            verify_tx_signature_v2(payload, sig_bytes, pk_bytes)
        }
        _ => false,
    }
}

/// Derive the canonical BLEEP account address from a SPHINCS+ public key.
///
/// The address is `BLEEP1` followed by the first 20 bytes of SHA256² over a
/// domain-separated, length-delimited public key.
pub fn derive_account_address(pk_bytes: &[u8]) -> String {
    derive_account_address_with_domain(pk_bytes, ACCOUNT_DOMAIN, "BLEEP1")
}

/// Derive a version-2 account address for FIPS 205 SLH-DSA keys.
pub fn derive_account_address_v2(pk_bytes: &[u8]) -> String {
    derive_account_address_with_domain(pk_bytes, ACCOUNT_DOMAIN_V2, "BLEEP2")
}

/// Return whether a public key derives to the supplied versioned account address.
pub fn account_address_matches_public_key(address: &str, pk_bytes: &[u8]) -> bool {
    match address {
        address if address.starts_with("BLEEP1") => derive_account_address(pk_bytes) == address,
        address if address.starts_with("BLEEP2") => derive_account_address_v2(pk_bytes) == address,
        _ => false,
    }
}

fn derive_account_address_with_domain(pk_bytes: &[u8], domain: &[u8], prefix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((pk_bytes.len() as u64).to_le_bytes());
    hasher.update(pk_bytes);
    let first = hasher.finalize();
    let second = Sha256::digest(first);
    format!("{prefix}{}", hex::encode(&second[..20]))
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

/// Build the canonical payload for bonding stake to a validator.
///
/// The destination commits to the Kyber and VRF public keys so the signing key
/// proves ownership of both validator keys in the stake request.
pub struct ValidatorKeyBindings<'a> {
    pub label: &'a str,
    pub kyber_public_key: &'a [u8],
    pub vrf_public_key: &'a [u8],
}

pub fn validator_stake_payload(
    chain_id: &str,
    sender: &str,
    validator: ValidatorKeyBindings<'_>,
    amount: u64,
    timestamp: u64,
    nonce: u64,
) -> [u8; 32] {
    let kem_commitment = hex::encode(Sha256::digest(validator.kyber_public_key));
    let vrf_commitment = hex::encode(Sha256::digest(validator.vrf_public_key));
    let receiver = format!(
        "validator:{}:kem:{kem_commitment}:vrf:{vrf_commitment}",
        validator.label
    );
    tx_payload(chain_id, sender, &receiver, amount, timestamp, nonce)
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
        assert_ne!(
            baseline,
            tx_payload("BLEEP-Mainnet", "alice", "bob", 1000, 99999, 0)
        );
        assert_ne!(
            baseline,
            tx_payload("BLEEP-PreTestnet", "alice", "bob", 1000, 99999, 1)
        );
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
