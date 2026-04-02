//! # bleep-connect-crypto
//!
//! Production-grade quantum-resistant and classical cryptography for BLEEP Connect.
//!
//! ## Algorithms
//! - **SPHINCS+**: Hash-based post-quantum signature scheme (signing/verification)
//! - **Kyber1024**: Post-quantum key encapsulation mechanism (encryption)
//! - **Ed25519**: Classical elliptic-curve signatures (for EVM interop)
//! - **AES-256-GCM**: Authenticated symmetric encryption
//! - **BLAKE2b / SHA-256 / SHA-3**: Hashing

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use blake2::Blake2b512;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber1024;
use pqcrypto_sphincsplus::sphincssha2256ssimple;
use pqcrypto_traits::kem::{Ciphertext, PublicKey as KemPk, SecretKey as KemSk, SharedSecret};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as SignPk, SecretKey as SignSk};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Errors from cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Random number generation failed")]
    RngFailed,
    #[error("Ed25519 error: {0}")]
    Ed25519Error(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// ─────────────────────────────────────────────────────────────────────────────
// QUANTUM KEY PAIR (SPHINCS+ signing + Kyber1024 KEM)
// ─────────────────────────────────────────────────────────────────────────────

/// A post-quantum keypair: SPHINCS+ for signing, Kyber1024 for key encapsulation.
#[derive(ZeroizeOnDrop)]
pub struct QuantumKeyPair {
    /// SPHINCS+ signing secret key bytes
    sign_sk: Vec<u8>,
    /// SPHINCS+ signing public key bytes (kept with the pair for convenience)
    sign_pk: Vec<u8>,
    /// Kyber1024 KEM secret key bytes
    kem_sk: Vec<u8>,
    /// Kyber1024 KEM public key bytes
    kem_pk: Vec<u8>,
}

impl QuantumKeyPair {
    /// Generate a fresh quantum keypair using OS randomness.
    pub fn generate() -> Self {
        let (sign_pk, sign_sk) = sphincssha2256ssimple::keypair();
        let (kem_pk, kem_sk) = kyber1024::keypair();
        Self {
            sign_sk: sign_sk.as_bytes().to_vec(),
            sign_pk: sign_pk.as_bytes().to_vec(),
            kem_sk: kem_sk.as_bytes().to_vec(),
            kem_pk: kem_pk.as_bytes().to_vec(),
        }
    }

    /// Return the SPHINCS+ public key bytes (for sharing).
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.sign_pk
    }

    /// Return the Kyber1024 public key bytes (for sharing).
    pub fn kem_public_key_bytes(&self) -> &[u8] {
        &self.kem_pk
    }

    /// Sign a message with SPHINCS+. Returns a detached signature.
    pub fn sign(&self, message: &[u8]) -> CryptoResult<QuantumSignature> {
        let sk = sphincssha2256ssimple::SecretKey::from_bytes(&self.sign_sk).map_err(|_| {
            CryptoError::InvalidKeyLength {
                expected: sphincssha2256ssimple::secret_key_bytes(),
                got: self.sign_sk.len(),
            }
        })?;
        let sig = sphincssha2256ssimple::detached_sign(message, &sk);
        Ok(QuantumSignature {
            bytes: sig.as_bytes().to_vec(),
        })
    }

    /// Encrypt data using Kyber1024 KEM + AES-256-GCM hybrid encryption.
    /// Returns (ciphertext, kem_ciphertext) where kem_ciphertext is the
    /// Kyber encapsulation needed for decryption.
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<EncryptedPayload> {
        let pk = kyber1024::PublicKey::from_bytes(&self.kem_pk).map_err(|_| {
            CryptoError::InvalidKeyLength {
                expected: kyber1024::public_key_bytes(),
                got: self.kem_pk.len(),
            }
        })?;
        let (shared_secret, kem_ciphertext) = kyber1024::encapsulate(&pk);
        let aes_key = derive_aes_key(shared_secret.as_bytes())?;
        let encrypted = aes_gcm_encrypt(&aes_key, plaintext)?;
        Ok(EncryptedPayload {
            kem_ciphertext: kem_ciphertext.as_bytes().to_vec(),
            aes_ciphertext: encrypted,
        })
    }

    /// Decrypt a payload encrypted with our KEM public key.
    pub fn decrypt(&self, payload: &EncryptedPayload) -> CryptoResult<Vec<u8>> {
        let sk = kyber1024::SecretKey::from_bytes(&self.kem_sk).map_err(|_| {
            CryptoError::InvalidKeyLength {
                expected: kyber1024::secret_key_bytes(),
                got: self.kem_sk.len(),
            }
        })?;
        let ct = kyber1024::Ciphertext::from_bytes(&payload.kem_ciphertext)
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let shared_secret = kyber1024::decapsulate(&ct, &sk);
        let aes_key = derive_aes_key(shared_secret.as_bytes())?;
        aes_gcm_decrypt(&aes_key, &payload.aes_ciphertext)
    }
}

/// A detached SPHINCS+ signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSignature {
    pub bytes: Vec<u8>,
}

/// Encrypted payload: Kyber KEM encapsulation + AES-256-GCM ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub kem_ciphertext: Vec<u8>,
    pub aes_ciphertext: Vec<u8>,
}

/// A public-only quantum verifier (for verifying signatures without the secret key).
pub struct QuantumVerifier {
    sign_pk: Vec<u8>,
}

impl QuantumVerifier {
    pub fn new(sign_pk_bytes: &[u8]) -> Self {
        Self {
            sign_pk: sign_pk_bytes.to_vec(),
        }
    }

    /// Verify a SPHINCS+ detached signature over `message`.
    pub fn verify_sphincs(&self, message: &[u8], signature: &QuantumSignature) -> bool {
        let pk = match sphincssha2256ssimple::PublicKey::from_bytes(&self.sign_pk) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match sphincssha2256ssimple::DetachedSignature::from_bytes(&signature.bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        sphincssha2256ssimple::verify_detached_signature(&sig, message, &pk).is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLASSICAL ED25519 (for EVM interoperability)
// ─────────────────────────────────────────────────────────────────────────────

/// An Ed25519 keypair for compatibility with EVM chains.
pub struct ClassicalKeyPair {
    signing_key: SigningKey,
}

impl ClassicalKeyPair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> CryptoResult<Self> {
        Ok(Self {
            signing_key: SigningKey::from_bytes(bytes),
        })
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }

    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| CryptoError::Ed25519Error(e.to_string()))?;
        if signature.len() != 64 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 64,
                got: signature.len(),
            });
        }
        let sig_bytes: [u8; 64] =
            signature
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength {
                    expected: 64,
                    got: signature.len(),
                })?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        Ok(vk.verify(message, &sig).is_ok())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HASHING UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

/// SHA-256 hash of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-3-256 hash of `data`.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

/// BLAKE2b-512 hash of `data`, truncated to 32 bytes.
pub fn blake2b_32(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2b512::new();
    h.update(data);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

/// BLAKE2b-512 hash of `data`.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    blake2b_32(data)
}

/// Compute a Merkle root from a list of 32-byte leaf hashes.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() {
                current[i + 1]
            } else {
                current[i]
            };
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&left);
            combined.extend_from_slice(&right);
            next.push(sha256(&combined));
            i += 2;
        }
        current = next;
    }
    current[0]
}

// ─────────────────────────────────────────────────────────────────────────────
// INTERNAL HELPERS
// ─────────────────────────────────────────────────────────────────────────────

fn derive_aes_key(shared_secret: &[u8]) -> CryptoResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"bleep-connect-aes-key", &mut key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    Ok(key)
}

fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    // Prepend 12-byte nonce to ciphertext
    let mut output = nonce.to_vec();
    output.append(&mut ciphertext);
    Ok(output)
}

fn aes_gcm_decrypt(key: &[u8; 32], data: &[u8]) -> CryptoResult<Vec<u8>> {
    if data.len() < 12 {
        return Err(CryptoError::InvalidCiphertext);
    }
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDATOR MULTI-SIG AGGREGATION
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate multiple Ed25519 validator signatures into a compact representation.
/// Returns the concatenated signatures and public keys; verification checks
/// that at least `threshold` out of `total` validators signed correctly.
pub struct ValidatorMultiSig {
    pub signatures: Vec<Vec<u8>>,
    pub public_keys: Vec<[u8; 32]>,
    pub message_hash: [u8; 32],
}

impl ValidatorMultiSig {
    pub fn new(message: &[u8]) -> Self {
        Self {
            signatures: Vec::new(),
            public_keys: Vec::new(),
            message_hash: sha256(message),
        }
    }

    pub fn add_signature(&mut self, public_key: [u8; 32], signature: Vec<u8>) {
        self.public_keys.push(public_key);
        self.signatures.push(signature);
    }

    /// Verify that at least `threshold` signatures are valid.
    pub fn verify_threshold(&self, threshold: usize) -> bool {
        let mut valid = 0usize;
        for (pk, sig) in self.public_keys.iter().zip(self.signatures.iter()) {
            if ClassicalKeyPair::verify(pk, &self.message_hash, sig).unwrap_or(false) {
                valid += 1;
            }
        }
        valid >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_sign_verify() {
        let kp = QuantumKeyPair::generate();
        let msg = b"cross-chain transfer payload";
        let sig = kp.sign(msg).expect("sign failed");
        let verifier = QuantumVerifier::new(kp.public_key_bytes());
        assert!(verifier.verify_sphincs(msg, &sig));
        // Tampered message must fail
        let sig2 = kp.sign(b"different message").expect("sign failed");
        assert!(!verifier.verify_sphincs(msg, &sig2));
    }

    #[test]
    fn test_quantum_encrypt_decrypt() {
        let kp = QuantumKeyPair::generate();
        let plaintext = b"secret cross-chain data";
        let enc = kp.encrypt(plaintext).expect("encrypt failed");
        let dec = kp.decrypt(&enc).expect("decrypt failed");
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn test_classical_ed25519() {
        let kp = ClassicalKeyPair::generate();
        let msg = b"evm compatible message";
        let sig = kp.sign(msg);
        assert!(ClassicalKeyPair::verify(&kp.public_key_bytes(), msg, &sig).unwrap());
    }

    #[test]
    fn test_merkle_root() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| sha256(&[i])).collect();
        let root = merkle_root(&leaves);
        assert_ne!(root, [0u8; 32]);
        // Same leaves, same root
        let root2 = merkle_root(&leaves);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_validator_multisig() {
        let kp1 = ClassicalKeyPair::generate();
        let kp2 = ClassicalKeyPair::generate();
        let kp3 = ClassicalKeyPair::generate();
        let msg = b"commit block 42";
        let mut multi = ValidatorMultiSig::new(msg);
        multi.add_signature(kp1.public_key_bytes(), kp1.sign(&sha256(msg)));
        multi.add_signature(kp2.public_key_bytes(), kp2.sign(&sha256(msg)));
        multi.add_signature(kp3.public_key_bytes(), kp3.sign(&sha256(msg)));
        // Threshold 2 of 3 must pass
        assert!(multi.verify_threshold(2));
        // Threshold 4 of 3 must fail
        assert!(!multi.verify_threshold(4));
    }
}
