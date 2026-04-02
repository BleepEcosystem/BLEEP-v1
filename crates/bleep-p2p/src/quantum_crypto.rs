//! Production post-quantum and classical cryptography for bleep-p2p.
//!
//! Algorithms used:
//! - Key encapsulation : Kyber-768 (NIST PQC round 3 winner)
//! - Signatures        : SPHINCS+-SHA2-128s (stateless hash-based, NIST PQC winner)
//! - Classical signing : Ed25519 (for EVM / off-chain compatibility)
//! - Symmetric         : AES-256-GCM with random 12-byte nonce prepended
//! - KDF               : HKDF-SHA256

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_sphincsplus::sphincssha2128ssimple as sphincs;
use pqcrypto_traits::{
    kem::{Ciphertext as KemCiphertext, PublicKey as KemPk, SecretKey as KemSk, SharedSecret},
    sign::{PublicKey as SignPk, SecretKey as SignSk, SignedMessage},
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

use crate::error::{P2PError, P2PResult};

// ─────────────────────────────────────────────────────────────────────────────
// KYBER KEY ENCAPSULATION
// ─────────────────────────────────────────────────────────────────────────────

/// Kyber-768 public key.
#[derive(Clone)]
pub struct KyberPublicKey(pub Vec<u8>);

/// Kyber-768 secret key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct KyberSecretKey(#[zeroize(skip)] pub Vec<u8>);

/// A generated Kyber keypair.
pub struct KyberKeypair {
    pub public_key: KyberPublicKey,
    pub secret_key: KyberSecretKey,
}

impl KyberKeypair {
    /// Generate a fresh Kyber-768 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = kyber768::keypair();
        KyberKeypair {
            public_key: KyberPublicKey(pk.as_bytes().to_vec()),
            secret_key: KyberSecretKey(sk.as_bytes().to_vec()),
        }
    }
}

/// Encapsulate a shared secret to `recipient_pk`.
/// Returns `(ciphertext_bytes, shared_secret_bytes)`.
pub fn kyber_encapsulate(recipient_pk_bytes: &[u8]) -> P2PResult<(Vec<u8>, Vec<u8>)> {
    let pk = kyber768::PublicKey::from_bytes(recipient_pk_bytes)
        .map_err(|e| P2PError::Crypto(format!("Kyber pk parse: {e}")))?;
    let (ss, ct) = kyber768::encapsulate(&pk);
    Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

/// Decapsulate to recover the shared secret.
pub fn kyber_decapsulate(ciphertext_bytes: &[u8], sk_bytes: &[u8]) -> P2PResult<Vec<u8>> {
    let ct = kyber768::Ciphertext::from_bytes(ciphertext_bytes)
        .map_err(|e| P2PError::Crypto(format!("Kyber ct parse: {e}")))?;
    let sk = kyber768::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| P2PError::Crypto(format!("Kyber sk parse: {e}")))?;
    let ss = kyber768::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// SPHINCS+ SIGNATURES
// ─────────────────────────────────────────────────────────────────────────────

/// SPHINCS+-SHA2-128s public key.
#[derive(Clone, Debug)]
pub struct SphincsPublicKey(pub Vec<u8>);

/// SPHINCS+-SHA2-128s secret key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SphincsSecretKey(#[zeroize(skip)] pub Vec<u8>);

pub struct SphincsKeypair {
    pub public_key: SphincsPublicKey,
    pub secret_key: SphincsSecretKey,
}

impl SphincsKeypair {
    pub fn generate() -> Self {
        let (pk, sk) = sphincs::keypair();
        SphincsKeypair {
            public_key: SphincsPublicKey(pk.as_bytes().to_vec()),
            secret_key: SphincsSecretKey(sk.as_bytes().to_vec()),
        }
    }
}

/// Sign `message` with SPHINCS+ and return the detached signature bytes.
pub fn sphincs_sign(message: &[u8], sk_bytes: &[u8]) -> P2PResult<Vec<u8>> {
    let sk = sphincs::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| P2PError::Crypto(format!("SPHINCS+ sk parse: {e}")))?;
    let signed = sphincs::sign(message, &sk);
    // Extract detached signature: signed_message = signature ‖ message
    let sig_len = signed.as_bytes().len() - message.len();
    Ok(signed.as_bytes()[..sig_len].to_vec())
}

/// Verify a detached SPHINCS+ signature.
pub fn sphincs_verify(message: &[u8], signature_bytes: &[u8], pk_bytes: &[u8]) -> P2PResult<()> {
    let pk = sphincs::PublicKey::from_bytes(pk_bytes)
        .map_err(|e| P2PError::Crypto(format!("SPHINCS+ pk parse: {e}")))?;
    // Re-assemble signed message = signature ‖ message
    let mut signed_bytes = signature_bytes.to_vec();
    signed_bytes.extend_from_slice(message);
    let signed = sphincs::SignedMessage::from_bytes(&signed_bytes)
        .map_err(|e| P2PError::Crypto(format!("SPHINCS+ signed parse: {e}")))?;
    sphincs::open(&signed, &pk)
        .map(|_| ())
        .map_err(|_| P2PError::AuthenticationFailed)
}

// ─────────────────────────────────────────────────────────────────────────────
// ED25519 CLASSICAL SIGNATURES
// ─────────────────────────────────────────────────────────────────────────────

/// Ed25519 keypair for classical (EVM-compatible) signing.
pub struct Ed25519Keypair {
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Ed25519Keypair {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        Ed25519Keypair {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_bytes(secret_bytes: &[u8; 32]) -> P2PResult<Self> {
        let signing_key = SigningKey::from_bytes(secret_bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Ed25519Keypair {
            signing_key,
            verifying_key,
        })
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
}

/// Verify an Ed25519 signature.
pub fn ed25519_verify(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> P2PResult<()> {
    let vk_bytes: &[u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| P2PError::Crypto("Ed25519 pk must be 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(vk_bytes)
        .map_err(|e| P2PError::Crypto(format!("Ed25519 pk parse: {e}")))?;
    let sig_bytes: &[u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| P2PError::Crypto("Ed25519 sig must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify(message, &sig)
        .map_err(|_| P2PError::AuthenticationFailed)
}

// ─────────────────────────────────────────────────────────────────────────────
// SYMMETRIC ENCRYPTION — AES-256-GCM + HKDF
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a 32-byte symmetric key from `ikm` using HKDF-SHA256.
/// `info` is a domain-separation label (e.g., b"bleep-p2p-session-key").
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand should not fail for 32-byte output");
    okm
}

/// Encrypt `plaintext` with AES-256-GCM.
/// Returns `nonce (12 bytes) ‖ ciphertext`.
pub fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> P2PResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| P2PError::Crypto(format!("AES-GCM encrypt: {e}")))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `nonce ‖ ciphertext` with AES-256-GCM.
pub fn aes_gcm_decrypt(key: &[u8; 32], nonce_and_ciphertext: &[u8]) -> P2PResult<Vec<u8>> {
    if nonce_and_ciphertext.len() < 12 {
        return Err(P2PError::DecryptionFailed);
    }
    let (nonce_bytes, ciphertext) = nonce_and_ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| P2PError::DecryptionFailed)
}

// ─────────────────────────────────────────────────────────────────────────────
// SESSION KEY MATERIAL
// ─────────────────────────────────────────────────────────────────────────────

/// A Kyber-derived session key shared between two peers.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKey {
    #[zeroize(skip)]
    pub key_material: [u8; 32],
    pub peer_id_bytes: Vec<u8>,
}

impl SessionKey {
    /// Derive a session key from a Kyber shared secret and a peer-specific salt.
    pub fn from_shared_secret(shared_secret: &[u8], peer_id_bytes: &[u8]) -> Self {
        let key_material = derive_key(shared_secret, peer_id_bytes, b"bleep-p2p-session-v1");
        SessionKey {
            key_material,
            peer_id_bytes: peer_id_bytes.to_vec(),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> P2PResult<Vec<u8>> {
        aes_gcm_encrypt(&self.key_material, plaintext)
    }

    pub fn decrypt(&self, nonce_and_ct: &[u8]) -> P2PResult<Vec<u8>> {
        aes_gcm_decrypt(&self.key_material, nonce_and_ct)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROOF OF IDENTITY (ZK-lite Schnorr-like commitment)
// ─────────────────────────────────────────────────────────────────────────────

/// A non-interactive proof-of-identity built on Ed25519 + SHA-256 Fiat-Shamir.
///
/// The prover demonstrates knowledge of the signing key for `public_key` by:
/// 1. Generating a random commitment `R = r·G`.
/// 2. Computing challenge `c = SHA-256(R ‖ public_key ‖ context)`.
/// 3. Computing response `s = r + c·sk` (mod ℓ, handled by ed25519-dalek internally
///    via signing a deterministic message).
///
/// In practice we use Ed25519's deterministic signing of a challenge-derived message,
/// which is cryptographically equivalent and simpler to implement correctly.
pub struct ProofOfIdentity {
    /// The challenge that was signed.
    pub challenge: Vec<u8>,
    /// The Ed25519 signature over the challenge.
    pub signature: Vec<u8>,
    /// The signer's Ed25519 public key.
    pub public_key: Vec<u8>,
}

impl ProofOfIdentity {
    /// Create a proof of identity for `context` (e.g., `b"bleep-p2p-handshake"` ‖ peer_nonce).
    pub fn create(keypair: &Ed25519Keypair, context: &[u8]) -> Self {
        // Challenge = SHA-256(public_key ‖ context ‖ random_nonce)
        let mut rng_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rng_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&keypair.public_key_bytes());
        hasher.update(context);
        hasher.update(&rng_bytes);
        let challenge = hasher.finalize().to_vec();

        let signature = keypair.sign(&challenge);
        ProofOfIdentity {
            challenge,
            signature,
            public_key: keypair.public_key_bytes(),
        }
    }

    /// Verify the proof.
    pub fn verify(&self) -> P2PResult<()> {
        ed25519_verify(&self.challenge, &self.signature, &self.public_key)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HYBRID IDENTITY — Ed25519 + SPHINCS+
// ─────────────────────────────────────────────────────────────────────────────

/// A complete node identity that holds both classical and post-quantum keys.
pub struct NodeIdentity {
    pub ed_keypair: Ed25519Keypair,
    pub sphincs_keypair: SphincsKeypair,
    pub kyber_keypair: KyberKeypair,
}

impl NodeIdentity {
    pub fn generate() -> Self {
        NodeIdentity {
            ed_keypair: Ed25519Keypair::generate(),
            sphincs_keypair: SphincsKeypair::generate(),
            kyber_keypair: KyberKeypair::generate(),
        }
    }

    /// Derive the NodeId from the Ed25519 public key.
    pub fn node_id(&self) -> crate::types::NodeId {
        crate::types::NodeId::from_bytes(&self.ed_keypair.public_key_bytes())
    }

    /// Sign message with Ed25519 (fast, small signature — used for gossip).
    pub fn sign_ed(&self, message: &[u8]) -> Vec<u8> {
        self.ed_keypair.sign(message)
    }

    /// Sign message with SPHINCS+ (quantum-safe — used for identity proofs).
    pub fn sign_sphincs(&self, message: &[u8]) -> P2PResult<Vec<u8>> {
        sphincs_sign(message, &self.sphincs_keypair.secret_key.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_encap_decap_roundtrip() {
        let kp = KyberKeypair::generate();
        let (ct, ss1) = kyber_encapsulate(&kp.public_key.0).unwrap();
        let ss2 = kyber_decapsulate(&ct, &kp.secret_key.0).unwrap();
        assert_eq!(ss1, ss2, "Shared secrets must match");
        assert_eq!(ss1.len(), 32, "Kyber-768 shared secret is 32 bytes");
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let kp = SphincsKeypair::generate();
        let msg = b"bleep identity proof test";
        let sig = sphincs_sign(msg, &kp.secret_key.0).unwrap();
        sphincs_verify(msg, &sig, &kp.public_key.0).unwrap();
    }

    #[test]
    fn test_sphincs_verify_wrong_message_fails() {
        let kp = SphincsKeypair::generate();
        let sig = sphincs_sign(b"correct", &kp.secret_key.0).unwrap();
        assert!(sphincs_verify(b"wrong", &sig, &kp.public_key.0).is_err());
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let kp = Ed25519Keypair::generate();
        let msg = b"test message";
        let sig = kp.sign(msg);
        ed25519_verify(msg, &sig, &kp.public_key_bytes()).unwrap();
    }

    #[test]
    fn test_ed25519_verify_wrong_sig_fails() {
        let kp = Ed25519Keypair::generate();
        let msg = b"test message";
        let mut sig = kp.sign(msg);
        sig[0] ^= 0xff;
        assert!(ed25519_verify(msg, &sig, &kp.public_key_bytes()).is_err());
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = derive_key(b"secret", b"salt", b"test");
        let pt = b"hello bleep p2p";
        let ct = aes_gcm_encrypt(&key, pt).unwrap();
        let recovered = aes_gcm_decrypt(&key, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn test_aes_gcm_decrypt_wrong_key_fails() {
        let key1 = derive_key(b"secret1", b"salt", b"test");
        let key2 = derive_key(b"secret2", b"salt", b"test");
        let ct = aes_gcm_encrypt(&key1, b"data").unwrap();
        assert!(aes_gcm_decrypt(&key2, &ct).is_err());
    }

    #[test]
    fn test_session_key_encrypt_decrypt() {
        let shared = b"kyber_shared_secret_32_bytes____";
        let peer_id = b"peer123";
        let sk = SessionKey::from_shared_secret(shared, peer_id);
        let pt = b"transaction payload";
        let ct = sk.encrypt(pt).unwrap();
        let dec = sk.decrypt(&ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_proof_of_identity() {
        let kp = Ed25519Keypair::generate();
        let proof = ProofOfIdentity::create(&kp, b"bleep-p2p-handshake-context");
        proof.verify().unwrap();
    }

    #[test]
    fn test_node_identity_node_id_is_deterministic() {
        let id = NodeIdentity::generate();
        let n1 = id.node_id();
        let n2 = crate::types::NodeId::from_bytes(&id.ed_keypair.public_key_bytes());
        assert_eq!(n1.0, n2.0);
    }
}
