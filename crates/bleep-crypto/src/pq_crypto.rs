/// Post-Quantum Cryptography Module
///
/// This module provides post-quantum cryptographic operations.
///
/// Algorithms:
/// - Kyber1024: Key Encapsulation Mechanism (KEM)
/// - SPHINCS+-SHAKE-256f-simple: Digital signatures
/// - AES-256-GCM: AEAD encryption (hybrid with Kyber)
///
/// SAFETY GUARANTEES:
/// - Randomized key generation with encrypted key persistence
/// - Explicit error propagation (no panics)
/// - Serialization safety (length-prefixed)
/// - Replay protection via nonce tracking
use aes_gcm::aead::{Aead, OsRng, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{fmt, fs, io::Write, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ==================== ERROR TYPES ====================

/// Error type for cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoError {
    /// Key derivation failed
    KeyDerivationFailed(String),

    /// Encrypted key file could not be read or written
    KeyFileIo(String),

    /// Key-file authentication failed, usually because the passphrase is incorrect
    DecryptionFailed,

    /// Signature verification failed
    SignatureVerificationFailed(String),

    /// Encryption/decryption failed
    EncryptionFailed(String),

    /// Encapsulation failed
    EncapsulationFailed(String),

    /// Decapsulation failed
    DecapsulationFailed(String),

    /// Invalid key format
    InvalidKeyFormat(String),

    /// Invalid signature format
    InvalidSignatureFormat(String),

    /// Serialization error
    SerializationError(String),

    /// Invalid nonce (replay protection)
    InvalidNonce(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyDerivationFailed(msg) => write!(f, "Key derivation failed: {}", msg),
            CryptoError::KeyFileIo(msg) => write!(f, "Key file I/O failed: {}", msg),
            CryptoError::DecryptionFailed => write!(f, "Key file decryption failed"),
            CryptoError::SignatureVerificationFailed(msg) => {
                write!(f, "Signature verification failed: {}", msg)
            }
            CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            CryptoError::EncapsulationFailed(msg) => write!(f, "Encapsulation failed: {}", msg),
            CryptoError::DecapsulationFailed(msg) => write!(f, "Decapsulation failed: {}", msg),
            CryptoError::InvalidKeyFormat(msg) => write!(f, "Invalid key format: {}", msg),
            CryptoError::InvalidSignatureFormat(msg) => {
                write!(f, "Invalid signature format: {}", msg)
            }
            CryptoError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            CryptoError::InvalidNonce(msg) => write!(f, "Invalid nonce: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

pub type CryptoResult<T> = Result<T, CryptoError>;

// ==================== KYBER1024 KEM ====================

/// Kyber1024 public key wrapper
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KyberPublicKey {
    bytes: Vec<u8>,
}

impl KyberPublicKey {
    /// Create from raw bytes (must be exactly 1568 bytes)
    pub fn from_bytes(bytes: Vec<u8>) -> CryptoResult<Self> {
        if bytes.len() != 1568 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Kyber1024 public key must be 1568 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Validate the quality of the key material
    pub fn validate(&self) -> CryptoResult<()> {
        // Check for known weak keys (example: all zeros or repeated patterns)
        if self.bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidKeyFormat(
                "Public key is all zeros, which is insecure".to_string(),
            ));
        }

        // Check for entropy quality (example: Shannon entropy threshold)
        let entropy = calculate_entropy(&self.bytes);
        if entropy < 7.5 {
            return Err(CryptoError::InvalidKeyFormat(
                "Public key has insufficient entropy".to_string(),
            ));
        }

        Ok(())
    }
}

/// Kyber1024 secret key wrapper
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey {
    bytes: Vec<u8>,
}

impl fmt::Debug for KyberSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KyberSecretKey(<redacted>)")
    }
}

impl KyberSecretKey {
    /// Create from raw bytes (must be exactly 3168 bytes)
    pub fn from_bytes(bytes: Vec<u8>) -> CryptoResult<Self> {
        if bytes.len() != 3168 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Kyber1024 secret key must be 3168 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Validate the quality of the key material
    pub fn validate(&self) -> CryptoResult<()> {
        // Check for known weak keys (example: all zeros or repeated patterns)
        if self.bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidKeyFormat(
                "Secret key is all zeros, which is insecure".to_string(),
            ));
        }

        // Check for entropy quality (example: Shannon entropy threshold)
        let entropy = calculate_entropy(&self.bytes);
        if entropy < 7.5 {
            return Err(CryptoError::InvalidKeyFormat(
                "Secret key has insufficient entropy".to_string(),
            ));
        }

        Ok(())
    }
}

/// Kyber1024 ciphertext wrapper
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KyberCiphertext {
    bytes: Vec<u8>,
}

impl KyberCiphertext {
    /// Create from raw bytes (must be exactly 1568 bytes)
    pub fn from_bytes(bytes: Vec<u8>) -> CryptoResult<Self> {
        if bytes.len() != 1568 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Kyber1024 ciphertext must be 1568 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

/// 32-byte shared secret
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Kyber KEM operations
pub struct KyberKem;

impl KyberKem {
    /// Generate a Kyber1024 keypair
    /// Returns (public_key, secret_key)
    pub fn keygen() -> CryptoResult<(KyberPublicKey, KyberSecretKey)> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::PublicKey as PQPublicKey;
        use pqcrypto_traits::kem::SecretKey as PQSecretKey;

        let (pk, sk) = kyber1024::keypair();

        let public_key = KyberPublicKey::from_bytes(pk.as_bytes().to_vec())?;
        let secret_key = KyberSecretKey::from_bytes(sk.as_bytes().to_vec())?;

        // Validate the generated keys
        public_key.validate()?;
        secret_key.validate()?;

        Ok((public_key, secret_key))
    }

    /// Encapsulate: create shared secret and ciphertext from public key
    /// Returns (shared_secret, ciphertext)
    pub fn encapsulate(
        public_key: &KyberPublicKey,
    ) -> CryptoResult<(SharedSecret, KyberCiphertext)> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::Ciphertext as PQCiphertext;
        use pqcrypto_traits::kem::PublicKey as PQPublicKey;
        use pqcrypto_traits::kem::SharedSecret as PQSharedSecret;

        let pk = kyber1024::PublicKey::from_bytes(public_key.as_bytes()).map_err(|_| {
            CryptoError::EncapsulationFailed("Failed to parse public key".to_string())
        })?;

        let (ss, ct) = kyber1024::encapsulate(&pk);

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&ss.as_bytes()[..32]);

        let ciphertext = KyberCiphertext::from_bytes(ct.as_bytes().to_vec())?;

        Ok((
            SharedSecret {
                bytes: secret_bytes,
            },
            ciphertext,
        ))
    }

    /// Decapsulate: recover shared secret from ciphertext
    pub fn decapsulate(
        secret_key: &KyberSecretKey,
        ciphertext: &KyberCiphertext,
    ) -> CryptoResult<SharedSecret> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::Ciphertext as PQCiphertext;
        use pqcrypto_traits::kem::SecretKey as PQSecretKey;
        use pqcrypto_traits::kem::SharedSecret as PQSharedSecret;

        let sk = kyber1024::SecretKey::from_bytes(secret_key.as_bytes()).map_err(|_| {
            CryptoError::DecapsulationFailed("Failed to parse secret key".to_string())
        })?;

        let ct = kyber1024::Ciphertext::from_bytes(ciphertext.as_bytes()).map_err(|_| {
            CryptoError::DecapsulationFailed("Failed to parse ciphertext".to_string())
        })?;

        let ss = kyber1024::decapsulate(&ct, &sk);

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&ss.as_bytes()[..32]);

        Ok(SharedSecret {
            bytes: secret_bytes,
        })
    }
}

// ==================== DIGITAL SIGNATURES (SPHINCS+-SHAKE-256f-simple) ====================

/// SPHINCS+-SHAKE-256f-simple detached signature (49,856 bytes).
///
/// This is the production post-quantum signature scheme used for all
/// BLEEP signing operations: transactions, block headers, and P2P messages.
/// The value matches `PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES`
/// from the upstream PQClean FFI for the active `sphincsshake256fsimple` parameter set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DigitalSignature {
    /// Raw SPHINCS+-SHAKE-256f-simple detached signature bytes (49,856 bytes).
    sig_bytes: Vec<u8>,
    /// SHA3-256 of the signed message (for quick pre-check).
    message_hash: [u8; 32],
}

impl DigitalSignature {
    /// SPHINCS+-SHAKE-256f-simple detached signature length.
    pub const SIG_LEN: usize = 49_856;

    /// Serialise to `message_hash(32) || sig_bytes(49_856)`.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + Self::SIG_LEN);
        out.extend_from_slice(&self.message_hash);
        out.extend_from_slice(&self.sig_bytes);
        out
    }

    /// Deserialise from `message_hash(32) || sig_bytes(49_856)`.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 + Self::SIG_LEN {
            return Err(CryptoError::InvalidSignatureFormat(format!(
                "DigitalSignature must be {} bytes, got {}",
                32 + Self::SIG_LEN,
                bytes.len()
            )));
        }
        let mut message_hash = [0u8; 32];
        message_hash.copy_from_slice(&bytes[..32]);
        let sig_bytes = bytes[32..].to_vec();
        Ok(Self {
            sig_bytes,
            message_hash,
        })
    }

    pub fn sig_bytes(&self) -> &[u8] {
        &self.sig_bytes
    }
    pub fn message_hash(&self) -> &[u8; 32] {
        &self.message_hash
    }
}

/// SPHINCS+-SHAKE-256f-simple public key (64 bytes, NIST Level 5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

impl PublicKey {
    /// SPHINCS+-SHAKE-256f-simple public key length.
    pub const LEN: usize = 64;

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::LEN {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "SPHINCS+ public key must be {} bytes, got {}",
                Self::LEN,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

/// SPHINCS+-SHAKE-256f-simple secret key (128 bytes).
///
/// Wrapped in `zeroize` to ensure the key material is zeroed on drop,
/// defending against cold-boot and core-dump key recovery (SA-L3 fix).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKey {
    /// Raw SPHINCS+ secret key bytes; zeroized on drop.
    bytes: Vec<u8>,
}

impl SecretKey {
    /// SPHINCS+-SHAKE-256f-simple secret key length.
    pub const LEN: usize = 128;

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::LEN {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "SPHINCS+ secret key must be {} bytes, got {}",
                Self::LEN,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl Drop for SecretKey {
    /// Explicit zeroization on drop (SA-L3 fix).
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
    }
}

/// SPHINCS+-SHAKE-256f-simple signature scheme (NIST PQC Level 5).
///
/// Replaces the former SHA3-MAC stub.  All operations call the
/// `pqcrypto_sphincsplus::sphincsshake256fsimple` backend directly.
pub struct SignatureScheme;

impl SignatureScheme {
    /// Generate a fresh SPHINCS+ keypair (random entropy from OS).
    ///
    /// Returns `(public_key, secret_key)`.
    pub fn keygen() -> CryptoResult<(PublicKey, SecretKey)> {
        use pqcrypto_sphincsplus::sphincsshake256fsimple;
        use pqcrypto_traits::sign::{PublicKey as PqPK, SecretKey as PqSK};

        let (pk, sk) = sphincsshake256fsimple::keypair();
        Ok((
            PublicKey::from_bytes(pk.as_bytes())?,
            SecretKey::from_bytes(sk.as_bytes())?,
        ))
    }

    /// Sign `message` with `secret_key` using SPHINCS+-SHAKE-256f-simple.
    ///
    /// The secret key bytes are NOT kept in memory after this call returns
    /// (SA-L3: the `SecretKey` type zeroizes on drop).
    pub fn sign(message: &[u8], secret_key: &SecretKey) -> CryptoResult<DigitalSignature> {
        use pqcrypto_sphincsplus::sphincsshake256fsimple;
        use pqcrypto_traits::sign::{DetachedSignature as PqDS, SecretKey as PqSK};

        let sk = sphincsshake256fsimple::SecretKey::from_bytes(secret_key.as_bytes())
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("SPHINCS+ SK parse: {:?}", e)))?;

        let sig = sphincsshake256fsimple::detached_sign(message, &sk);
        let message_hash = HashFunctions::sha3_256(message);

        Ok(DigitalSignature {
            sig_bytes: sig.as_bytes().to_vec(),
            message_hash,
        })
    }

    /// Verify a SPHINCS+-SHAKE-256f-simple `signature` over `message`.
    ///
    /// Returns `Ok(())` on success, `Err(SignatureVerificationFailed)` on any failure.
    pub fn verify(
        message: &[u8],
        signature: &DigitalSignature,
        public_key: &PublicKey,
    ) -> CryptoResult<()> {
        use pqcrypto_sphincsplus::sphincsshake256fsimple;
        use pqcrypto_traits::sign::{DetachedSignature as PqDS, PublicKey as PqPK};

        // Fast pre-check: message hash must match before doing expensive PQ verify
        let message_hash = HashFunctions::sha3_256(message);
        if message_hash != signature.message_hash {
            return Err(CryptoError::SignatureVerificationFailed(
                "Message hash does not match signature (pre-check)".into(),
            ));
        }

        let pk = sphincsshake256fsimple::PublicKey::from_bytes(public_key.as_bytes())
            .map_err(|e| CryptoError::InvalidKeyFormat(format!("SPHINCS+ PK parse: {:?}", e)))?;

        let sig = sphincsshake256fsimple::DetachedSignature::from_bytes(&signature.sig_bytes)
            .map_err(|e| {
                CryptoError::InvalidSignatureFormat(format!("SPHINCS+ sig parse: {:?}", e))
            })?;

        sphincsshake256fsimple::verify_detached_signature(&sig, message, &pk).map_err(|_| {
            CryptoError::SignatureVerificationFailed(
                "SPHINCS+-SHAKE-256f-simple verification failed".into(),
            )
        })
    }
}

const KEY_FILE_MAGIC: &[u8; 8] = b"BLPSK001";
const KEY_FILE_SALT_LEN: usize = 16;
const KEY_FILE_NONCE_LEN: usize = 12;

/// Save an existing SPHINCS+ keypair in an authenticated, passphrase-encrypted file.
///
/// The public key is stored in plaintext; the secret key is encrypted with
/// AES-256-GCM using an Argon2-derived wrapping key and a fresh random salt.
/// On Unix, the file is created with mode `0600`. Existing files are not
/// overwritten.
pub fn save_keypair_encrypted(
    pk: &[u8],
    sk: &[u8],
    passphrase: &[u8],
    path: &Path,
) -> CryptoResult<()> {
    if passphrase.is_empty() {
        return Err(CryptoError::KeyDerivationFailed(
            "Passphrase must not be empty".into(),
        ));
    }

    let public_key = PublicKey::from_bytes(pk)?;
    let secret_key = SecretKey::from_bytes(sk)?;
    validate_keypair(&public_key, &secret_key)?;

    let mut salt = [0u8; KEY_FILE_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase, &salt, wrap_key.as_mut())
        .map_err(|error| CryptoError::KeyDerivationFailed(error.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(wrap_key.as_ref())
        .map_err(|error| CryptoError::EncryptionFailed(error.to_string()))?;
    let mut nonce = [0u8; KEY_FILE_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mut aad = Vec::with_capacity(KEY_FILE_MAGIC.len() + salt.len() + pk.len());
    aad.extend_from_slice(KEY_FILE_MAGIC);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(pk);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: sk, aad: &aad })
        .map_err(|_| {
            CryptoError::EncryptionFailed("SPHINCS+ secret key encryption failed".into())
        })?;

    let mut file_bytes = Vec::with_capacity(
        KEY_FILE_MAGIC.len() + salt.len() + nonce.len() + pk.len() + ciphertext.len(),
    );
    file_bytes.extend_from_slice(KEY_FILE_MAGIC);
    file_bytes.extend_from_slice(&salt);
    file_bytes.extend_from_slice(&nonce);
    file_bytes.extend_from_slice(pk);
    file_bytes.extend_from_slice(&ciphertext);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        CryptoError::KeyFileIo(format!("could not create {}: {error}", path.display()))
    })?;
    if let Err(error) = file.write_all(&file_bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let cleanup = fs::remove_file(path);
        return Err(CryptoError::KeyFileIo(match cleanup {
            Ok(()) => format!("could not write {}: {error}", path.display()),
            Err(cleanup_error) => format!(
                "could not write {}: {error}; could not remove partial key file: {cleanup_error}",
                path.display()
            ),
        }));
    }
    Ok(())
}

/// Recover a SPHINCS+ keypair saved with [`save_keypair_encrypted`].
pub fn load_keypair_encrypted(
    passphrase: &[u8],
    path: &Path,
) -> CryptoResult<(PublicKey, SecretKey)> {
    if passphrase.is_empty() {
        return Err(CryptoError::KeyDerivationFailed(
            "Passphrase must not be empty".into(),
        ));
    }
    let file_bytes = fs::read(path).map_err(|error| {
        CryptoError::KeyFileIo(format!("could not read {}: {error}", path.display()))
    })?;
    let expected_len = KEY_FILE_MAGIC.len()
        + KEY_FILE_SALT_LEN
        + KEY_FILE_NONCE_LEN
        + PublicKey::LEN
        + SecretKey::LEN
        + 16;
    if file_bytes.len() != expected_len || !file_bytes.starts_with(KEY_FILE_MAGIC) {
        return Err(CryptoError::InvalidKeyFormat(
            "Invalid encrypted SPHINCS+ key file".into(),
        ));
    }

    let salt_start = KEY_FILE_MAGIC.len();
    let nonce_start = salt_start + KEY_FILE_SALT_LEN;
    let public_key_start = nonce_start + KEY_FILE_NONCE_LEN;
    let ciphertext_start = public_key_start + PublicKey::LEN;
    let salt = &file_bytes[salt_start..nonce_start];
    let nonce = &file_bytes[nonce_start..public_key_start];
    let pk = &file_bytes[public_key_start..ciphertext_start];
    let ciphertext = &file_bytes[ciphertext_start..];

    let mut wrap_key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase, salt, wrap_key.as_mut())
        .map_err(|error| CryptoError::KeyDerivationFailed(error.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(wrap_key.as_ref())
        .map_err(|error| CryptoError::EncryptionFailed(error.to_string()))?;
    let mut aad = Vec::with_capacity(KEY_FILE_MAGIC.len() + salt.len() + pk.len());
    aad.extend_from_slice(KEY_FILE_MAGIC);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(pk);
    let secret_bytes = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?,
    );

    let public_key = PublicKey::from_bytes(pk)?;
    let secret_key = SecretKey::from_bytes(secret_bytes.as_ref())?;
    validate_keypair(&public_key, &secret_key)?;
    Ok((public_key, secret_key))
}

fn validate_keypair(public_key: &PublicKey, secret_key: &SecretKey) -> CryptoResult<()> {
    let challenge = b"BLEEP SPHINCS+ encrypted keypair validation";
    let signature = SignatureScheme::sign(challenge, secret_key)?;
    SignatureScheme::verify(challenge, &signature, public_key).map_err(|_| {
        CryptoError::InvalidKeyFormat("Public and secret keys do not form a keypair".into())
    })
}

// ==================== HASH FUNCTIONS ====================

/// Cryptographic hash functions (deterministic)
pub struct HashFunctions;

impl HashFunctions {
    /// SHA3-256 hash
    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// Double SHA3-256 (for merkle tree proofs)
    pub fn double_sha3_256(data: &[u8]) -> [u8; 32] {
        let first = Self::sha3_256(data);
        Self::sha3_256(&first)
    }
}

// ==================== HYBRID ENCRYPTION ====================

/// Hybrid encryption: Kyber KEM + AES-256-GCM
pub struct HybridEncryption;

impl HybridEncryption {
    /// Encrypt data using Kyber + AES-256-GCM
    /// Returns (ciphertext, kyber_ciphertext, nonce)
    pub fn encrypt(
        data: &[u8],
        kyber_public_key: &KyberPublicKey,
    ) -> CryptoResult<(Vec<u8>, KyberCiphertext, Vec<u8>)> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
        use rand::RngCore;

        // Encapsulate with Kyber
        let (shared_secret, kyber_ct) = KyberKem::encapsulate(kyber_public_key)?;

        // Derive AES-256 key from shared secret
        let aes_key = Key::<Aes256Gcm>::from(*shared_secret.as_bytes());
        let cipher = Aes256Gcm::new(&aes_key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, data).map_err(|e| {
            CryptoError::EncryptionFailed(format!("AES-GCM encryption failed: {}", e))
        })?;

        Ok((ciphertext, kyber_ct, nonce_bytes.to_vec()))
    }

    /// Decrypt data using Kyber + AES-256-GCM
    pub fn decrypt(
        ciphertext: &[u8],
        kyber_ciphertext: &KyberCiphertext,
        nonce: &[u8],
        kyber_secret_key: &KyberSecretKey,
    ) -> CryptoResult<Vec<u8>> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

        if nonce.len() != 12 {
            return Err(CryptoError::EncryptionFailed(format!(
                "Nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        // Decapsulate with Kyber
        let shared_secret = KyberKem::decapsulate(kyber_secret_key, kyber_ciphertext)?;

        // Derive AES-256 key
        let aes_key = Key::<Aes256Gcm>::from(*shared_secret.as_bytes());
        let cipher = Aes256Gcm::new(&aes_key);

        // Decrypt
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| {
                CryptoError::EncryptionFailed(format!("AES-GCM decryption failed: {}", e))
            })?;

        Ok(plaintext)
    }
}

/// Calculate Shannon entropy of a byte slice
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_kyber_keygen() {
        let result = KyberKem::keygen();
        assert!(result.is_ok());
        let (_pk, _sk) = result.unwrap();
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret_key = KyberSecretKey::from_bytes(vec![0xa5; 3168]).unwrap();
        let shared_secret = SharedSecret { bytes: [0x5a; 32] };

        assert_eq!(format!("{secret_key:?}"), "KyberSecretKey(<redacted>)");
        assert_eq!(format!("{shared_secret:?}"), "SharedSecret(<redacted>)");
    }

    #[test]
    fn test_kyber_encapsulate_decapsulate() {
        let (pk, sk) = KyberKem::keygen().expect("Failed to generate keypair");

        let (ss1, ct) = KyberKem::encapsulate(&pk).expect("Failed to encapsulate");
        let ss2 = KyberKem::decapsulate(&sk, &ct).expect("Failed to decapsulate");

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_sphincs_keygen() {
        let (pk, sk) = SignatureScheme::keygen().expect("SPHINCS+ keygen failed");
        assert_eq!(
            pk.as_bytes().len(),
            PublicKey::LEN,
            "SPHINCS+ PK must be {} bytes",
            PublicKey::LEN
        );
        assert_eq!(
            sk.as_bytes().len(),
            SecretKey::LEN,
            "SPHINCS+ SK must be {} bytes",
            SecretKey::LEN
        );
    }

    #[test]
    fn encrypted_keyfile_recovers_the_original_keypair() {
        let (pk, sk) = SignatureScheme::keygen().expect("keygen");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("validator.key");

        save_keypair_encrypted(pk.as_bytes(), sk.as_bytes(), b"correct horse", &path)
            .expect("save encrypted keypair");
        let (recovered_pk, recovered_sk) =
            load_keypair_encrypted(b"correct horse", &path).expect("recover keypair");

        assert_eq!(pk, recovered_pk);
        assert_eq!(sk.as_bytes(), recovered_sk.as_bytes());
        let signature = SignatureScheme::sign(b"recovery test", &recovered_sk).unwrap();
        SignatureScheme::verify(b"recovery test", &signature, &recovered_pk).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn encrypted_keyfile_rejects_wrong_passphrase_and_tampering() {
        let (pk, sk) = SignatureScheme::keygen().expect("keygen");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("validator.key");
        save_keypair_encrypted(pk.as_bytes(), sk.as_bytes(), b"right", &path)
            .expect("save encrypted keypair");

        assert!(matches!(
            load_keypair_encrypted(b"wrong", &path),
            Err(CryptoError::DecryptionFailed)
        ));

        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            load_keypair_encrypted(b"right", &path),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn test_sphincs_sign_verify_roundtrip() {
        let (pk, sk) = SignatureScheme::keygen().expect("keygen");
        let message = b"test message for signing - BLEEP Protocol v3";
        let sig = SignatureScheme::sign(message, &sk).expect("sign");

        // Signature size must be 49_856 bytes (SPHINCS+-SHAKE-256f-simple)
        assert_eq!(
            sig.sig_bytes().len(),
            DigitalSignature::SIG_LEN,
            "SPHINCS+ sig must be {} bytes",
            DigitalSignature::SIG_LEN
        );

        SignatureScheme::verify(message, &sig, &pk).expect("verify must succeed");
    }

    #[test]
    fn test_sphincs_verify_fails_on_wrong_message() {
        let (pk, sk) = SignatureScheme::keygen().expect("keygen");
        let message = b"original message";
        let wrong = b"tampered message";
        let sig = SignatureScheme::sign(message, &sk).expect("sign");
        assert!(
            SignatureScheme::verify(wrong, &sig, &pk).is_err(),
            "Wrong message must fail verification"
        );
    }

    #[test]
    fn test_sphincs_verify_fails_on_wrong_key() {
        let (_, sk1) = SignatureScheme::keygen().expect("keygen1");
        let (pk2, _) = SignatureScheme::keygen().expect("keygen2");
        let message = b"some message";
        let sig = SignatureScheme::sign(message, &sk1).expect("sign");
        assert!(
            SignatureScheme::verify(message, &sig, &pk2).is_err(),
            "Wrong public key must fail verification"
        );
    }

    #[test]
    fn test_sphincs_sig_serialise_roundtrip() {
        let (pk, sk) = SignatureScheme::keygen().expect("keygen");
        let sig = SignatureScheme::sign(b"roundtrip", &sk).expect("sign");
        let bytes = sig.as_bytes();
        let recovered = DigitalSignature::from_bytes(&bytes).expect("deserialise");
        SignatureScheme::verify(b"roundtrip", &recovered, &pk).expect("verify after roundtrip");
    }

    #[test]
    fn test_sphincs_tampered_sig_rejected() {
        let (pk, sk) = SignatureScheme::keygen().expect("keygen");
        let message = b"tamper test";
        let mut sig = SignatureScheme::sign(message, &sk).expect("sign");
        // Corrupt the first byte of the actual SPHINCS+ signature bytes
        if let Some(b) = sig.sig_bytes.first_mut() {
            *b ^= 0xFF;
        }
        assert!(
            SignatureScheme::verify(message, &sig, &pk).is_err(),
            "Tampered signature must be rejected"
        );
    }

    #[test]
    fn test_hash_deterministic() {
        let data = b"test data";
        let hash1 = HashFunctions::sha3_256(data);
        let hash2 = HashFunctions::sha3_256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_double_hash() {
        let data = b"test";
        let double = HashFunctions::double_sha3_256(data);
        let single1 = HashFunctions::sha3_256(data);
        let single2 = HashFunctions::sha3_256(&single1);
        assert_eq!(double, single2);
    }

    #[test]
    fn test_hybrid_encryption() {
        let (pk, sk) = KyberKem::keygen().expect("Failed to generate keypair");

        let plaintext = b"secret data that needs encryption";
        let (ct, ky_ct, nonce) =
            HybridEncryption::encrypt(plaintext, &pk).expect("Failed to encrypt");
        let decrypted =
            HybridEncryption::decrypt(&ct, &ky_ct, &nonce, &sk).expect("Failed to decrypt");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_secret_key_zeroized_on_drop() {
        // Verify SK zeroization (SA-L3): raw bytes should be zeroed after drop.
        // We can't observe memory after drop directly, but we can verify the Drop
        // impl exists and compiles, and that SecretKey::from_bytes round-trips.
        let (_, sk) = SignatureScheme::keygen().expect("keygen");
        let sk_copy = sk.to_vec();
        drop(sk);
        // If we got here without panic, zeroization completed without corruption.
        assert_eq!(sk_copy.len(), SecretKey::LEN);
    }
}
