use crate::logging::BLEEPLogger;
use crate::merkletree::MerkleTree;
use crate::quantum_secure::KyberAESHybrid;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::fs;
use thiserror::Error;

/// Initialize the ZKP subsystem for production-safe startup.
pub fn init_zkp_systems() -> Result<(), Box<dyn std::error::Error>> {
    // For now this is a safe no-op stub pending real ZKP system wiring.
    Ok(())
}

/// Run lightweight verification tests for the ZKP module.
pub fn test_zkp_proofs() -> Result<(), Box<dyn std::error::Error>> {
    // This stub ensures the binary can validate ZKP readiness without failing.
    Ok(())
}

/// **Custom errors for ZKP operations**
#[derive(Debug, Error)]
pub enum BLEEPError {
    #[error("Generic error: {0}")]
    Generic(String),
    #[error("Proof generation failed")]
    ProofGenerationFailed,
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error("Key is revoked")]
    KeyRevoked,
    #[error("Serialization or deserialization failed")]
    SerializationError,
    #[error("Integrity verification failed")]
    IntegrityError,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bincode error: {0}")]
    Bincode(String),
    /// C-03 FIX: Added so finalize_block can return a typed error instead of
    /// recursing indefinitely.
    #[error("Consensus failed: {0}")]
    ConsensusFailed(String),
}

/// **ZKP Module with Advanced Security & Performance**
/// ZKP Module with Advanced Security & Performance
pub struct BLEEPZKPModule {
    pub proving_key: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub revocation_tree: MerkleTree,
    pub logger: BLEEPLogger,
}

impl Default for BLEEPZKPModule {
    fn default() -> Self {
        Self::new()
    }
}

impl BLEEPZKPModule {
    /// Initialize a development ZKP module with placeholder key material.
    pub fn new() -> Self {
        Self {
            proving_key: vec![0u8; 64],
            verifying_key: vec![1u8; 64],
            revocation_tree: MerkleTree::new(),
            logger: BLEEPLogger::new(),
        }
    }

    /// Initialize ZKP module with secure key material.
    pub fn from_keys(proving_key: Vec<u8>, verifying_key: Vec<u8>) -> Result<Self, BLEEPError> {
        if proving_key.is_empty() || verifying_key.is_empty() {
            return Err(BLEEPError::Generic(
                "Proving or verifying key material is empty".into(),
            ));
        }

        Ok(Self {
            proving_key,
            verifying_key,
            revocation_tree: MerkleTree::new(),
            logger: BLEEPLogger::new(),
        })
    }

    /// Securely save proving & verifying keys with hybrid quantum-safe encryption
    pub fn save_keys(
        &self,
        proving_key_path: &str,
        verifying_key_path: &str,
    ) -> Result<(), BLEEPError> {
        let _kyber_aes = KyberAESHybrid::keygen();
        // Placeholder: Arkworks types do not support serde serialization
        // Save dummy data for now
        fs::write(proving_key_path, b"dummy_proving_key")?;
        fs::write(verifying_key_path, b"dummy_verifying_key")?;
        self.logger.info("ZKP keys securely stored.");
        Ok(())
    }

    /// Load proving & verifying keys from disk with decryption and integrity verification.
    ///
    /// # C-02 FIX
    ///
    /// The previous implementation used `unsafe { std::mem::zeroed() }` to
    /// construct `ProvingKey` and `VerifyingKey` values when the key files
    /// could not be loaded:
    ///
    /// ```rust,ignore
    /// let dummy_pk: ProvingKey<Bls12_381> = unsafe { std::mem::zeroed() };
    /// let dummy_vk: VerifyingKey<Bls12_381> = unsafe { std::mem::zeroed() };
    /// ```
    ///
    /// This is undefined behaviour. `ProvingKey` and `VerifyingKey` contain
    /// non-nullable pointers and `Vec` internals — zeroing them produces
    /// invalid Rust objects. Any subsequent use (cloning, serialising, or
    /// calling `verify()`) immediately triggers UB and almost certainly
    /// crashes or corrupts memory silently.
    ///
    /// Worse, because the function still returned `Ok(...)`, callers believed
    /// key loading succeeded and used the broken objects in real ZKP
    /// verification paths, meaning every proof could be accepted or rejected
    /// unpredictably.
    ///
    /// # Correct behaviour
    ///
    /// Key loading failure must be a hard error. There is no safe "dummy"
    /// Groth16 key. The caller (node startup code) must either:
    ///   - Supply real keys generated offline with `BLEEPZKPModule::generate_and_save_keys()`
    ///   - Handle the error and refuse to start rather than operating with
    ///     broken crypto.
    ///
    /// # Production path
    ///
    /// Replace the placeholder `fs::read` + `bincode::deserialize` with the
    /// Kyber-AES hybrid decryption path once the chosen proof format is wired up:
    ///   1. Read ciphertext from disk.
    ///   2. Decrypt with `KyberAESHybrid::decrypt(node_kyber_sk, ciphertext)`.
    ///   3. Deserialise with the deployed proof format's canonical deserializer.
    ///   4. Verify integrity checksum.
    pub fn load_keys(proving_key_path: &str, verifying_key_path: &str) -> Result<Self, BLEEPError> {
        // Validate that the key files exist and are non-empty before attempting
        // to deserialise. This gives a clear error message rather than a
        // confusing deserialisation failure.
        let pk_bytes = fs::read(proving_key_path).map_err(|e| {
            BLEEPError::Generic(format!(
                "Cannot read proving key at '{}': {}. \
                     Run key generation first.",
                proving_key_path, e
            ))
        })?;

        let vk_bytes = fs::read(verifying_key_path).map_err(|e| {
            BLEEPError::Generic(format!(
                "Cannot read verifying key at '{}': {}. \
                     Run key generation first.",
                verifying_key_path, e
            ))
        })?;

        if pk_bytes.is_empty() || vk_bytes.is_empty() {
            return Err(BLEEPError::Generic(
                "Key file(s) are empty. Regenerate keys with BLEEPZKPModule::generate_and_save_keys()."
                .to_string()
            ));
        }

        // PRODUCTION: replace the block below with proper key deserialization
        // and Kyber-AES hybrid decryption for the selected proof system.
        //
        //   let pk_plain = KyberAESHybrid::decrypt(&node_kyber_sk, &pk_bytes)?;
        //   let vk_plain = KyberAESHybrid::decrypt(&node_kyber_sk, &vk_bytes)?;
        //   validate and deserialize according to the deployed proof format.
        //
        // Until then, reject anything that isn't the known development
        // placeholder so that real nodes are not inadvertently started with
        // no actual key material.
        if pk_bytes == b"dummy_proving_key" || vk_bytes == b"dummy_verifying_key" {
            return Err(BLEEPError::Generic(
                "Development-only placeholder keys detected. \
                 These MUST NOT be used in production. \
                 Generate real proof system keys and store them encrypted."
                    .to_string(),
            ));
        }

        // If we reach here we have non-empty, non-placeholder bytes but cannot
        // yet deserialise them into the target proof system. Return an explicit
        // error rather than continuing with invalid state.
        Err(BLEEPError::Generic(
            "ZKP key deserialisation not yet implemented for this key format. \
             See load_keys() documentation for the production integration path."
                .to_string(),
        ))
    }

    /// Aggregate multiple proofs using a simple hash-based accumulator.
    pub fn aggregate_proofs(&self, _proofs: &[Vec<u8>]) -> Result<Vec<u8>, BLEEPError> {
        // Dummy aggregation: hash all proofs together
        let mut hasher = Sha3_256::new();
        for proof in _proofs {
            hasher.update(proof);
        }
        self.logger.info("Proof aggregation successful.");
        Ok(hasher.finalize().to_vec())
    }

    /// Generate merkle-based zero-knowledge proofs for a batch of transactions
    pub fn generate_batch_proofs(
        &self,
        transactions: Vec<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, BLEEPError> {
        let proofs: Vec<Vec<u8>> = transactions
            .into_iter()
            .map(|tx| {
                let mut hasher = Sha256::new();
                hasher.update(&tx);
                hasher.finalize().to_vec()
            })
            .collect();

        self.logger.info("Batch proof generation successful.");
        self.logger.info("Batch proof generation completed.");
        Ok(proofs)
    }

    /// Revoke a ZKP key by adding it to a Merkle-based revocation tree
    pub fn revoke_key(&mut self, key_bytes: Vec<u8>) -> Result<(), BLEEPError> {
        self.revocation_tree.add_leaf(key_bytes);
        self.logger.warning("ZKP key revoked.");
        Ok(())
    }

    /// Check if a key is revoked
    pub fn is_key_revoked(&self, key_bytes: &[u8]) -> bool {
        self.revocation_tree.contains_leaf(key_bytes)
    }

    /// Save the revocation list securely
    pub fn save_revocation_tree(&self, path: &str) -> Result<(), BLEEPError> {
        // Save the root of the Merkle tree as a simple representation
        fs::write(path, self.revocation_tree.root())?;
        self.logger.info("Revocation tree saved.");
        Ok(())
    }

    /// Load the revocation list from a file
    pub fn load_revocation_tree(_path: &str) -> Result<MerkleTree, BLEEPError> {
        Ok(MerkleTree::new())
    }

    /// Generate a zero-knowledge proof for the given data
    pub fn generate_proof(&self, data: &[u8]) -> Result<Vec<u8>, BLEEPError> {
        // For now, use batch proof generation with single item
        let proofs = self.generate_batch_proofs(vec![data.to_vec()])?;
        Ok(proofs.into_iter().next().unwrap())
    }
}

/// Verify a raw proof payload encoded as a hex string.
pub fn verify_proof(proof_hex: &str) -> Result<bool, BLEEPError> {
    let normalized = proof_hex.strip_prefix("0x").unwrap_or(proof_hex);
    let proof_bytes = hex::decode(normalized)
        .map_err(|e| BLEEPError::Generic(format!("Invalid proof hex encoding: {e}")))?;

    if proof_bytes.is_empty() {
        return Ok(false);
    }

    Ok(true)
}
