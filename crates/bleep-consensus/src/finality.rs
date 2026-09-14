// PHASE 1: FINALITY PROOFS & CERTIFICATES
// Cryptographic proofs that a block is irreversibly finalized
//
// SAFETY INVARIANTS:
// 1. A finalized block's hash cannot change
// 2. Finality proofs are cryptographically verifiable
// 3. Finality implies Byzantine-fault-tolerance (cannot be reverted with <1/3 attackers)
// 4. Proofs are deterministic (same input → same proof)
// 5. Proofs can be stored on-chain or in light client proofs

use blst::{
    min_sig::{PublicKey, Signature},
    BLST_ERROR,
};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(test)]
use blst::min_sig::{AggregateSignature, SecretKey};

#[cfg(test)]
use rand::rngs::OsRng;

#[cfg(test)]
use rand::RngCore;

const BLS_DST: &[u8] = b"BLEEP-BLS-AGGREGATE-SIG";

#[cfg(test)]
#[allow(dead_code)]
fn generate_bls_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut ikm = [0u8; 32];
    OsRng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).map_err(|_| "BLS key generation failed".to_string())?;
    let pk = sk.sk_to_pk();
    Ok((pk.to_bytes().to_vec(), sk.to_bytes().to_vec()))
}

#[cfg(test)]
#[allow(dead_code)]
fn bls_sign(message: &[u8], secret_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let sk = SecretKey::from_bytes(secret_key_bytes)
        .map_err(|_| "Invalid BLS secret key".to_string())?;
    let signature = sk.sign(message, BLS_DST, &[]);
    Ok(signature.to_bytes().to_vec())
}

#[cfg(test)]
#[allow(dead_code)]
fn aggregate_bls_signatures(signatures: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    // Parse individual signatures
    let mut sig_objs: Vec<Signature> = Vec::with_capacity(signatures.len());
    for signature_bytes in signatures {
        let sig = Signature::from_bytes(signature_bytes)
            .map_err(|_| "Invalid BLS signature bytes".to_string())?;
        sig_objs.push(sig);
    }

    // Build slice of references for aggregation API
    let sig_refs: Vec<&Signature> = sig_objs.iter().collect();

    // Aggregate signatures using the crate API
    let agg = AggregateSignature::aggregate(&sig_refs, true)
        .map_err(|e| format!("BLS signature aggregation failed: {:?}", e))?;

    // Convert aggregated object to a single Signature and serialize
    let signature = Signature::from_aggregate(&agg);
    Ok(signature.to_bytes().to_vec())
}

fn verify_bls_aggregate_signature(
    message: &[u8],
    aggregate_signature: &[u8],
    public_keys: &[Vec<u8>],
) -> Result<(), String> {
    let signature = Signature::from_bytes(aggregate_signature)
        .map_err(|_| "Invalid aggregate BLS signature".to_string())?;

    let mut pks = Vec::with_capacity(public_keys.len());
    for pk_bytes in public_keys {
        let pk =
            PublicKey::from_bytes(pk_bytes).map_err(|_| "Invalid BLS public key".to_string())?;
        pks.push(pk);
    }

    // Build slice of references for verification API
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();

    let err = signature.fast_aggregate_verify(true, message, BLS_DST, &pk_refs);
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(format!("BLS aggregate verification failed: {:?}", err));
    }
    Ok(())
}

/// A finality certificate: cryptographic proof that a block is finalized.
///
/// SAFETY: This certificate can be verified by any node in the network
/// and proves that a block has been finalized under consensus rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizyCertificate {
    /// Block height that was finalized
    pub block_height: u64,

    /// Hash of the finalized block (immutable)
    pub block_hash: String,

    /// Epoch during which block was finalized
    pub finalized_epoch: u64,

    /// Consensus mode used to finalize this block
    pub consensus_mode: String,

    /// List of validator IDs that participated in finalization.
    /// In the legacy path, each item carries a per-validator signature.
    pub validator_signatures: Vec<ValidatorSignature>,

    /// Signer metadata for an aggregated finality proof.
    /// When `aggregate_signature` is used, this holds validator IDs, voting power and BLS public keys.
    pub aggregate_signers: Vec<AggregateSigner>,

    /// Aggregated signature from participating validators (optional BLS aggregation)
    pub aggregate_signature: Vec<u8>,

    /// Merkle root of all transactions in the block
    pub merkle_root: String,

    /// Timestamp when finality was achieved (seconds since epoch)
    pub finalized_timestamp: u64,

    /// Protocol version used
    pub protocol_version: u32,
}

impl FinalizyCertificate {
    /// Create a new finality certificate.
    pub fn new(
        block_height: u64,
        block_hash: String,
        finalized_epoch: u64,
        consensus_mode: String,
        merkle_root: String,
        finalized_timestamp: u64,
        protocol_version: u32,
    ) -> Result<Self, String> {
        if block_hash.is_empty() {
            return Err("block_hash cannot be empty".to_string());
        }
        if merkle_root.is_empty() {
            return Err("merkle_root cannot be empty".to_string());
        }

        Ok(FinalizyCertificate {
            block_height,
            block_hash,
            finalized_epoch,
            consensus_mode,
            validator_signatures: Vec::new(),
            aggregate_signers: Vec::new(),
            aggregate_signature: Vec::new(),
            merkle_root,
            finalized_timestamp,
            protocol_version,
        })
    }

    /// Add a validator's signature to this certificate.
    ///
    /// SAFETY: The same validator should only sign once.
    pub fn add_validator_signature(
        &mut self,
        validator_id: String,
        signature: Vec<u8>,
        voting_power: u128,
    ) -> Result<(), String> {
        if !self.aggregate_signature.is_empty() {
            return Err(
                "Cannot add individual validator signatures when an aggregate signature is set"
                    .to_string(),
            );
        }

        // Check for duplicates
        if self
            .validator_signatures
            .iter()
            .any(|s| s.validator_id == validator_id)
        {
            return Err(format!(
                "Validator {} already signed this certificate",
                validator_id
            ));
        }

        self.validator_signatures.push(ValidatorSignature {
            validator_id,
            signature,
            voting_power,
        });

        Ok(())
    }

    /// Set an aggregated finality proof using BLS aggregation.
    pub fn set_aggregate_signature(
        &mut self,
        aggregate_signers: Vec<AggregateSigner>,
        aggregate_signature: Vec<u8>,
    ) -> Result<(), String> {
        if !self.validator_signatures.is_empty() {
            return Err(
                "Cannot set aggregate signature when individual signatures are present".to_string(),
            );
        }
        if !self.aggregate_signature.is_empty() {
            return Err("Aggregate signature already set".to_string());
        }
        if aggregate_signers.is_empty() {
            return Err("Aggregate signers cannot be empty".to_string());
        }

        self.aggregate_signers = aggregate_signers;
        self.aggregate_signature = aggregate_signature;
        Ok(())
    }

    /// Get the total voting power of all signers.
    pub fn total_voting_power(&self) -> u128 {
        if !self.aggregate_signature.is_empty() {
            return self.aggregate_signers.iter().map(|s| s.voting_power).sum();
        }

        self.validator_signatures
            .iter()
            .map(|s| s.voting_power)
            .sum()
    }

    /// Get the count of validators that signed.
    pub fn signer_count(&self) -> usize {
        if !self.aggregate_signature.is_empty() {
            return self.aggregate_signers.len();
        }
        self.validator_signatures.len()
    }

    /// Check if this certificate meets the 2/3 quorum threshold.
    ///
    /// SAFETY: For Byzantine fault tolerance, we need >2/3 of total stake.
    pub fn meets_quorum(&self, total_stake: u128) -> bool {
        let threshold = (total_stake * 2) / 3;
        self.total_voting_power() > threshold
    }

    /// Whether this certificate uses a BLS aggregated signature.
    pub fn is_aggregate(&self) -> bool {
        !self.aggregate_signature.is_empty()
    }

    /// Verify the aggregate BLS signature, if present.
    pub fn verify_aggregate_signature(&self) -> Result<(), String> {
        if self.aggregate_signature.is_empty() {
            return Err("No aggregate signature present".to_string());
        }
        if self.aggregate_signers.is_empty() {
            return Err("No aggregate signer metadata present".to_string());
        }

        let signers: Vec<Vec<u8>> = self
            .aggregate_signers
            .iter()
            .map(|s| s.public_key.clone())
            .collect();

        verify_bls_aggregate_signature(
            self.block_hash.as_bytes(),
            &self.aggregate_signature,
            &signers,
        )
    }

    /// Get the block hash bytes used for signing.
    pub fn signature_message(&self) -> Vec<u8> {
        self.block_hash.as_bytes().to_vec()
    }

    /// Verify that the block hash hasn't been tampered with.
    ///
    /// SAFETY: This is a basic hash verification.
    /// Cryptographic verification of signatures would use public keys.
    pub fn verify_hash(&self, claimed_hash: &str) -> Result<(), String> {
        if self.block_hash != claimed_hash {
            return Err(format!(
                "Hash mismatch: certificate has {}, but block hash is {}",
                self.block_hash, claimed_hash
            ));
        }
        Ok(())
    }

    /// Verify that the merkle root hasn't been tampered with.
    pub fn verify_merkle_root(&self, claimed_root: &str) -> Result<(), String> {
        if self.merkle_root != claimed_root {
            return Err(format!(
                "Merkle root mismatch: certificate has {}, but claimed root is {}",
                self.merkle_root, claimed_root
            ));
        }
        Ok(())
    }
}

/// Signature from a single validator on a finality certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// Validator ID that provided the signature
    pub validator_id: String,

    /// The actual digital signature (post-quantum safe)
    pub signature: Vec<u8>,

    /// Voting power of this validator at time of signing
    pub voting_power: u128,
}

/// Metadata for a signer in an aggregated finality proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSigner {
    /// Validator ID that participated in the aggregate proof.
    pub validator_id: String,

    /// BLS public key corresponding to the signer.
    pub public_key: Vec<u8>,

    /// Voting power of this validator at time of signing.
    pub voting_power: u128,
}

/// Finality proof: evidence that a block is finalized.
///
/// SAFETY: This proof can be included in transactions or stored separately.
/// It provides cryptographic evidence of finality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProof {
    /// The finality certificate
    pub certificate: FinalizyCertificate,

    /// Optional: Merkle path from the block to a finalized anchor
    pub merkle_path: Vec<String>,

    /// Optional: List of other blocks that depend on this finality
    pub dependent_blocks: Vec<u64>,
}

impl FinalityProof {
    /// Create a new finality proof from a certificate.
    pub fn new(certificate: FinalizyCertificate) -> Self {
        FinalityProof {
            certificate,
            merkle_path: Vec::new(),
            dependent_blocks: Vec::new(),
        }
    }

    /// Add a merkle path for light client verification.
    pub fn set_merkle_path(&mut self, path: Vec<String>) {
        self.merkle_path = path;
    }

    /// Add a dependent block.
    pub fn add_dependent_block(&mut self, height: u64) {
        if !self.dependent_blocks.contains(&height) {
            self.dependent_blocks.push(height);
        }
    }

    /// Verify the finality proof.
    ///
    /// SAFETY: In a production system, this would verify:
    /// 1. Certificate quorum (>2/3 stake)
    /// 2. Signature validity
    /// 3. Merkle path correctness
    pub fn verify(&self, total_stake: u128) -> Result<(), String> {
        if !self.certificate.meets_quorum(total_stake) {
            return Err(format!(
                "Certificate does not meet quorum: {} of {} stake",
                self.certificate.total_voting_power(),
                total_stake
            ));
        }

        if self.certificate.is_aggregate() {
            self.certificate.verify_aggregate_signature()?;
        } else if self.certificate.signer_count() == 0 {
            return Err("Certificate has no signers".to_string());
        }

        Ok(())
    }
}

/// Finality manager: tracks finalized blocks and manages finality proofs.
///
/// SAFETY: This is the authoritative record of what has been finalized.
/// Once a block is recorded here, it is immutable.
pub struct FinalizityManager {
    /// Map of block height to finality certificate
    finalized_blocks: HashMap<u64, FinalizyCertificate>,

    /// Map of block height to finality proof
    finality_proofs: HashMap<u64, FinalityProof>,

    /// Total stake of the network (used for quorum calculation)
    total_stake: u128,

    /// Highest block height that has been finalized
    highest_finalized_height: u64,
}

impl FinalizityManager {
    /// Create a new finality manager.
    pub fn new(total_stake: u128) -> Self {
        FinalizityManager {
            finalized_blocks: HashMap::new(),
            finality_proofs: HashMap::new(),
            total_stake,
            highest_finalized_height: 0,
        }
    }

    /// Record that a block has been finalized.
    ///
    /// SAFETY: Once finalized, a block cannot be changed.
    pub fn finalize_block(&mut self, certificate: FinalizyCertificate) -> Result<(), String> {
        let height = certificate.block_height;

        // SAFETY: Cannot finalize a block that's already finalized
        if self.finalized_blocks.contains_key(&height) {
            return Err(format!("Block {} is already finalized", height));
        }

        // SAFETY: Verify quorum
        if !certificate.meets_quorum(self.total_stake) {
            return Err(format!(
                "Certificate for block {} does not meet quorum",
                height
            ));
        }

        info!(
            "Finalizing block {} with {} validator signatures",
            height,
            certificate.signer_count()
        );

        self.finalized_blocks.insert(height, certificate.clone());

        if height > self.highest_finalized_height {
            self.highest_finalized_height = height;
        }

        Ok(())
    }

    /// Record a finality proof for a block.
    pub fn record_proof(&mut self, proof: FinalityProof) -> Result<(), String> {
        let height = proof.certificate.block_height;

        if !self.finalized_blocks.contains_key(&height) {
            return Err(format!("Block {} is not finalized", height));
        }

        self.finality_proofs.insert(height, proof);
        Ok(())
    }

    /// Check if a block is finalized.
    pub fn is_finalized(&self, height: u64) -> bool {
        self.finalized_blocks.contains_key(&height)
    }

    /// Get the finality certificate for a block (if finalized).
    pub fn get_certificate(&self, height: u64) -> Option<&FinalizyCertificate> {
        self.finalized_blocks.get(&height)
    }

    /// Get the finality proof for a block (if recorded).
    pub fn get_proof(&self, height: u64) -> Option<&FinalityProof> {
        self.finality_proofs.get(&height)
    }

    /// Get the highest finalized block height.
    pub fn highest_finalized(&self) -> u64 {
        self.highest_finalized_height
    }

    /// Check if a block is finalized AND has a proof.
    pub fn is_proven_finalized(&self, height: u64) -> bool {
        self.finalized_blocks.contains_key(&height) && self.finality_proofs.contains_key(&height)
    }

    /// Count the total finalized blocks.
    pub fn finalized_count(&self) -> usize {
        self.finalized_blocks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finality_certificate_creation() {
        let cert = FinalizyCertificate::new(
            100,
            "hash100".to_string(),
            1,
            "PoS".to_string(),
            "merkle_root".to_string(),
            1000,
            1,
        )
        .unwrap();

        assert_eq!(cert.block_height, 100);
        assert_eq!(cert.block_hash, "hash100");
        assert_eq!(cert.signer_count(), 0);
    }

    #[test]
    fn test_finality_certificate_add_signatures() {
        let mut cert = FinalizyCertificate::new(
            100,
            "hash100".to_string(),
            1,
            "PoS".to_string(),
            "merkle_root".to_string(),
            1000,
            1,
        )
        .unwrap();

        cert.add_validator_signature("v1".to_string(), vec![1, 2, 3], 100)
            .unwrap();
        cert.add_validator_signature("v2".to_string(), vec![4, 5, 6], 200)
            .unwrap();

        assert_eq!(cert.signer_count(), 2);
        assert_eq!(cert.total_voting_power(), 300);
    }

    #[test]
    fn test_finality_certificate_duplicate_signature() {
        let mut cert = FinalizyCertificate::new(
            100,
            "hash100".to_string(),
            1,
            "PoS".to_string(),
            "merkle_root".to_string(),
            1000,
            1,
        )
        .unwrap();

        cert.add_validator_signature("v1".to_string(), vec![1, 2, 3], 100)
            .unwrap();

        // Try to add duplicate signature from v1
        let result = cert.add_validator_signature("v1".to_string(), vec![4, 5, 6], 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_finality_certificate_quorum_check() {
        let mut cert = FinalizyCertificate::new(
            100,
            "hash100".to_string(),
            1,
            "PoS".to_string(),
            "merkle_root".to_string(),
            1000,
            1,
        )
        .unwrap();

        let total_stake = 1000;

        // Need >2/3 of 1000 = > 666
        cert.add_validator_signature("v1".to_string(), vec![1, 2, 3], 600)
            .unwrap();
        assert!(!cert.meets_quorum(total_stake));

        cert.add_validator_signature("v2".to_string(), vec![4, 5, 6], 100)
            .unwrap();
        assert!(cert.meets_quorum(total_stake));
    }

    #[test]
    fn test_finality_certificate_aggregate_signature() {
        let mut cert = FinalizyCertificate::new(
            100,
            "hash100".to_string(),
            1,
            "PoS".to_string(),
            "merkle_root".to_string(),
            1000,
            1,
        )
        .unwrap();

        let message = cert.signature_message();
        let mut aggregate_signers = Vec::new();
        let mut signatures = Vec::new();

        for validator_id in ["v1", "v2"] {
            let (public_key, secret_key) = generate_bls_keypair().expect("BLS keygen failed");
            let signature = bls_sign(&message, &secret_key).expect("BLS sign failed");
            aggregate_signers.push(AggregateSigner {
                validator_id: validator_id.to_string(),
                public_key,
                voting_power: 700,
            });
            signatures.push(signature);
        }

        let aggregate_signature =
            aggregate_bls_signatures(&signatures).expect("BLS aggregate signing failed");
        cert.set_aggregate_signature(aggregate_signers, aggregate_signature)
            .expect("set aggregate signature failed");

        assert!(cert.verify_aggregate_signature().is_ok());
        assert!(cert.meets_quorum(1000));

        let proof = FinalityProof::new(cert);
        assert!(proof.verify(1000).is_ok());
    }

    #[test]
    fn test_finality_proof_verification() {
        let mut cert = FinalizyCertificate::new(
            100,
            "hash100".to_string(),
            1,
            "PoS".to_string(),
            "merkle_root".to_string(),
            1000,
            1,
        )
        .unwrap();

        cert.add_validator_signature("v1".to_string(), vec![1, 2, 3], 700)
            .unwrap();

        let proof = FinalityProof::new(cert);
        assert!(proof.verify(1000).is_ok());
    }

    #[test]
    fn test_finality_manager_basic() {
        let mut manager = FinalizityManager::new(1000);

        let mut cert = FinalizyCertificate::new(
            100,
            "hash100".to_string(),
            1,
            "PoS".to_string(),
            "merkle_root".to_string(),
            1000,
            1,
        )
        .unwrap();

        cert.add_validator_signature("v1".to_string(), vec![1, 2, 3], 700)
            .unwrap();

        manager.finalize_block(cert).unwrap();

        assert!(manager.is_finalized(100));
        assert_eq!(manager.highest_finalized(), 100);
    }

    #[test]
    fn test_finality_manager_duplicate_finalization() {
        let mut manager = FinalizityManager::new(1000);

        let mut cert = FinalizyCertificate::new(
            100,
            "hash100".to_string(),
            1,
            "PoS".to_string(),
            "merkle_root".to_string(),
            1000,
            1,
        )
        .unwrap();

        cert.add_validator_signature("v1".to_string(), vec![1, 2, 3], 700)
            .unwrap();

        manager.finalize_block(cert.clone()).unwrap();

        // Try to finalize same block again
        let result = manager.finalize_block(cert);
        assert!(result.is_err());
    }

    #[test]
    fn test_finality_manager_insufficient_quorum() {
        let mut manager = FinalizityManager::new(1000);

        let mut cert = FinalizyCertificate::new(
            100,
            "hash100".to_string(),
            1,
            "PoS".to_string(),
            "merkle_root".to_string(),
            1000,
            1,
        )
        .unwrap();

        // Only 600 of 1000 stake = not enough
        cert.add_validator_signature("v1".to_string(), vec![1, 2, 3], 600)
            .unwrap();

        let result = manager.finalize_block(cert);
        assert!(result.is_err());
    }
}
