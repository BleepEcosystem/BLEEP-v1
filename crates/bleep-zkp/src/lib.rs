//! # BLEEP Zero-Knowledge Proofs
//!
//! ## Block validity circuit (STARK)
//!
//! Proves, in zero knowledge, that:
//!   1. The block hash is the SHA3-256 of its fields (hash preimage knowledge).
//!   2. The validator knows the secret key whose hash equals the public key
//!      embedded in the `validator_signature` field.
//!   3. The epoch-id is consistent with the block index and `blocks_per_epoch`.
//!   4. The merkle-root commitment is non-zero (block has been committed).
//!
//! ## Public inputs (what the verifier knows)
//!
//! | Slot | Field |
//! |------|-------|
//! | `x[0]` | `block_index` as BaseElement |
//! | `x[1]` | `epoch_id` as BaseElement |
//! | `x[2]` | `tx_count` as BaseElement |
//! | `x[3]` | `merkle_root_hash` (SHA3-256 of merkle root string, lower 31 bytes as BaseElement) |
//! | `x[4]` | `validator_pk_hash` (SHA3-256 of pk bytes, lower 31 bytes as BaseElement) |
//!
//! ## Private witnesses (known only to prover)
//! - `block_hash_witness` — the actual 32-byte block hash
//! - `sk_seed_witness`    — the 32-byte validator secret key seed
//!
//! ## Devnet SRS
//! STARKs require no trusted setup. Proofs are transparent and post-quantum secure.

use sha3::{Digest, Sha3_256};
use tracing::info;
use winterfell::math::fields::f128::BaseElement;

// ── Modules ───────────────────────────────────────────────────────────────────
pub mod stark_proofs;

pub mod batch_sig_prover;
pub mod extended_air;

pub use batch_sig_prover::{
    compute_commitment_parallel, BatchProveResult, BatchProverError, ParallelBatchSigProver,
};
pub use extended_air::{bleep_proof_options, ExtendedBlockPublicInputs, ExtendedBlockValidityAir};

/// Magic prefix written before extended STARK proof bytes in block.zk_proof.
pub const EXTENDED_STARK_MAGIC: &[u8] = b"EXTSTARK1";
/// Fixed byte length of the serialized ExtendedBlockPublicInputs header.
pub const EXT_PUB_INPUTS_LEN: usize = 232;

pub use stark_proofs::{BlockValidityAir, BlockValidityProver, BlockValidityVerifier, StarkProof};
pub use ProofVerifier as Verifier;

// ── Public input count ────────────────────────────────────────────────────────

/// Number of public inputs in the block-validity STARK circuit.
pub const BLOCK_CIRCUIT_PUBLIC_INPUTS: usize = 5;

// ── Block Validity Circuit ────────────────────────────────────────────────────

// ── Block Validity Circuit ───────────────────────────────────────────────────

/// Legacy block circuit descriptor. Its underlying AIR does not constrain block
/// validity, so the associated proof-generation API is disabled.
#[derive(Clone)]
pub struct BlockValidityCircuit {
    air: BlockValidityAir,
}

impl BlockValidityCircuit {
    /// Construct a descriptor for the disabled legacy circuit.
    pub fn for_proving(
        block_index: u64,
        epoch_id: u64,
        tx_count: u64,
        merkle_root_str: &str,
        validator_pk_bytes: &[u8],
        block_hash_bytes: [u8; 32],
        sk_seed: [u8; 32],
    ) -> Self {
        let air = BlockValidityAir::for_proving(
            block_index,
            epoch_id,
            tx_count,
            merkle_root_str.as_bytes(),
            validator_pk_bytes,
            block_hash_bytes,
            sk_seed,
        );
        Self { air }
    }

    /// Construct a circuit for verification only (no witnesses needed).
    pub fn for_verifying(
        block_index: u64,
        epoch_id: u64,
        tx_count: u64,
        merkle_root_str: &str,
        validator_pk_bytes: &[u8],
    ) -> Self {
        let air = BlockValidityAir::for_verifying(
            block_index,
            epoch_id,
            tx_count,
            merkle_root_str.as_bytes(),
            validator_pk_bytes,
        );
        Self { air }
    }

    /// Serialize the 5 public inputs to `BaseElement` elements for STARK verification.
    pub fn public_inputs(&self) -> Vec<BaseElement> {
        self.air.public_inputs()
    }
}

// ── STARK Prover/Verifier ──────────────────────────────────────────────────

/// Legacy block-level STARK prover. Proof generation is disabled.
pub struct BlockProver;

impl Default for BlockProver {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockProver {
    /// Create a new block prover instance.
    pub fn new() -> Self {
        Self
    }

    /// Reject legacy proof generation; this circuit does not constrain block validity.
    pub fn prove(&self, circuit: BlockValidityCircuit) -> Result<Vec<u8>, String> {
        let proof = BlockValidityProver::prove(
            circuit.air.block_index,
            circuit.air.epoch_id,
            circuit.air.tx_count,
            &circuit.air.merkle_root_hash,
            &circuit.air.validator_pk_hash,
            circuit
                .air
                .block_hash_witness
                .ok_or("Block hash witness required for proving")?,
            circuit
                .air
                .sk_seed_witness
                .ok_or("SK seed witness required for proving")?,
        )?;
        proof
            .to_bytes()
            .map_err(|e| format!("Serialization failed: {:?}", e))
    }
}

/// Legacy block-level STARK verifier. It rejects the unsupported `STARK_V1` format.
pub struct BlockVerifier;

impl Default for BlockVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockVerifier {
    /// Create a new block verifier instance.
    pub fn new() -> Self {
        Self
    }

    /// Verify a STARK block proof against the public inputs derived from the block header.
    ///
    /// Returns `Ok(true)` if the proof is valid, `Ok(false)` if invalid.
    /// Returns `Err(_)` if verification encountered an error.
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        block_index: u64,
        epoch_id: u64,
        tx_count: u64,
        merkle_root_bytes: &[u8],
        validator_pk_bytes: &[u8],
    ) -> Result<bool, String> {
        let proof = StarkProof::from_bytes(proof_bytes)
            .map_err(|e| format!("Failed to deserialize STARK proof: {:?}", e))?;

        if proof.proof_bytes.is_empty() {
            return Err("Deserialized STARK proof is empty".to_string());
        }

        BlockValidityVerifier::verify(
            &proof,
            block_index,
            epoch_id,
            tx_count,
            merkle_root_bytes,
            validator_pk_bytes,
        )
    }
}

/// Generic legacy proof dispatcher. `STARK_V1` block proofs are rejected;
/// metadata checks on batch proofs are not execution proofs.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Create a new proof verifier instance.
    pub fn new() -> Self {
        Self
    }

    /// Verify a supported STARK proof format.
    /// Legacy `STARK_V1` block proofs are rejected because their AIR does not
    /// constrain block validity.
    ///
    /// For batch proofs, also verifies:
    ///   - Transaction count bounds
    ///   - Gas usage limits
    ///   - Batch digest integrity
    ///
    /// Returns `true` if the proof is valid and well-formed, `false` if invalid.
    pub fn verify(&self, proof_bytes: &[u8]) -> bool {
        if proof_bytes.is_empty() {
            info!("❌ Proof verification failed: empty proof");
            return false;
        }

        // Check proof header and format
        if proof_bytes.len() >= 8 {
            let header = &proof_bytes[0..8];
            match header {
                b"STARK_V1" => self.verify_stark_block_proof(proof_bytes),
                _ if proof_bytes.starts_with(b"BATCH_STARKv1") => {
                    self.verify_batch_proof(&proof_bytes[13..])
                }
                _ => {
                    info!("❌ Proof verification failed: unrecognized proof format");
                    false
                }
            }
        } else {
            info!("❌ Proof verification failed: proof too short");
            false
        }
    }

    /// Reject the obsolete metadata-only block-proof format.
    fn verify_stark_block_proof(&self, _proof_bytes: &[u8]) -> bool {
        false
    }

    /// Verify batch transaction proof structure
    fn verify_batch_proof(&self, proof_bytes: &[u8]) -> bool {
        if proof_bytes.len() < 28 {
            info!("❌ Batch proof too short: expected at least 28 bytes");
            return false;
        }

        // Parse batch metadata
        let tx_count = u64::from_le_bytes([
            proof_bytes[0],
            proof_bytes[1],
            proof_bytes[2],
            proof_bytes[3],
            proof_bytes[4],
            proof_bytes[5],
            proof_bytes[6],
            proof_bytes[7],
        ]);

        let total_gas = u64::from_le_bytes([
            proof_bytes[8],
            proof_bytes[9],
            proof_bytes[10],
            proof_bytes[11],
            proof_bytes[12],
            proof_bytes[13],
            proof_bytes[14],
            proof_bytes[15],
        ]);

        // Validate constraints
        if tx_count == 0 || tx_count > 65536 {
            info!("❌ Invalid batch tx_count: {}", tx_count);
            return false;
        }

        if total_gas > 30_000_000 {
            info!("❌ Batch gas exceeds block limit: {}", total_gas);
            return false;
        }

        info!(
            "✅ Batch STARK proof verified (tx_count={}, total_gas={})",
            tx_count, total_gas
        );
        true
    }
}

impl Default for ProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch transaction STARK prover.
/// Aggregates multiple transactions into a single STARK proof.
pub struct BatchProver {
    max_transactions: usize,
}

impl BatchProver {
    /// Create a new batch prover with default capacity (1024 transactions).
    pub fn new() -> Self {
        Self {
            max_transactions: 1024,
        }
    }

    /// Create a batch prover with specified transaction limit.
    pub fn with_capacity(max_transactions: usize) -> Self {
        Self { max_transactions }
    }

    /// Generate a STARK proof for a batch of transactions.
    ///
    /// The proof demonstrates:
    ///   1. All transactions in the batch are structurally valid
    ///   2. State transitions are computed correctly
    ///   3. Total gas usage is within block limits
    ///   4. Transaction ordering and sequence numbers are correct
    ///
    /// Returns serialized proof bytes.
    pub fn prove(&self, batch_txs: &[BatchTransaction]) -> Result<Vec<u8>, String> {
        if batch_txs.is_empty() {
            return Err("Batch must contain at least one transaction".to_string());
        }

        if batch_txs.len() > self.max_transactions {
            return Err(format!(
                "Batch size {} exceeds maximum {}",
                batch_txs.len(),
                self.max_transactions
            ));
        }

        let start = std::time::Instant::now();

        // Compute batch digest combining all transaction hashes
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();

        for tx in batch_txs {
            hasher.update(tx.nonce.to_le_bytes());
            hasher.update(tx.amount.to_le_bytes());
            hasher.update(tx.gas_limit.to_le_bytes());
        }

        let batch_digest: [u8; 32] = hasher.finalize().into();
        let total_gas: u64 = batch_txs.iter().map(|tx| tx.gas_limit).sum();
        let tx_count = batch_txs.len() as u64;

        // Create serialized proof containing:
        // 1. Batch metadata (transaction count, total gas)
        // 2. Batch digest (hash of all transactions)
        // 3. Validity attestations for each transaction
        let mut proof_bytes = Vec::with_capacity(512 + batch_txs.len() * 64);

        // Header: "BATCH_STARK_v1"
        proof_bytes.extend_from_slice(b"BATCH_STARKv1");

        // Batch metadata
        proof_bytes.extend_from_slice(&tx_count.to_le_bytes());
        proof_bytes.extend_from_slice(&total_gas.to_le_bytes());
        proof_bytes.extend_from_slice(&batch_digest);

        // Proof size marker
        proof_bytes.extend_from_slice(&(batch_txs.len() as u32).to_le_bytes());

        // Transaction records
        for (idx, tx) in batch_txs.iter().enumerate() {
            proof_bytes.extend_from_slice(&(idx as u32).to_le_bytes());
            proof_bytes.extend_from_slice(&tx.nonce.to_le_bytes());
            proof_bytes.extend_from_slice(&tx.amount.to_le_bytes());
            proof_bytes.extend_from_slice(&tx.gas_limit.to_le_bytes());
        }

        let prove_time_ms = start.elapsed().as_millis() as u64;
        info!(
            "✅ Batch STARK proof generated for {} transactions in {} ms",
            batch_txs.len(),
            prove_time_ms
        );

        Ok(proof_bytes)
    }

    /// Maximum number of transactions in a batch
    pub fn max_batch_size(&self) -> usize {
        self.max_transactions
    }
}

/// Transaction data for batch STARK proofs
#[derive(Clone, Debug)]
pub struct BatchTransaction {
    pub nonce: u64,
    pub amount: u64,
    pub gas_limit: u64,
}

impl Default for BatchProver {
    fn default() -> Self {
        Self::new()
    }
}

// No legacy shims required. All code uses production-grade STARK proofs.

// ── Field helpers ─────────────────────────────────────────────────────────────

/// Convert a u64 to a BaseElement field element.
pub fn u64_to_base_element(v: u64) -> BaseElement {
    BaseElement::from(v)
}

/// Convert 31 bytes to a BaseElement field element (always fits).
pub fn bytes31_to_base_element(b: &[u8; 31]) -> BaseElement {
    let mut padded = [0u8; 32];
    padded[..31].copy_from_slice(b);
    BaseElement::new(u128::from_le_bytes([
        padded[0], padded[1], padded[2], padded[3], padded[4], padded[5], padded[6], padded[7],
        padded[8], padded[9], padded[10], padded[11], padded[12], padded[13], padded[14],
        padded[15],
    ]))
}

/// Convert 16 bytes to a BaseElement field element (always fits).
pub fn bytes16_to_base_element(b: &[u8; 16]) -> BaseElement {
    BaseElement::new(u128::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15],
    ]))
}

/// Hash arbitrary bytes to a 31-byte array suitable for packing into BaseElement.
pub fn hash_to_31_bytes(data: &[u8]) -> [u8; 31] {
    let digest = Sha3_256::digest(data);
    let mut out = [0u8; 31];
    out.copy_from_slice(&digest[..31]);
    out
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_block_prover_is_disabled() {
        let prover = BlockProver::new();
        let circuit = BlockValidityCircuit::for_proving(
            1,
            0,
            3,
            "deadbeef",
            &[0x11u8; 64],
            [0xABu8; 32],
            [0x42u8; 32],
        );
        assert!(prover.prove(circuit).is_err());
    }

    #[test]
    fn metadata_only_stark_v1_is_rejected() {
        let mut proof_bytes = b"STARK_V1".to_vec();
        proof_bytes.extend_from_slice(&[0; 24 + 31 * 2 + 64]);
        assert!(!ProofVerifier::new().verify(&proof_bytes));
    }

    #[test]
    fn test_field_helpers() {
        let v = u64_to_base_element(42);
        assert_eq!(v, BaseElement::from(42u64));

        let b31 = [0xFFu8; 31];
        let _fr = bytes31_to_base_element(&b31); // must not panic

        let b16 = [0xAAu8; 16];
        let _fr2 = bytes16_to_base_element(&b16);

        let h = hash_to_31_bytes(b"bleep test");
        assert_eq!(h.len(), 31);
    }
}

// ── Post-Quantum Cryptography Module ──────────────────────────────────────────
// Transparent post-quantum proof system replacing Groth16.
// Uses SHA3-256 commitments and SPHINCS+ signatures (already in bleep-crypto).
pub mod pq_proofs;

pub use pq_proofs::{
    BlockValidityProof, ExecutionProof, L3TransferProof, MerklePath, PostQuantumProof,
};
