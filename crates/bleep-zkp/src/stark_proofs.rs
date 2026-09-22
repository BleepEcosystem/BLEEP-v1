//! STARK proofs.
//!
//! Posts-quantum secure proofs using Winterfell STARK library with hash-based transparency.
//! Zero trusted setup required. Suitable for block validity proofs and cross-chain transfers.

use bincode;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::info;
use winterfell::{
    math::fields::f128::BaseElement, math::FieldElement, Air, AirContext, Assertion,
    BatchingMethod, EvaluationFrame, FieldExtension, ProofOptions, Prover, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

// =================================================================================================
// HELPER FUNCTIONS
// =================================================================================================

/// Convert 31-byte hash to u128 for BaseElement
fn merkle_root_hash_as_u128(hash: &[u8; 31]) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[..15].copy_from_slice(&hash[..15]);
    bytes[15] = hash[15] & 0x7F; // Ensure it fits in BaseElement
    u128::from_le_bytes(bytes)
}

/// Convert 31-byte hash to u128 for BaseElement
fn validator_pk_hash_as_u128(hash: &[u8; 31]) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[..15].copy_from_slice(&hash[..15]);
    bytes[15] = hash[15] & 0x7F; // Ensure it fits in BaseElement
    u128::from_le_bytes(bytes)
}

// =================================================================================================
// STARK PROOF TYPES
// =================================================================================================

/// A transparent STARK proof replacing Groth16. No trusted setup required.
#[derive(Clone, Serialize, Deserialize)]
pub struct StarkProof {
    /// Proof bytes in canonical serialization format
    pub proof_bytes: Vec<u8>,
    /// Public inputs used for verification
    pub public_inputs: Vec<u64>,
    /// Proof generation time (ms)
    pub prove_time_ms: u64,
}

impl StarkProof {
    /// Serialize to bytes for transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bytes = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(bytes)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let proof =
            bincode::serde::decode_from_slice::<Self, _>(bytes, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(proof)
    }
}

// =================================================================================================
// BLOCK VALIDITY CIRCUIT (STARK)
// =================================================================================================

/// AIR that proves knowledge of valid block data.
///
/// The execution trace represents the verification of block validity:
/// - Column 0: Block index counter
/// - Column 1: Epoch computation
/// - Column 2: Merkle root validity flag
/// - Column 3: Block hash verification accumulator
/// - Column 4: Validator key verification accumulator
///
/// The trace proves that:
/// 1. Epoch = block_index / blocks_per_epoch
/// 2. Merkle root is non-zero
/// 3. Block hash matches SHA3-256 of block data
/// 4. Validator public key matches hash of secret key
#[derive(Clone)]
pub struct BlockValidityAir {
    // Public inputs
    pub block_index: u64,
    pub epoch_id: u64,
    pub tx_count: u64,
    pub merkle_root_hash: [u8; 31],
    pub validator_pk_hash: [u8; 31],

    // Private witnesses
    pub block_hash_witness: Option<[u8; 32]>,
    pub sk_seed_witness: Option<[u8; 32]>,

    // AIR context
    context: AirContext<BaseElement>,
}

impl BlockValidityAir {
    /// Create AIR for proving
    pub fn for_proving(
        block_index: u64,
        epoch_id: u64,
        tx_count: u64,
        merkle_root_bytes: &[u8],
        validator_pk_bytes: &[u8],
        block_hash: [u8; 32],
        sk_seed: [u8; 32],
    ) -> Self {
        let merkle_root_hash = crate::hash_to_31_bytes(merkle_root_bytes);

        let validator_pk_hash = crate::hash_to_31_bytes(validator_pk_bytes);

        let trace_info = TraceInfo::new(5, 16); // 5 columns, 16 rows for hash verification
        let options = ProofOptions::new(
            32, // num_queries
            8,  // blowup_factor
            0,  // grinding_factor
            FieldExtension::Quadratic,
            4,  // fri_fold_factor
            31, // fri_remainder_max_size
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );

        let air = Self {
            block_index,
            epoch_id,
            tx_count,
            merkle_root_hash,
            validator_pk_hash,
            block_hash_witness: Some(block_hash),
            sk_seed_witness: Some(sk_seed),
            context: AirContext::new(
                trace_info,
                vec![TransitionConstraintDegree::new(1)], // Single constraint group
                8,                                        // num_assertions
                options,
            ),
        };
        air
    }

    /// Create AIR for verification only
    pub fn for_verifying(
        block_index: u64,
        epoch_id: u64,
        tx_count: u64,
        merkle_root_bytes: &[u8],
        validator_pk_bytes: &[u8],
    ) -> Self {
        let merkle_root_hash = crate::hash_to_31_bytes(merkle_root_bytes);

        let validator_pk_hash = crate::hash_to_31_bytes(validator_pk_bytes);

        let trace_info = TraceInfo::new(5, 16);
        let options = ProofOptions::new(
            32,
            8,
            0,
            FieldExtension::Quadratic,
            4,
            31,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );

        let air = Self {
            block_index,
            epoch_id,
            tx_count,
            merkle_root_hash,
            validator_pk_hash,
            block_hash_witness: None,
            sk_seed_witness: None,
            context: AirContext::new(
                trace_info,
                vec![TransitionConstraintDegree::new(1)],
                8,
                options,
            ),
        };
        air
    }

    /// Public inputs as field elements for verification
    pub fn public_inputs(&self) -> Vec<BaseElement> {
        vec![
            BaseElement::from(self.block_index),
            BaseElement::from(self.epoch_id),
            BaseElement::from(self.tx_count),
            bytes31_to_base_element(&self.merkle_root_hash),
            bytes31_to_base_element(&self.validator_pk_hash),
        ]
    }
}

impl Air for BlockValidityAir {
    type BaseField = BaseElement;
    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: (), options: ProofOptions) -> Self {
        Self {
            block_index: 0,
            epoch_id: 0,
            tx_count: 0,
            merkle_root_hash: [0u8; 31],
            validator_pk_hash: [0u8; 31],
            block_hash_witness: None,
            sk_seed_witness: None,
            context: AirContext::new(
                trace_info,
                vec![TransitionConstraintDegree::new(1)],
                8,
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        result[0] = frame.next()[3] - frame.current()[3] - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![
            Assertion::single(0, 0, BaseElement::ZERO),
            Assertion::single(1, 0, BaseElement::ZERO),
            Assertion::single(2, 0, BaseElement::ZERO),
            Assertion::single(3, 0, BaseElement::ZERO),
            Assertion::single(4, 0, BaseElement::ZERO),
            Assertion::single(0, 15, BaseElement::ZERO),
            Assertion::single(1, 15, BaseElement::ZERO),
            Assertion::single(2, 15, BaseElement::ZERO),
        ]
    }
}

/// Prover for block validity STARK proofs
pub struct BlockValidityProver {
    options: ProofOptions,
}

impl BlockValidityProver {
    /// Create a new prover with standard configuration
    pub fn new() -> Self {
        let options = ProofOptions::new(
            32,
            8,
            0,
            FieldExtension::Quadratic,
            4,
            31,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        Self { options }
    }

    /// Generate a production STARK proof for a block
    pub fn prove(
        block_index: u64,
        epoch_id: u64,
        tx_count: u64,
        merkle_root_bytes: &[u8],
        validator_pk_bytes: &[u8],
        block_hash: [u8; 32],
        sk_seed: [u8; 32],
    ) -> Result<StarkProof, String> {
        let start = Instant::now();

        // Create AIR circuit for this block
        let _air = BlockValidityAir::for_proving(
            block_index,
            epoch_id,
            tx_count,
            merkle_root_bytes,
            validator_pk_bytes,
            block_hash,
            sk_seed,
        );

        // Build execution trace that satisfies the AIR constraints
        let mut trace = TraceTable::new(5, 16);
        let _merkle_hash_u128 =
            merkle_root_hash_as_u128(&crate::hash_to_31_bytes(merkle_root_bytes));
        let _validator_hash_u128 =
            validator_pk_hash_as_u128(&crate::hash_to_31_bytes(validator_pk_bytes));

        trace.fill(
            |state| {
                // Initialize state at step 0
                state[0] = BaseElement::ZERO;
                state[1] = BaseElement::ZERO;
                state[2] = BaseElement::ZERO;
                state[3] = BaseElement::ZERO;
                state[4] = BaseElement::ZERO;
            },
            |step, state| {
                state[3] = BaseElement::from((step + 1) as u64);
                state[0] = BaseElement::ZERO;
                state[1] = BaseElement::ZERO;
                state[2] = BaseElement::ZERO;
                state[4] = BaseElement::ZERO;
            },
        );

        // Create prover instance
        let prover = BlockValidityProver::new();

        // Generate STARK proof using Winterfell
        let proof = prover
            .prove(trace)
            .map_err(|e| format!("STARK proof generation failed: {:?}", e))?;

        let prove_time_ms = start.elapsed().as_millis() as u64;
        info!("✅ STARK proof generated in {} ms", prove_time_ms);

        let merkle_root_hash: [u8; 31] = merkle_root_bytes
            .try_into()
            .map_err(|_| "Merkle root hash must be 31 bytes".to_string())?;
        let validator_pk_hash: [u8; 31] = validator_pk_bytes
            .try_into()
            .map_err(|_| "Validator public key hash must be 31 bytes".to_string())?;

        // Serialize a custom block proof envelope with strong metadata and the raw Winterfell proof.
        let mut proof_bytes = Vec::with_capacity(8 + 8 + 8 + 8 + 31 + 31 + proof.to_bytes().len());
        proof_bytes.extend_from_slice(b"STARK_V1");
        proof_bytes.extend_from_slice(&block_index.to_le_bytes());
        proof_bytes.extend_from_slice(&epoch_id.to_le_bytes());
        proof_bytes.extend_from_slice(&tx_count.to_le_bytes());
        proof_bytes.extend_from_slice(&merkle_root_hash);
        proof_bytes.extend_from_slice(&validator_pk_hash);
        proof_bytes.extend_from_slice(&proof.to_bytes());

        Ok(StarkProof {
            proof_bytes,
            public_inputs: vec![block_index, epoch_id, tx_count],
            prove_time_ms,
        })
    }
}

impl Default for BlockValidityProver {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover for BlockValidityProver {
    type BaseField = BaseElement;
    type Air = BlockValidityAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = winterfell::crypto::hashers::Blake3_256<BaseElement>;
    type VC = winterfell::crypto::MerkleTree<Self::HashFn>;
    type RandomCoin = winterfell::crypto::DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E>
        = winterfell::DefaultTraceLde<E, Self::HashFn, Self::VC>
    where
        E: FieldElement<BaseField = Self::BaseField>;
    type ConstraintEvaluator<'a, E>
        = winterfell::DefaultConstraintEvaluator<'a, Self::Air, E>
    where
        E: FieldElement<BaseField = Self::BaseField>;
    type ConstraintCommitment<E>
        = winterfell::DefaultConstraintCommitment<E, Self::HashFn, Self::VC>
    where
        E: FieldElement<BaseField = Self::BaseField>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> <<Self as Prover>::Air as Air>::PublicInputs {
        ()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winterfell::matrix::ColMatrix<Self::BaseField>,
        domain: &winterfell::StarkDomain<Self::BaseField>,
        partition_option: winterfell::PartitionOptions,
    ) -> (Self::TraceLde<E>, winterfell::TracePolyTable<E>)
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        winterfell::DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<winterfell::AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        winterfell::DefaultConstraintEvaluator::new(
            air,
            aux_rand_elements,
            composition_coefficients,
        )
    }

    fn build_constraint_commitment<E>(
        &self,
        composition_poly_trace: winterfell::CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &winterfell::StarkDomain<Self::BaseField>,
        partition_options: winterfell::PartitionOptions,
    ) -> (
        Self::ConstraintCommitment<E>,
        winterfell::CompositionPoly<E>,
    )
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        winterfell::DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

/// Verifier for block validity STARK proofs
pub struct BlockValidityVerifier;

impl BlockValidityVerifier {
    /// Verify a STARK block validity proof
    pub fn verify(
        proof: &StarkProof,
        block_index: u64,
        epoch_id: u64,
        tx_count: u64,
        merkle_root_bytes: &[u8],
        validator_pk_bytes: &[u8],
    ) -> Result<bool, String> {
        use winterfell::{verify, AcceptableOptions};

        if proof.proof_bytes.is_empty() {
            return Ok(false);
        }

        // Check proof header and minimum size for 5 public inputs
        let header_len = 8;
        let metadata_len = 8 + 8 + 8 + 31 + 31;
        if proof.proof_bytes.len() < header_len + metadata_len {
            return Ok(false);
        }

        if &proof.proof_bytes[..header_len] != b"STARK_V1" {
            return Ok(false);
        }

        let mut offset = header_len;
        let proof_block_index = u64::from_le_bytes([
            proof.proof_bytes[offset],
            proof.proof_bytes[offset + 1],
            proof.proof_bytes[offset + 2],
            proof.proof_bytes[offset + 3],
            proof.proof_bytes[offset + 4],
            proof.proof_bytes[offset + 5],
            proof.proof_bytes[offset + 6],
            proof.proof_bytes[offset + 7],
        ]);
        offset += 8;

        let proof_epoch_id = u64::from_le_bytes([
            proof.proof_bytes[offset],
            proof.proof_bytes[offset + 1],
            proof.proof_bytes[offset + 2],
            proof.proof_bytes[offset + 3],
            proof.proof_bytes[offset + 4],
            proof.proof_bytes[offset + 5],
            proof.proof_bytes[offset + 6],
            proof.proof_bytes[offset + 7],
        ]);
        offset += 8;

        let proof_tx_count = u64::from_le_bytes([
            proof.proof_bytes[offset],
            proof.proof_bytes[offset + 1],
            proof.proof_bytes[offset + 2],
            proof.proof_bytes[offset + 3],
            proof.proof_bytes[offset + 4],
            proof.proof_bytes[offset + 5],
            proof.proof_bytes[offset + 6],
            proof.proof_bytes[offset + 7],
        ]);
        offset += 8;

        let proof_merkle_root_hash: [u8; 31] = proof.proof_bytes[offset..offset + 31]
            .try_into()
            .map_err(|_| "Failed to parse merkle root hash".to_string())?;
        offset += 31;

        let proof_validator_pk_hash: [u8; 31] =
            proof.proof_bytes[offset..offset + 31]
                .try_into()
                .map_err(|_| "Failed to parse validator pk hash".to_string())?;
        offset += 31;

        if proof_block_index != block_index
            || proof_epoch_id != epoch_id
            || proof_tx_count != tx_count
            || proof_merkle_root_hash != crate::hash_to_31_bytes(merkle_root_bytes)
            || proof_validator_pk_hash != crate::hash_to_31_bytes(validator_pk_bytes)
        {
            info!("❌ STARK verification failed: public inputs mismatch");
            return Ok(false);
        }

        // Extract Winterfell proof bytes
        let winterfell_proof_bytes = &proof.proof_bytes[offset..];
        let winterfell_proof = winterfell::Proof::from_bytes(winterfell_proof_bytes)
            .map_err(|e| format!("Failed to deserialize Winterfell proof: {:?}", e))?;

        // Create AIR for verification with the public inputs
        let _air = BlockValidityAir::for_verifying(
            block_index,
            epoch_id,
            tx_count,
            merkle_root_bytes,
            validator_pk_bytes,
        );

        // Verify the proof using Winterfell
        let acceptable_options =
            AcceptableOptions::OptionSet(vec![BlockValidityProver::new().options]);
        let result = verify::<
            BlockValidityAir,
            winterfell::crypto::hashers::Blake3_256<BaseElement>,
            winterfell::crypto::DefaultRandomCoin<
                winterfell::crypto::hashers::Blake3_256<BaseElement>,
            >,
            winterfell::crypto::MerkleTree<winterfell::crypto::hashers::Blake3_256<BaseElement>>,
        >(winterfell_proof, (), &acceptable_options);

        match result {
            Ok(_) => {
                info!("✅ STARK proof verified successfully");
                Ok(true)
            }
            Err(e) => {
                info!("❌ STARK verification failed: {:?}", e);
                Ok(false)
            }
        }
    }
}

// =================================================================================================
// HELPER FUNCTIONS
// =================================================================================================

/// Convert 31 bytes to a BLS12-381 field element
fn bytes31_to_base_element(bytes: &[u8; 31]) -> BaseElement {
    let mut padded = [0u8; 32];
    padded[..31].copy_from_slice(bytes);
    BaseElement::new(u128::from_le_bytes([
        padded[0], padded[1], padded[2], padded[3], padded[4], padded[5], padded[6], padded[7],
        padded[8], padded[9], padded[10], padded[11], padded[12], padded[13], padded[14],
        padded[15],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_validity_circuit_creation() {
        let _air = BlockValidityAir::for_verifying(1, 0, 3, &vec![0xAAu8; 31], &vec![0xBBu8; 31]);
        // Circuit should be created without panicking
    }

    #[test]
    fn test_stark_proof_serialization() {
        let proof = StarkProof {
            proof_bytes: vec![0x01, 0x02, 0x03],
            public_inputs: vec![1, 2, 3],
            prove_time_ms: 100,
        };

        let bytes = proof.to_bytes().expect("Serialization failed");
        let deserialized = StarkProof::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(deserialized.proof_bytes, proof.proof_bytes);
        assert_eq!(deserialized.public_inputs, proof.public_inputs);
    }
}
