//! STARK proofs.
//!
//! Legacy Winterfell STARK proof APIs.
//! The underconstrained `STARK_V1` block-validity prover and verifier are disabled.

use bincode;
use serde::{Deserialize, Serialize};
use winterfell::{
    math::fields::f128::BaseElement, math::FieldElement, Air, AirContext, Assertion,
    BatchingMethod, EvaluationFrame, FieldExtension, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

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
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(bytes)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let proof =
            bincode::serde::decode_from_slice::<Self, _>(bytes, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(proof)
    }
}

// =================================================================================================
// BLOCK VALIDITY CIRCUIT (STARK)
// =================================================================================================

/// Legacy AIR retained for source compatibility; it does not prove block validity.
/// Its transition constraint only increments one trace column; all block
/// metadata and witnesses are unconstrained.
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
    /// Construct the legacy AIR. This does not establish block validity.
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

        let trace_info = TraceInfo::new(5, 16); // Legacy trace dimensions only.
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

        Self {
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
        }
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

        Self {
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
        }
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

/// Legacy block-validity prover. Proof generation is disabled because its AIR
/// does not constrain the block data it claims to attest.
pub struct BlockValidityProver;

impl BlockValidityProver {
    /// Create the disabled legacy prover handle.
    pub fn new() -> Self {
        Self
    }

    /// Reject proof generation until the AIR constrains block validity.
    pub fn prove(
        block_index: u64,
        epoch_id: u64,
        tx_count: u64,
        merkle_root_bytes: &[u8],
        validator_pk_bytes: &[u8],
        block_hash: [u8; 32],
        sk_seed: [u8; 32],
    ) -> Result<StarkProof, String> {
        let _ = (
            block_index,
            epoch_id,
            tx_count,
            merkle_root_bytes,
            validator_pk_bytes,
            block_hash,
            sk_seed,
        );
        Err("Legacy STARK_V1 block proofs are disabled because the AIR does not constrain block validity".into())
    }
}

impl Default for BlockValidityProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifier for the disabled legacy block-proof format.
pub struct BlockValidityVerifier;

impl BlockValidityVerifier {
    /// Reject a legacy STARK_V1 proof; its AIR does not establish block validity.
    pub fn verify(
        proof: &StarkProof,
        block_index: u64,
        epoch_id: u64,
        tx_count: u64,
        merkle_root_bytes: &[u8],
        validator_pk_bytes: &[u8],
    ) -> Result<bool, String> {
        let _ = (
            proof,
            block_index,
            epoch_id,
            tx_count,
            merkle_root_bytes,
            validator_pk_bytes,
        );
        Ok(false)
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
        let _air = BlockValidityAir::for_verifying(1, 0, 3, &[0xAAu8; 31], &[0xBBu8; 31]);
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

    #[test]
    fn legacy_block_proof_generation_is_disabled() {
        let result =
            BlockValidityProver::prove(1, 0, 3, &[0xAA; 31], &[0xBB; 31], [0x42; 32], [0x99; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn legacy_block_proof_envelopes_are_rejected() {
        let mut proof_bytes = b"STARK_V1".to_vec();
        proof_bytes.extend_from_slice(&[0; 8 * 3 + 31 * 2 + 64]);
        let proof = StarkProof {
            proof_bytes,
            public_inputs: vec![1, 0, 3],
            prove_time_ms: 0,
        };

        assert!(!BlockValidityVerifier::verify(&proof, 1, 0, 3, &[0xAA; 31], &[0xBB; 31]).unwrap());
    }
}
