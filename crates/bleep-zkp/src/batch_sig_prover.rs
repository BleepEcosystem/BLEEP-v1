//! Parallel commitment builder and prover for BLEEP's bounded block-metadata AIR.
//!
//! ## Historical reference estimates (8-core / 32 GB RAM)
//!
//! These estimates are not a benchmark result for this crate and do not include
//! proving SPHINCS+ verification or state-transition execution inside the AIR.
//!
//! | Step                              | Time     |
//! |-----------------------------------|----------|
//! | Parallel SHA3-256 (512 sigs)      |  ~45 ms  |
//! | Blake3 Merkle tree construction   |   ~5 ms  |
//! | AIR trace construction (rayon)    |  ~50 ms  |
//! | Winterfell STARK proof generation | ~850 ms  |
//! | **Total**                         | **~950 ms** |
//!
//! They must not be interpreted as performance measurements for a full
//! transaction-signature/state-transition proof.
//!
//! ## Integration with bleep-consensus
//!
//! ```rust
//! use bleep_zkp::{
//!     batch_sig_prover::ParallelBatchSigProver,
//!     extended_air::{bleep_proof_options, ExtendedBlockPublicInputs},
//! };
//!
//! let blocks_per_epoch = 100u64;
//! let sk_seed = [0x42u8; 32];
//! let sigs = vec![vec![0u8; 49_856]; 4];
//! let pub_inputs = ExtendedBlockPublicInputs {
//!     block_index: 42,
//!     epoch_id: 0,
//!     tx_count: 4,
//!     blocks_per_epoch,
//!     merkle_root_hash: [0xAA; 32],
//!     validator_pk_hash: [0xBB; 32],
//!     sk_seed_hash: [0u8; 32],
//!     block_hash: [0xCC; 32],
//!     smt_root: [0xDD; 32],
//!     sig_commitment_root: [0u8; 32],
//!     sig_count: 4,
//!     batch_seq_id: 42,
//! };
//!
//! let prover = ParallelBatchSigProver::new(blocks_per_epoch, bleep_proof_options());
//! let result = prover
//!     .prove_block(pub_inputs, &sigs, &sk_seed)
//!     .expect("proof generation should succeed");
//!
//! // result.proof             → include in block header
//! // result.sig_commitment_root → include in block header + announce via SAL
//! // result.sig_hashes        → broadcast via SigCommitmentAnnouncement
//! let _ = result.sig_commitment_root;
//! ```

use sha3::{Digest, Sha3_256};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    verify as winterfell_verify, AcceptableOptions, AuxRandElements,
    ConstraintCompositionCoefficients, DefaultConstraintEvaluator, DefaultTraceLde,
    PartitionOptions, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use crate::extended_air::{
    range_values, ExtendedBlockPublicInputs, ExtendedBlockValidityAir, COL_BATCH_SEQ_ID,
    COL_BLOCK_HASH_HI, COL_BLOCK_HASH_LO, COL_BLOCK_INDEX,
    COL_BLOCKS_PER_EPOCH, COL_BLOCKS_PER_EPOCH_INVERSE, COL_EPOCH_ID, COL_EPOCH_REMAINDER,
    COL_EPOCH_REMAINDER_GAP, COL_MERKLE_ROOT_HI, COL_MERKLE_ROOT_LO, COL_RANGE_BITS_END,
    COL_RANGE_BITS_START, COL_RANGE_VALUE, COL_RESERVED_END, COL_RESERVED_START, COL_SIG_COUNT,
    COL_SIG_ROOT_HI, COL_SIG_ROOT_LO, COL_SK_SEED_HASH_HI, COL_SK_SEED_HASH_LO, COL_SMT_ROOT_HI,
    COL_SMT_ROOT_LO, COL_TX_COUNT, COL_TX_COUNT_GAP, COL_VALIDATOR_PK_HI, COL_VALIDATOR_PK_LO,
    MIN_TRACE_LENGTH, NUM_RANGE_LIMBS, TRACE_WIDTH,
};

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the batch signature prover.
#[derive(Debug, thiserror::Error)]
pub enum BatchProverError {
    #[error("empty signature list — at least one transaction required")]
    EmptySignatureList,

    #[error("sig_count ({sig_count}) does not match signatures length ({sigs_len})")]
    SignatureCountMismatch { sig_count: u32, sigs_len: usize },

    #[error("tx_count ({tx_count}) does not match signatures length ({sigs_len})")]
    TransactionCountMismatch { tx_count: u32, sigs_len: usize },

    #[error("Winterfell prover error: {0}")]
    WinterfellProver(String),

    #[error("sig_commitment_root mismatch: expected {expected}, got {got}",
        expected = hex::encode(expected), got = hex::encode(got))]
    CommitmentRootMismatch { expected: [u8; 32], got: [u8; 32] },
}

/// Errors produced by the STARK proof verifier.
#[derive(Debug, thiserror::Error)]
pub enum BatchVerifyError {
    #[error("Winterfell verification failed: {0}")]
    WinterfellVerify(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchProveResult — returned by prove_block
// ─────────────────────────────────────────────────────────────────────────────

/// Full output of a successful `prove_block` call.
#[derive(Debug)]
pub struct BatchProveResult {
    /// Winterfell STARK proof — embed in the block header.
    pub proof: winterfell::Proof,
    /// Blake3 Merkle root over all `sig_hashes` — embed in the block header and
    /// broadcast via `SigCommitmentAnnouncement`.
    pub sig_commitment_root: [u8; 32],
    /// Ordered `SHA3-256(sig_i)` values — broadcast alongside the block header
    /// instead of the full 49,088-byte signatures.
    pub sig_hashes: Vec<[u8; 32]>,
    /// Public inputs baked into the proof — hand to `bleep-consensus` for storage.
    pub pub_inputs: ExtendedBlockPublicInputs,
}

// ─────────────────────────────────────────────────────────────────────────────
// ParallelBatchSigProver
// ─────────────────────────────────────────────────────────────────────────────

/// Produces Winterfell STARK proofs for BLEEP's bounded block-metadata AIR.
pub struct ParallelBatchSigProver {
    options: ProofOptions,
}

impl ParallelBatchSigProver {
    /// Create a prover with the given `blocks_per_epoch` value.
    ///
    /// Pass `bleep_proof_options()` for production; custom options for testing.
    pub fn new(_blocks_per_epoch: u64, options: ProofOptions) -> Self {
        Self { options }
    }

    // ── Main entry point ───────────────────────────────────────────────────

    /// Prove the bounded metadata constraints represented by the AIR.
    ///
    /// # Arguments
    /// * `pub_inputs_template` — block metadata, including the block hash, state
    ///   root, validator identity hash, and the signature commitment; signature
    ///   count and commitment root are filled in from `raw_signatures`.
    /// * `raw_signatures`      — ordered slice of raw SPHINCS+ signature bytes,
    ///   each leaf of the signature commitment. The AIR does not verify these
    ///   signatures or constrain how the commitment root was derived.
    /// * `sk_seed`             — seed used to populate a public metadata hash.
    ///   The AIR does not prove knowledge of this seed or bind it to a key.
    pub fn prove_block(
        &self,
        mut pub_inputs: ExtendedBlockPublicInputs,
        raw_signatures: &[Vec<u8>],
        sk_seed: &[u8; 32],
    ) -> Result<BatchProveResult, BatchProverError> {
        if raw_signatures.is_empty() {
            return Err(BatchProverError::EmptySignatureList);
        }
        if raw_signatures.len() > crate::extended_air::MAX_BLOCK_TRANSACTIONS as usize {
            return Err(BatchProverError::WinterfellProver(format!(
                "transaction count exceeds {}",
                crate::extended_air::MAX_BLOCK_TRANSACTIONS
            )));
        }

        if pub_inputs.sig_count != 0 && pub_inputs.sig_count as usize != raw_signatures.len() {
            return Err(BatchProverError::SignatureCountMismatch {
                sig_count: pub_inputs.sig_count,
                sigs_len: raw_signatures.len(),
            });
        }
        if pub_inputs.tx_count as usize != raw_signatures.len() {
            return Err(BatchProverError::TransactionCountMismatch {
                tx_count: pub_inputs.tx_count,
                sigs_len: raw_signatures.len(),
            });
        }

        // The signature count may be left as a placeholder by the caller.
        pub_inputs.sig_count = raw_signatures.len() as u32;
        if !pub_inputs.is_consistent() {
            return Err(BatchProverError::WinterfellProver(format!(
                "public metadata is inconsistent for block {}: epoch_id={}, blocks_per_epoch={}, batch_seq_id={}",
                pub_inputs.block_index,
                pub_inputs.epoch_id,
                pub_inputs.blocks_per_epoch,
                pub_inputs.batch_seq_id,
            )));
        }

        // ── Step 1: compute the signature commitment outside the AIR. ─────
        let (sig_commitment_root, sig_hashes) = compute_commitment_parallel(raw_signatures);
        pub_inputs.sig_commitment_root = sig_commitment_root;
        pub_inputs.sk_seed_hash = hash_sk_seed(sk_seed);

        // ── Step 2: build the metadata trace ──────────────────────────────
        let trace = self.build_trace(&pub_inputs, &sig_hashes);

        // ── Step 3: generate STARK proof ──────────────────────────────────
        let proof = self
            .prove(trace)
            .map_err(|e| BatchProverError::WinterfellProver(format!("{e:?}")))?;

        Ok(BatchProveResult {
            proof,
            sig_commitment_root,
            sig_hashes,
            pub_inputs,
        })
    }

    // ── Static verification ────────────────────────────────────────────────

    /// Verify a proof produced by `prove_block` against the given public inputs.
    pub fn verify_block(
        pub_inputs: ExtendedBlockPublicInputs,
        proof: winterfell::Proof,
        options: &ProofOptions,
    ) -> Result<(), BatchVerifyError> {
        winterfell_verify::<
            ExtendedBlockValidityAir,
            Blake3_256<BaseElement>,
            DefaultRandomCoin<Blake3_256<BaseElement>>,
            winterfell::crypto::MerkleTree<Blake3_256<BaseElement>>,
        >(
            proof,
            pub_inputs,
            &AcceptableOptions::OptionSet(vec![options.clone()]),
        )
        .map_err(|e| BatchVerifyError::WinterfellVerify(format!("{e:?}")))
    }

    // ── Trace construction ─────────────────────────────────────────────────

    /// Build the metadata trace. Signature hashes are not trace witnesses.
    pub fn build_trace(
        &self,
        pub_inputs: &ExtendedBlockPublicInputs,
        _sig_hashes: &[[u8; 32]],
    ) -> TraceTable<BaseElement> {
        let remainder = if pub_inputs.blocks_per_epoch == 0 {
            0
        } else {
            pub_inputs.block_index % pub_inputs.blocks_per_epoch
        };
        let remainder_gap = pub_inputs
            .blocks_per_epoch
            .saturating_sub(remainder.saturating_add(1));
        let tx_count_gap = u64::from(crate::extended_air::MAX_BLOCK_TRANSACTIONS)
            .saturating_sub(u64::from(pub_inputs.tx_count));
        let range_values = range_values(pub_inputs, remainder, remainder_gap, tx_count_gap);
        debug_assert_eq!(range_values.len(), NUM_RANGE_LIMBS);
        let inverse = BaseElement::new(pub_inputs.blocks_per_epoch as u128).inv();

        let trace_len = next_power_of_two(pub_inputs.tx_count.max(1).max(MIN_TRACE_LENGTH as u32) as usize);
        let mut trace = TraceTable::<BaseElement>::new(TRACE_WIDTH, trace_len);

        trace.fill(
            |state| {
                for (column, value) in pub_inputs.to_elements().into_iter().enumerate() {
                    state[column] = value;
                }
                state[COL_EPOCH_REMAINDER] = BaseElement::from(remainder);
                state[COL_EPOCH_REMAINDER_GAP] = BaseElement::from(remainder_gap);
                state[COL_TX_COUNT_GAP] = BaseElement::from(tx_count_gap);
                state[COL_BLOCKS_PER_EPOCH_INVERSE] = inverse;
                for value in state
                    .iter_mut()
                    .take(COL_RESERVED_END + 1)
                    .skip(COL_RESERVED_START)
                {
                    *value = BaseElement::ZERO;
                }
                Self::set_range_row(state, 0, &range_values);
            },
            |step, state| {
                Self::set_range_row(state, step + 1, &range_values);
            },
        );

        trace
    }

    fn set_range_row(state: &mut [BaseElement], row: usize, values: &[BaseElement]) {
        // A valid, unconstrained padding row keeps every boolean-bit
        // transition polynomial at its declared degree, independent of the
        // particular public inputs (which may leave high bits unused).
        let value = values.get(row).copied().unwrap_or_else(|| {
            if row == NUM_RANGE_LIMBS {
                BaseElement::from(u64::from(u16::MAX))
            } else {
                BaseElement::ZERO
            }
        });
        state[COL_RANGE_VALUE] = value;
        let raw = value.as_int();
        for bit in 0..16 {
            state[COL_RANGE_BITS_START + bit] =
                BaseElement::from(((raw >> bit) & 1) as u64);
        }
        debug_assert_eq!(COL_RANGE_BITS_START + 15, COL_RANGE_BITS_END);
    }
}

fn next_power_of_two(value: usize) -> usize {
    let mut power = 1usize;
    while power < value {
        power <<= 1;
    }
    power
}

// ─────────────────────────────────────────────────────────────────────────────
// Winterfell Prover trait implementation
// ─────────────────────────────────────────────────────────────────────────────

impl Prover for ParallelBatchSigProver {
    type BaseField = BaseElement;
    type Air = ExtendedBlockValidityAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type VC = winterfell::crypto::MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Blake3_256<BaseElement>>;
    type TraceLde<E>
        = winterfell::DefaultTraceLde<E, Self::HashFn, Self::VC>
    where
        E: FieldElement<BaseField = BaseElement>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, ExtendedBlockValidityAir, E>;
    type ConstraintCommitment<E>
        = winterfell::DefaultConstraintCommitment<E, Self::HashFn, Self::VC>
    where
        E: FieldElement<BaseField = BaseElement>;

    /// Extract public inputs from the first row of the trace.
    fn get_pub_inputs(&self, trace: &TraceTable<BaseElement>) -> ExtendedBlockPublicInputs {
        // Read the raw u128 backing value for each column at row 0.
        macro_rules! col0 {
            ($col:expr) => {
                trace.get($col, 0)
            };
        }

        // Reconstruct 32-byte hashes from hi/lo f128 pairs.
        let merkle_root_hash =
            field_pair_to_bytes(col0!(COL_MERKLE_ROOT_HI), col0!(COL_MERKLE_ROOT_LO));
        let validator_pk_hash =
            field_pair_to_bytes(col0!(COL_VALIDATOR_PK_HI), col0!(COL_VALIDATOR_PK_LO));
        let sk_seed_hash =
            field_pair_to_bytes(col0!(COL_SK_SEED_HASH_HI), col0!(COL_SK_SEED_HASH_LO));
        let block_hash = field_pair_to_bytes(col0!(COL_BLOCK_HASH_HI), col0!(COL_BLOCK_HASH_LO));
        let smt_root = field_pair_to_bytes(col0!(COL_SMT_ROOT_HI), col0!(COL_SMT_ROOT_LO));
        let sig_commitment_root =
            field_pair_to_bytes(col0!(COL_SIG_ROOT_HI), col0!(COL_SIG_ROOT_LO));

        ExtendedBlockPublicInputs {
            block_index: col0!(COL_BLOCK_INDEX).as_int() as u64,
            epoch_id: col0!(COL_EPOCH_ID).as_int() as u64,
            tx_count: col0!(COL_TX_COUNT).as_int() as u32,
            blocks_per_epoch: col0!(COL_BLOCKS_PER_EPOCH).as_int() as u64,
            merkle_root_hash,
            validator_pk_hash,
            sk_seed_hash,
            block_hash,
            smt_root,
            sig_commitment_root,
            sig_count: col0!(COL_SIG_COUNT).as_int() as u32,
            batch_seq_id: col0!(COL_BATCH_SEQ_ID).as_int() as u64,
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = BaseElement>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<BaseElement>,
        domain: &StarkDomain<BaseElement>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E>(
        &self,
        composition_poly_trace: winterfell::CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<BaseElement>,
        partition_options: PartitionOptions,
    ) -> (
        Self::ConstraintCommitment<E>,
        winterfell::CompositionPoly<E>,
    )
    where
        E: FieldElement<BaseField = BaseElement>,
    {
        winterfell::DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute `(sig_commitment_root, sig_hashes)` from raw signature bytes.
/// Uses Rayon for parallel SHA3-256 hashing; then a sequential Blake3 Merkle build.
pub fn compute_commitment_parallel(raw_signatures: &[Vec<u8>]) -> ([u8; 32], Vec<[u8; 32]>) {
    use bleep_sig_availability::compute_sig_commitment;
    compute_sig_commitment(raw_signatures)
}

/// `SHA3-256(b"bleep_sk_seed_hash_v1" || sk_seed)` — public metadata only.
/// The AIR does not prove knowledge of the seed or bind it to a validator key.
fn hash_sk_seed(sk_seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"bleep_sk_seed_hash_v1");
    h.update(sk_seed);
    h.finalize().into()
}

/// Reconstruct a 32-byte hash from two f128 hi/lo field elements.
fn field_pair_to_bytes(hi: BaseElement, lo: BaseElement) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&hi.as_int().to_le_bytes());
    out[16..].copy_from_slice(&lo.as_int().to_le_bytes());
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extended_air::bleep_proof_options;
    use winterfell::Trace;

    /// Build a minimal, deterministic set of public inputs for testing.
    fn test_pub_inputs(tx_count: u32) -> ExtendedBlockPublicInputs {
        ExtendedBlockPublicInputs {
            block_index: 42,
            epoch_id: 0,
            tx_count,
            blocks_per_epoch: 100,
            merkle_root_hash: [0xAA; 32],
            validator_pk_hash: [0xBB; 32],
            sk_seed_hash: [0u8; 32], // filled in by prove_block
            block_hash: [0xCC; 32],
            smt_root: [0xDD; 32],
            sig_commitment_root: [0u8; 32], // filled in by prove_block
            sig_count: tx_count,
            batch_seq_id: 42,
        }
    }

    /// Produce deterministic fake SPHINCS+ signatures of the right length.
    fn fake_sigs(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| vec![(i as u8).wrapping_add(1); 49_856])
            .collect()
    }

    #[test]
    fn trace_construction_single_tx() {
        let prover = ParallelBatchSigProver::new(100, bleep_proof_options());
        let sigs = fake_sigs(1);
        let pi = test_pub_inputs(1);
        let (root, hashes) = compute_commitment_parallel(&sigs);
        let mut pi2 = pi.clone();
        pi2.sig_commitment_root = root;
        pi2.sig_count = 1;
        pi2.sk_seed_hash = [0xEE; 32];

        let trace = prover.build_trace(&pi2, &hashes);
        assert_eq!(trace.width(), TRACE_WIDTH);
        // The minimum trace length is 32, independent of the transaction count.
        assert!(trace.length() >= MIN_TRACE_LENGTH);
        assert!(trace.length().is_power_of_two());
    }

    #[test]
    fn trace_construction_512_tx() {
        let prover = ParallelBatchSigProver::new(100, bleep_proof_options());
        let sigs = fake_sigs(512);
        let pi = test_pub_inputs(512);
        let (root, hashes) = compute_commitment_parallel(&sigs);
        let mut pi2 = pi;
        pi2.sig_commitment_root = root;
        pi2.sk_seed_hash = [0xEE; 32];

        let trace = prover.build_trace(&pi2, &hashes);
        assert_eq!(trace.width(), TRACE_WIDTH);
        assert_eq!(trace.length(), 512); // 512 is already a power of 2
    }

    #[test]
    fn prove_and_verify_4_tx() {
        // Uses a fast proof option to keep the test runtime reasonable.
        let fast_options = ProofOptions::new(
            10, // fewer queries
            4,  // smaller blowup
            0,  // no grinding
            winterfell::FieldExtension::None,
            4,
            7,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );
        let prover = ParallelBatchSigProver::new(100, fast_options.clone());
        let sigs = fake_sigs(4);
        let sk_seed = [0x42u8; 32];
        let mut pi = test_pub_inputs(4);
        pi.sig_count = 0;

        let result = prover
            .prove_block(pi, &sigs, &sk_seed)
            .expect("prove_block failed");

        assert_eq!(result.sig_hashes.len(), 4);
        assert_eq!(result.pub_inputs.sig_count, 4);
        assert_ne!(result.sig_commitment_root, [0u8; 32]);

        // Verify the proof.
        ParallelBatchSigProver::verify_block(result.pub_inputs, result.proof, &fast_options)
            .expect("verify_block failed");
    }

    #[test]
    fn tampered_pub_inputs_fails_verify() {
        let fast_options = ProofOptions::new(
            10,
            4,
            0,
            winterfell::FieldExtension::None,
            4,
            7,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );
        let prover = ParallelBatchSigProver::new(100, fast_options.clone());
        let sigs = fake_sigs(4);
        let sk_seed = [0x42u8; 32];
        let pi = test_pub_inputs(4);

        let result = prover
            .prove_block(pi, &sigs, &sk_seed)
            .expect("prove_block failed");

        // Tamper: change block_index in the public inputs before verifying.
        let mut tampered_pi = result.pub_inputs.clone();
        tampered_pi.block_index = 9999;

        let verify_result =
            ParallelBatchSigProver::verify_block(tampered_pi, result.proof, &fast_options);
        assert!(
            verify_result.is_err(),
            "verification must fail with tampered public inputs"
        );
    }

    #[test]
    fn inconsistent_public_inputs_are_rejected() {
        let prover = ParallelBatchSigProver::new(100, bleep_proof_options());
        let mut pi = test_pub_inputs(4);
        pi.sig_count = 3;

        let result = prover
            .prove_block(pi, &fake_sigs(4), &[0x42u8; 32])
            .expect_err("inconsistent public inputs should be rejected");

        assert!(matches!(
            result,
            BatchProverError::SignatureCountMismatch { .. }
        ));
    }

    #[test]
    #[ignore = "explicit benchmark: run with cargo test -p bleep-zkp --lib benchmark_100_tx -- --ignored --nocapture"]
    fn benchmark_100_tx_proof_generation_and_verification() {
        let transaction_count = 100;
        let signatures = fake_sigs(transaction_count);
        let secret_seed = [0x42u8; 32];
        let prover = ParallelBatchSigProver::new(100, bleep_proof_options());
        let public_inputs = test_pub_inputs(transaction_count as u32);

        let commitment_start = std::time::Instant::now();
        let (commitment_root, signature_hashes) = compute_commitment_parallel(&signatures);
        let commitment_ms = commitment_start.elapsed().as_secs_f64() * 1_000.0;

        let mut proof_inputs = public_inputs;
        proof_inputs.sig_commitment_root = commitment_root;
        proof_inputs.sk_seed_hash = hash_sk_seed(&secret_seed);

        let trace_start = std::time::Instant::now();
        let trace = prover.build_trace(&proof_inputs, &signature_hashes);
        let trace_ms = trace_start.elapsed().as_secs_f64() * 1_000.0;

        let prove_start = std::time::Instant::now();
        let proof = prover
            .prove(trace)
            .expect("100-transaction STARK generation failed");
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
        let proof_bytes = proof.to_bytes().len();

        let verify_start = std::time::Instant::now();
        ParallelBatchSigProver::verify_block(proof_inputs, proof, &bleep_proof_options())
            .expect("100-transaction STARK verification failed");
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;

        let total_ms = commitment_ms + trace_ms + prove_ms + verify_ms;
        eprintln!(
            "100-tx STARK benchmark: commitment_ms={commitment_ms:.2}, trace_ms={trace_ms:.2}, prove_ms={prove_ms:.2}, verify_ms={verify_ms:.2}, total_ms={total_ms:.2}, proof_bytes={proof_bytes}"
        );
    }
}
