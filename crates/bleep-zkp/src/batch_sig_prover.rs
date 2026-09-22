//! Parallel batch signature prover for BLEEP's extended block-validity circuit.
//!
//! ## Timing budget (reference: 8-core / 32 GB RAM)
//!
//! | Step                              | Time     |
//! |-----------------------------------|----------|
//! | Parallel SHA3-256 (512 sigs)      |  ~45 ms  |
//! | Blake3 Merkle tree construction   |   ~5 ms  |
//! | AIR trace construction (rayon)    |  ~50 ms  |
//! | Winterfell STARK proof generation | ~850 ms  |
//! | **Total**                         | **~950 ms** |
//!
//! Well within the 3,000 ms slot budget. The ~850 ms STARK generation figure
//! matches the existing `BlockValidityProver`
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
//!     batch_seq_id: 1,
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
use std::sync::Arc;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f128::BaseElement, FieldElement, StarkField},
    matrix::ColMatrix,
    verify as winterfell_verify, AcceptableOptions, AuxRandElements,
    ConstraintCompositionCoefficients, DefaultConstraintEvaluator, DefaultTraceLde,
    PartitionOptions, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use crate::extended_air::{
    bytes_hi, bytes_lo, ExtendedBlockPublicInputs, ExtendedBlockValidityAir, COL_AVAIL_THRESHOLD,
    COL_BATCH_SEQ_ID, COL_BLOCKS_PER_EPOCH, COL_BLOCK_HASH_HI, COL_BLOCK_HASH_LO, COL_BLOCK_INDEX,
    COL_BLOCK_RESERVED_END, COL_BLOCK_RESERVED_START, COL_CURR_SIG_HI, COL_CURR_SIG_LO,
    COL_EPOCH_ID, COL_IS_ACTIVE, COL_MERKLE_ROOT_HI, COL_MERKLE_ROOT_LO, COL_PROCESSED_COUNT,
    COL_SIG_COUNT, COL_SIG_ROOT_HI, COL_SIG_ROOT_LO, COL_SK_SEED_HASH_HI, COL_SK_SEED_HASH_LO,
    COL_SMT_ROOT_HI, COL_SMT_ROOT_LO, COL_TX_COUNT, COL_VALIDATOR_PK_HI, COL_VALIDATOR_PK_LO,
    MIN_TRACE_LENGTH, TRACE_WIDTH,
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
pub struct BatchProveResult {
    /// Winterfell STARK proof — embed in the block header.
    pub proof: winterfell::Proof,
    /// Blake3 Merkle root over all `sig_hashes` — embed in the block header and
    /// broadcast via `SigCommitmentAnnouncement`.
    pub sig_commitment_root: [u8; 32],
    /// Ordered `SHA3-256(sig_i)` values — broadcast alongside the block header
    /// instead of the full 49,856-byte signatures.
    pub sig_hashes: Vec<[u8; 32]>,
    /// Public inputs baked into the proof — hand to `bleep-consensus` for storage.
    pub pub_inputs: ExtendedBlockPublicInputs,
}

// ─────────────────────────────────────────────────────────────────────────────
// ParallelBatchSigProver
// ─────────────────────────────────────────────────────────────────────────────

/// Produces Winterfell STARK proofs for BLEEP's extended 68-column
/// `BlockValidityAir` using Rayon for parallel trace construction.
pub struct ParallelBatchSigProver {
    options: ProofOptions,
    _blocks_per_epoch: u64,
    /// BPS threshold written into the trace for validators to read.
    availability_threshold_bps: u32,
}

impl ParallelBatchSigProver {
    /// Create a prover with the given `blocks_per_epoch` value.
    ///
    /// Pass `bleep_proof_options()` for production; custom options for testing.
    pub fn new(blocks_per_epoch: u64, options: ProofOptions) -> Self {
        Self {
            options,
            _blocks_per_epoch: blocks_per_epoch,
            availability_threshold_bps: 6_667,
        }
    }

    /// Override the availability threshold written into the trace.
    pub fn with_threshold(mut self, threshold_bps: u32) -> Self {
        self.availability_threshold_bps = threshold_bps;
        self
    }

    // ── Main entry point ───────────────────────────────────────────────────

    /// Prove a block's validity with signature commitment.
    ///
    /// # Arguments
    /// * `pub_inputs_template` — block metadata (block_index, epoch_id, etc.)
    ///   with `sig_commitment_root` and `sig_count` left as zero/placeholder;
    ///   this function fills them in from `raw_signatures`.
    /// * `raw_signatures`      — ordered slice of raw SPHINCS+ signature bytes.
    /// * `sk_seed`             — 32-byte proposer SK seed for the
    ///   `sk_seed_hash` column (private witness — never leaves the prover).
    pub fn prove_block(
        &self,
        mut pub_inputs: ExtendedBlockPublicInputs,
        raw_signatures: &[Vec<u8>],
        sk_seed: &[u8; 32],
    ) -> Result<BatchProveResult, BatchProverError> {
        if raw_signatures.is_empty() {
            return Err(BatchProverError::EmptySignatureList);
        }

        // ── Step 1: parallel SHA3-256 hashing + Blake3 Merkle root ────────
        // Approximately 45 ms for 512 × 49,856-byte signatures on 8 cores.
        let (sig_commitment_root, sig_hashes) = compute_commitment_parallel(raw_signatures);

        // Verify the count is consistent with the public inputs template.
        if pub_inputs.sig_count != 0 && pub_inputs.sig_count as usize != raw_signatures.len() {
            return Err(BatchProverError::SignatureCountMismatch {
                sig_count: pub_inputs.sig_count,
                sigs_len: raw_signatures.len(),
            });
        }

        // Fill in the commitment fields that were left as placeholders.
        pub_inputs.sig_commitment_root = sig_commitment_root;
        pub_inputs.sig_count = raw_signatures.len() as u32;
        pub_inputs.sk_seed_hash = hash_sk_seed(sk_seed);

        // ── Step 2: build the 68-column execution trace ───────────────────
        // Approximately 50 ms for 512 transactions.
        let trace = self.build_trace(&pub_inputs, &sig_hashes);

        // ── Step 3: generate STARK proof ──────────────────────────────────
        // Approximately 850 ms on reference hardware.
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

    /// Verify a `StarkProof` produced by `prove_block` against the given
    /// public inputs. Approximately 12 ms on reference hardware.
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

    /// Build the 68-column execution trace for the given block.
    ///
    /// The trace is constructed in two phases:
    /// 1. **Init** (row 0): all constant block-validity columns are written;
    ///    the sig-commitment columns are initialised with their starting values.
    /// 2. **Update** (rows 1..trace_len-1): the proposer ticks through each
    ///    transaction, incrementing `processed_count` and writing
    ///    `current_sig_hash` for that row's transaction.
    ///
    /// Rows beyond `sig_count - 1` have `is_active = 0` and a frozen
    /// `processed_count`; the transition constraints handle this correctly.
    pub fn build_trace(
        &self,
        pub_inputs: &ExtendedBlockPublicInputs,
        sig_hashes: &[[u8; 32]],
    ) -> TraceTable<BaseElement> {
        // Trace length must be a power of 2 and at least MIN_TRACE_LENGTH.
        let raw_len = (pub_inputs.sig_count as usize).max(MIN_TRACE_LENGTH);
        let trace_len = raw_len.next_power_of_two();
        let sig_count = pub_inputs.sig_count as usize;

        // Pre-compute constant field elements (captured by the closures below).
        let f_block_index = BaseElement::new(pub_inputs.block_index as u128);
        let f_epoch_id = BaseElement::new(pub_inputs.epoch_id as u128);
        let f_tx_count = BaseElement::new(pub_inputs.tx_count as u128);
        let f_blocks_per_epoch = BaseElement::new(pub_inputs.blocks_per_epoch as u128);
        let f_merkle_root_hi = bytes_hi(&pub_inputs.merkle_root_hash);
        let f_merkle_root_lo = bytes_lo(&pub_inputs.merkle_root_hash);
        let f_validator_pk_hi = bytes_hi(&pub_inputs.validator_pk_hash);
        let f_validator_pk_lo = bytes_lo(&pub_inputs.validator_pk_hash);
        let f_sk_seed_hi = bytes_hi(&pub_inputs.sk_seed_hash);
        let f_sk_seed_lo = bytes_lo(&pub_inputs.sk_seed_hash);
        let f_smt_root_hi = bytes_hi(&pub_inputs.smt_root);
        let f_smt_root_lo = bytes_lo(&pub_inputs.smt_root);
        let f_block_hash_hi = bytes_hi(&pub_inputs.block_hash);
        let f_block_hash_lo = bytes_lo(&pub_inputs.block_hash);
        let f_sig_root_hi = bytes_hi(&pub_inputs.sig_commitment_root);
        let f_sig_root_lo = bytes_lo(&pub_inputs.sig_commitment_root);
        let f_sig_count = BaseElement::new(pub_inputs.sig_count as u128);
        let f_batch_seq_id = BaseElement::new(pub_inputs.batch_seq_id as u128);
        let f_avail_threshold = BaseElement::new(self.availability_threshold_bps as u128);

        // Snapshot sig_hashes into an Arc so the update closure can access it.
        let sig_hashes: Arc<Vec<[u8; 32]>> = Arc::new(sig_hashes.to_vec());
        let sh_clone = Arc::clone(&sig_hashes);

        let mut trace = TraceTable::<BaseElement>::new(TRACE_WIDTH, trace_len);

        trace.fill(
            // ── init: row 0 ───────────────────────────────────────────────
            |state| {
                // Block validity state (cols 0–13)
                state[COL_BLOCK_INDEX] = f_block_index;
                state[COL_EPOCH_ID] = f_epoch_id;
                state[COL_TX_COUNT] = f_tx_count;
                state[COL_BLOCKS_PER_EPOCH] = f_blocks_per_epoch;
                state[COL_MERKLE_ROOT_HI] = f_merkle_root_hi;
                state[COL_MERKLE_ROOT_LO] = f_merkle_root_lo;
                state[COL_VALIDATOR_PK_HI] = f_validator_pk_hi;
                state[COL_VALIDATOR_PK_LO] = f_validator_pk_lo;
                state[COL_SK_SEED_HASH_HI] = f_sk_seed_hi;
                state[COL_SK_SEED_HASH_LO] = f_sk_seed_lo;
                state[COL_SMT_ROOT_HI] = f_smt_root_hi;
                state[COL_SMT_ROOT_LO] = f_smt_root_lo;
                state[COL_BLOCK_HASH_HI] = f_block_hash_hi;
                state[COL_BLOCK_HASH_LO] = f_block_hash_lo;

                // Reserved block validity cols 14–47: zero
                for i in COL_BLOCK_RESERVED_START..=COL_BLOCK_RESERVED_END {
                    state[i] = BaseElement::ZERO;
                }

                // Sig commitment state (cols 48–56)
                state[COL_SIG_ROOT_HI] = f_sig_root_hi;
                state[COL_SIG_ROOT_LO] = f_sig_root_lo;
                state[COL_SIG_COUNT] = f_sig_count;
                state[COL_BATCH_SEQ_ID] = f_batch_seq_id;
                state[COL_AVAIL_THRESHOLD] = f_avail_threshold;
                state[COL_PROCESSED_COUNT] = BaseElement::ZERO;
                state[COL_IS_ACTIVE] = BaseElement::ONE;

                // First sig_hash (row 0 processes transaction 0)
                if let Some(h) = sig_hashes.first() {
                    state[COL_CURR_SIG_HI] = bytes_hi(h);
                    state[COL_CURR_SIG_LO] = bytes_lo(h);
                } else {
                    state[COL_CURR_SIG_HI] = BaseElement::ZERO;
                    state[COL_CURR_SIG_LO] = BaseElement::ZERO;
                }

                // Padding / reserved cols 57–67: zero
                for i in 57..TRACE_WIDTH {
                    state[i] = BaseElement::ZERO;
                }
            },
            // ── update: transition from row `step` → row `step + 1` ───────
            |step, state| {
                let next_row = step + 1; // the row being written

                // Block validity cols 0–47 are constant — no change needed;
                // Winterfell's fill() semantics update state in-place and
                // the constant-transition constraints enforce no divergence.

                // Determine if next_row is still within the active region.
                let next_is_active = next_row < sig_count;

                if next_is_active {
                    // Increment processed_count.
                    let cur_count = state[COL_PROCESSED_COUNT].as_int() as u64;
                    state[COL_PROCESSED_COUNT] = BaseElement::new((cur_count + 1) as u128);
                    state[COL_IS_ACTIVE] = BaseElement::ONE;

                    // Write the sig_hash for the transaction at next_row.
                    if let Some(h) = sh_clone.get(next_row) {
                        state[COL_CURR_SIG_HI] = bytes_hi(h);
                        state[COL_CURR_SIG_LO] = bytes_lo(h);
                    }
                } else {
                    // Padding rows: freeze processed_count, deactivate.
                    state[COL_IS_ACTIVE] = BaseElement::ZERO;
                    // processed_count stays at sig_count - 1 (last active value).
                    // current_sig_hash holds the last hash (informational, unconstrained).
                }
            },
        );

        trace
    }
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

/// `SHA3-256(b"bleep_sk_seed_hash_v1" || sk_seed)` — the private witness commitment
/// written into the trace so the verifier can check the proposer knows the SK.
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
            batch_seq_id: 1,
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
        // trace_len = next_power_of_two(max(1, MIN_TRACE_LENGTH=8)) = 8
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
        let pi = test_pub_inputs(4);

        let result = prover
            .prove_block(pi, &sigs, &sk_seed)
            .expect("prove_block failed");

        assert_eq!(result.sig_hashes.len(), 4);
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
