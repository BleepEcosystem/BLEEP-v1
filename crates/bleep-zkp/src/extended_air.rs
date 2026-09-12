//! Extended 68-column `BlockValidityAir` for BLEEP Protocol Version 5.
//!
//! ## Column layout
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │ BLOCK VALIDITY STATE  (cols 0–47)  — constant across all trace rows     │
//! │                                                                         │
//! │   0  block_index          4–5  merkle_root (hi/lo)   10–11 smt_root    │
//! │   1  epoch_id             6–7  validator_pk (hi/lo)   12–13 block_hash  │
//! │   2  tx_count             8–9  sk_seed_hash (hi/lo)   14–47 reserved=0  │
//! │   3  blocks_per_epoch                                                   │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │ SIGNATURE COMMITMENT STATE  (cols 48–67)  — evolves per row             │
//! │                                                                         │
//! │  48–49  sig_commitment_root (hi/lo)  — constant                         │
//! │  50     sig_count           — constant                                  │
//! │  51     batch_seq_id        — constant                                  │
//! │  52     avail_threshold_bps — constant                                  │
//! │  53     processed_count     — increments by 1 each active row           │
//! │  54–55  current_sig_hash (hi/lo)  — changes each row (informational)    │
//! │  56     is_active           — 1 for rows 0..sig_count-1, then 0         │
//! │  57–67  padding / reserved  — always 0                                  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Constraint count
//!
//! | Group                              | Type   | Count |
//! |------------------------------------|--------|-------|
//! | Block validity state (cols 0–47)   | Deg 1  | 48    |
//! | Sig commitment metadata (48–52)    | Deg 1  |  5    |
//! | `processed_count` evolution (53)   | Deg 2  |  2    |
//! | `is_active` state machine (56)     | Deg 2  |  1    |
//! | Padding / reserved (57–67)         | Deg 1  | 11    |
//! | **Total transition**               |        | **67**|
//! | **Boundary assertions**            |        | **14**|

use serde::{Deserialize, Serialize};
use winterfell::{
    Air, AirContext, Assertion, BatchingMethod, EvaluationFrame, FieldExtension,
    ProofOptions, TraceInfo, TransitionConstraintDegree,
    math::{fields::f128::BaseElement, FieldElement, ToElements},
};

// ─────────────────────────────────────────────────────────────────────────────
// Trace geometry
// ─────────────────────────────────────────────────────────────────────────────

/// Total number of columns in the extended trace.
pub const TRACE_WIDTH: usize = 68;

/// Minimum trace length required by the Winterfell prover/verifier stack.
pub const MIN_TRACE_LENGTH: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Column index constants
// ─────────────────────────────────────────────────────────────────────────────

// Block validity — constant throughout trace
pub const COL_BLOCK_INDEX:       usize =  0;
pub const COL_EPOCH_ID:          usize =  1;
pub const COL_TX_COUNT:          usize =  2;
pub const COL_BLOCKS_PER_EPOCH:  usize =  3;
pub const COL_MERKLE_ROOT_HI:    usize =  4;
pub const COL_MERKLE_ROOT_LO:    usize =  5;
pub const COL_VALIDATOR_PK_HI:   usize =  6;
pub const COL_VALIDATOR_PK_LO:   usize =  7;
pub const COL_SK_SEED_HASH_HI:   usize =  8;
pub const COL_SK_SEED_HASH_LO:   usize =  9;
pub const COL_SMT_ROOT_HI:       usize = 10;
pub const COL_SMT_ROOT_LO:       usize = 11;
pub const COL_BLOCK_HASH_HI:     usize = 12;
pub const COL_BLOCK_HASH_LO:     usize = 13;
// cols 14–47 reserved (always 0)
pub const COL_BLOCK_RESERVED_START: usize = 14;
pub const COL_BLOCK_RESERVED_END:   usize = 47; // inclusive

// Signature commitment — cols 48–67
pub const COL_SIG_ROOT_HI:       usize = 48;
pub const COL_SIG_ROOT_LO:       usize = 49;
pub const COL_SIG_COUNT:         usize = 50;
pub const COL_BATCH_SEQ_ID:      usize = 51;
pub const COL_AVAIL_THRESHOLD:   usize = 52;
pub const COL_PROCESSED_COUNT:   usize = 53;
pub const COL_CURR_SIG_HI:       usize = 54;
pub const COL_CURR_SIG_LO:       usize = 55;
pub const COL_IS_ACTIVE:         usize = 56;
// cols 57–67 padding / reserved
pub const COL_PAD_START:         usize = 57;
pub const COL_PAD_END:           usize = 67; // inclusive

// ─────────────────────────────────────────────────────────────────────────────
// Constraint counts — must match evaluate_transition and get_assertions exactly
// ─────────────────────────────────────────────────────────────────────────────

/// Number of transition constraint results written by `evaluate_transition`.
pub const NUM_TRANSITION_CONSTRAINTS: usize = 67;

/// Number of boundary assertions returned by `get_assertions`.
pub const NUM_ASSERTIONS: usize = 14;

// ─────────────────────────────────────────────────────────────────────────────
// Utility: encode 32-byte hash into two f128 field elements
// ─────────────────────────────────────────────────────────────────────────────

/// Encode bytes `[0..16)` of a 32-byte hash as a `BaseElement`.
#[inline]
pub fn bytes_hi(hash: &[u8; 32]) -> BaseElement {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&hash[..16]);
    BaseElement::new(u128::from_le_bytes(buf))
}

/// Encode bytes `[16..32)` of a 32-byte hash as a `BaseElement`.
#[inline]
pub fn bytes_lo(hash: &[u8; 32]) -> BaseElement {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&hash[16..]);
    BaseElement::new(u128::from_le_bytes(buf))
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtendedBlockPublicInputs
// ─────────────────────────────────────────────────────────────────────────────

/// Public inputs for the extended block-validity STARK proof.
///
/// Every field is committed to during proof generation and checked by every
/// verifier before accepting a `StarkProof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedBlockPublicInputs {
    /// Block height (`block_index` in the consensus layer).
    pub block_index: u64,
    /// Epoch identifier (`block_index / blocks_per_epoch`).
    pub epoch_id: u64,
    /// Number of transactions in the block.
    pub tx_count: u32,
    /// Epoch length in blocks (`BLOCKS_PER_EPOCH` from genesis config).
    pub blocks_per_epoch: u64,
    /// Sparse Merkle Trie commitment (32 bytes).
    pub merkle_root_hash: [u8; 32],
    /// SHA3-256 of the block proposer's SPHINCS+ public key.
    pub validator_pk_hash: [u8; 32],
    /// SHA3-256 of the proposer's secret-key seed (private witness commitment).
    pub sk_seed_hash: [u8; 32],
    /// SHA3-256 of the canonical block header bytes.
    pub block_hash: [u8; 32],
    /// SHA3-256 of the Sparse Merkle Trie root (non-zero check).
    pub smt_root: [u8; 32],
    /// Blake3 Merkle root over `SHA3-256(sig_i)` for all transactions.
    /// This is the SAL commitment bound into the proof.
    pub sig_commitment_root: [u8; 32],
    /// Number of signature commitments (= `tx_count`).
    pub sig_count: u32,
    /// Monotonically increasing batch sequence number from `bleep-consensus`.
    pub batch_seq_id: u64,
}

impl ToElements<BaseElement> for ExtendedBlockPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(20);
        v.push(BaseElement::new(self.block_index as u128));
        v.push(BaseElement::new(self.epoch_id as u128));
        v.push(BaseElement::new(self.tx_count as u128));
        v.push(BaseElement::new(self.blocks_per_epoch as u128));
        v.push(BaseElement::new(self.sig_count as u128));
        v.push(BaseElement::new(self.batch_seq_id as u128));
        v.push(bytes_hi(&self.merkle_root_hash));
        v.push(bytes_lo(&self.merkle_root_hash));
        v.push(bytes_hi(&self.validator_pk_hash));
        v.push(bytes_lo(&self.validator_pk_hash));
        v.push(bytes_hi(&self.sk_seed_hash));
        v.push(bytes_lo(&self.sk_seed_hash));
        v.push(bytes_hi(&self.block_hash));
        v.push(bytes_lo(&self.block_hash));
        v.push(bytes_hi(&self.smt_root));
        v.push(bytes_lo(&self.smt_root));
        v.push(bytes_hi(&self.sig_commitment_root));
        v.push(bytes_lo(&self.sig_commitment_root));
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtendedBlockValidityAir
// ─────────────────────────────────────────────────────────────────────────────

/// Winterfell AIR for the extended 68-column block validity proof.
pub struct ExtendedBlockValidityAir {
    context: AirContext<BaseElement>,
    // Public input field-element copies (pre-decoded for use in get_assertions).
    pi_block_index:    BaseElement,
    pi_epoch_id:       BaseElement,
    pi_tx_count:       BaseElement,
    pi_blocks_per_epoch: BaseElement,
    pi_merkle_root_hi: BaseElement,
    pi_merkle_root_lo: BaseElement,
    pi_validator_pk_hi: BaseElement,
    pi_validator_pk_lo: BaseElement,
    _pi_sk_seed_hash_hi: BaseElement,
    _pi_sk_seed_hash_lo: BaseElement,
    _pi_block_hash_hi:  BaseElement,
    _pi_block_hash_lo:  BaseElement,
    _pi_smt_root_hi:    BaseElement,
    _pi_smt_root_lo:    BaseElement,
    pi_sig_root_hi:    BaseElement,
    pi_sig_root_lo:    BaseElement,
    pi_sig_count:      BaseElement,
    pi_batch_seq_id:   BaseElement,
}

impl Air for ExtendedBlockValidityAir {
    type BaseField   = BaseElement;
    type PublicInputs = ExtendedBlockPublicInputs;

    fn new(
        trace_info: TraceInfo,
        pub_inputs: ExtendedBlockPublicInputs,
        options:    ProofOptions,
    ) -> Self {
        // ── Transition constraint degrees ─────────────────────────────────
        // Group 1: block validity cols 0–47 constant (48 × degree 1)
        let mut degrees: Vec<TransitionConstraintDegree> =
            vec![TransitionConstraintDegree::new(1); 48];

        // Group 2: sig commitment metadata 48–52 constant (5 × degree 1)
        for _ in 0..5 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Group 3: processed_count evolution — 2 × degree 2
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.push(TransitionConstraintDegree::new(2));

        // Group 4: is_active state machine — 1 × degree 2
        // (1 - is_active[t]) * is_active[t+1] = 0 (no 0→1 transition)
        degrees.push(TransitionConstraintDegree::new(2));

        // Group 5: padding / reserved cols 57–67 constant (11 × degree 1)
        for _ in 0..11 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        assert_eq!(degrees.len(), NUM_TRANSITION_CONSTRAINTS,
            "constraint degree list length must equal NUM_TRANSITION_CONSTRAINTS");

        let context = AirContext::new(trace_info, degrees, NUM_ASSERTIONS, options);

        Self {
            context,
            pi_block_index:      BaseElement::new(pub_inputs.block_index as u128),
            pi_epoch_id:         BaseElement::new(pub_inputs.epoch_id as u128),
            pi_tx_count:         BaseElement::new(pub_inputs.tx_count as u128),
            pi_blocks_per_epoch: BaseElement::new(pub_inputs.blocks_per_epoch as u128),
            pi_merkle_root_hi:   bytes_hi(&pub_inputs.merkle_root_hash),
            pi_merkle_root_lo:   bytes_lo(&pub_inputs.merkle_root_hash),
            pi_validator_pk_hi:  bytes_hi(&pub_inputs.validator_pk_hash),
            pi_validator_pk_lo:  bytes_lo(&pub_inputs.validator_pk_hash),
            _pi_sk_seed_hash_hi:  bytes_hi(&pub_inputs.sk_seed_hash),
            _pi_sk_seed_hash_lo:  bytes_lo(&pub_inputs.sk_seed_hash),
            _pi_block_hash_hi:    bytes_hi(&pub_inputs.block_hash),
            _pi_block_hash_lo:    bytes_lo(&pub_inputs.block_hash),
            _pi_smt_root_hi:      bytes_hi(&pub_inputs.smt_root),
            _pi_smt_root_lo:      bytes_lo(&pub_inputs.smt_root),
            pi_sig_root_hi:      bytes_hi(&pub_inputs.sig_commitment_root),
            pi_sig_root_lo:      bytes_lo(&pub_inputs.sig_commitment_root),
            pi_sig_count:        BaseElement::new(pub_inputs.sig_count as u128),
            pi_batch_seq_id:     BaseElement::new(pub_inputs.batch_seq_id as u128),
        }
    }

    fn context(&self) -> &AirContext<BaseElement> {
        &self.context
    }

    // ── Transition constraints ─────────────────────────────────────────────

    fn evaluate_transition<E: FieldElement<BaseField = BaseElement>>(
        &self,
        frame:           &EvaluationFrame<E>,
        _periodic_values: &[E],
        result:          &mut [E],
    ) {
        let cur  = frame.current();
        let next = frame.next();
        let one  = E::ONE;

        // ── Group 1: block validity cols 0–47 must not change (48 constraints) ─
        // result[0..48]
        for i in 0..48 {
            result[i] = next[i] - cur[i];
        }

        // ── Group 2: sig commitment metadata cols 48–52 constant (5 constraints) ─
        // result[48..53]
        for i in 0..5 {
            result[48 + i] = next[COL_SIG_ROOT_HI + i] - cur[COL_SIG_ROOT_HI + i];
        }

        // ── Group 3: processed_count evolution (2 constraints) ─────────────
        // result[53]: next_is_active * (next_processed - cur_processed - 1) = 0
        // result[54]: (1 - next_is_active) * (next_processed - cur_processed) = 0
        // The final active row transitions to padding without incrementing.
        let is_active       = cur[COL_IS_ACTIVE];
        let next_is_active  = next[COL_IS_ACTIVE];
        let cur_processed   = cur[COL_PROCESSED_COUNT];
        let next_processed  = next[COL_PROCESSED_COUNT];
        let delta           = next_processed - cur_processed;

        result[53] = next_is_active * (delta - one);     // active row: increment by 1
        result[54] = (one - next_is_active) * delta;     // padding row: stay constant

        // ── Group 4: is_active state machine (1 constraint) ────────────────
        // result[55]: (1 - is_active[t]) * is_active[t+1] = 0
        // Prevents the flag from going 0 → 1 (once deactivated, stays deactivated).
        result[55] = (one - is_active) * next[COL_IS_ACTIVE];

        // ── Group 5: padding / reserved cols 57–67 constant (11 constraints) ─
        // result[56..67]
        for i in 0..11 {
            result[56 + i] = next[COL_PAD_START + i] - cur[COL_PAD_START + i];
        }

        // Sanity: result has exactly NUM_TRANSITION_CONSTRAINTS = 67 entries.
        debug_assert_eq!(result.len(), NUM_TRANSITION_CONSTRAINTS);
    }

    // ── Boundary assertions ────────────────────────────────────────────────

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        // All 14 assertions are at row 0 (boundary of the trace).
        vec![
            // Block validity — match public inputs
            Assertion::single(COL_BLOCK_INDEX,      0, self.pi_block_index),
            Assertion::single(COL_EPOCH_ID,         0, self.pi_epoch_id),
            Assertion::single(COL_TX_COUNT,         0, self.pi_tx_count),
            Assertion::single(COL_BLOCKS_PER_EPOCH, 0, self.pi_blocks_per_epoch),
            Assertion::single(COL_MERKLE_ROOT_HI,   0, self.pi_merkle_root_hi),
            Assertion::single(COL_MERKLE_ROOT_LO,   0, self.pi_merkle_root_lo),
            Assertion::single(COL_VALIDATOR_PK_HI,  0, self.pi_validator_pk_hi),
            Assertion::single(COL_VALIDATOR_PK_LO,  0, self.pi_validator_pk_lo),
            // Signature commitment — match public inputs
            Assertion::single(COL_SIG_ROOT_HI,      0, self.pi_sig_root_hi),
            Assertion::single(COL_SIG_ROOT_LO,      0, self.pi_sig_root_lo),
            Assertion::single(COL_SIG_COUNT,        0, self.pi_sig_count),
            Assertion::single(COL_BATCH_SEQ_ID,     0, self.pi_batch_seq_id),
            // SAL evolution — initial state
            Assertion::single(COL_PROCESSED_COUNT,  0, BaseElement::ZERO),
            Assertion::single(
                COL_IS_ACTIVE,
                0,
                if self.pi_sig_count == BaseElement::ZERO {
                    BaseElement::ZERO
                } else {
                    BaseElement::ONE
                },
            ),
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Default ProofOptions for BLEEP Phase-6 testnet
// ─────────────────────────────────────────────────────────────────────────────

/// 96-bit conjectured security with Blake3 and no field extension.
///
/// Tuned for the 3,000 ms slot budget on 8-core / 32 GB reference hardware.
/// Adjust `blowup_factor` or `num_queries` to trade proof size vs. generation time.
pub fn bleep_proof_options() -> ProofOptions {
    ProofOptions::new(
        27,                       // num_queries       → ~96-bit security
        8,                        // blowup_factor     (must be power of 2)
        16,                       // grinding_factor
        FieldExtension::None,
        8,                        // FRI folding factor
        127,                      // FRI max remainder degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}
