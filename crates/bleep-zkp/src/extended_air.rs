//! AIR for bounded block metadata and commitment fields.
//!
//! The AIR constrains epoch arithmetic, transaction/signature counts, the
//! transaction cap, and batch sequence using range-constrained witnesses.
//! Hash preimages, transaction signature verification, commitment-root
//! derivation, and state-transition execution are not proved here; those remain
//! the responsibility of conventional block validation and execution.

use serde::{Deserialize, Serialize};
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, BatchingMethod, EvaluationFrame, FieldExtension, ProofOptions,
    TraceInfo, TransitionConstraintDegree,
};

pub const TRACE_WIDTH: usize = 48;
pub const MIN_TRACE_LENGTH: usize = 32;
pub const MAX_BLOCK_TRANSACTIONS: u32 = 4_096;

pub const COL_BLOCK_INDEX: usize = 0;
pub const COL_EPOCH_ID: usize = 1;
pub const COL_TX_COUNT: usize = 2;
pub const COL_BLOCKS_PER_EPOCH: usize = 3;
pub const COL_MERKLE_ROOT_HI: usize = 4;
pub const COL_MERKLE_ROOT_LO: usize = 5;
pub const COL_VALIDATOR_PK_HI: usize = 6;
pub const COL_VALIDATOR_PK_LO: usize = 7;
pub const COL_SK_SEED_HASH_HI: usize = 8;
pub const COL_SK_SEED_HASH_LO: usize = 9;
pub const COL_SMT_ROOT_HI: usize = 10;
pub const COL_SMT_ROOT_LO: usize = 11;
pub const COL_BLOCK_HASH_HI: usize = 12;
pub const COL_BLOCK_HASH_LO: usize = 13;
pub const COL_SIG_ROOT_HI: usize = 14;
pub const COL_SIG_ROOT_LO: usize = 15;
pub const COL_SIG_COUNT: usize = 16;
pub const COL_BATCH_SEQ_ID: usize = 17;
pub const COL_EPOCH_REMAINDER: usize = 18;
pub const COL_EPOCH_REMAINDER_GAP: usize = 19;
pub const COL_TX_COUNT_GAP: usize = 20;
pub const COL_BLOCKS_PER_EPOCH_INVERSE: usize = 21;
pub const COL_RANGE_BITS_START: usize = 22;
pub const COL_RANGE_BITS_END: usize = 37;
pub const COL_RANGE_VALUE: usize = 38;
pub const COL_RESERVED_START: usize = 39;
pub const COL_RESERVED_END: usize = 47;

const EPOCH_REMAINDER_LIMB: usize = 20;
const EPOCH_REMAINDER_GAP_LIMB: usize = 21;
const TX_COUNT_GAP_LIMB: usize = 22;
pub(crate) const NUM_RANGE_LIMBS: usize = 23;

pub const NUM_TRANSITION_CONSTRAINTS: usize = 54;
pub const NUM_ASSERTIONS: usize = 59;

#[inline]
pub fn bytes_hi(hash: &[u8; 32]) -> BaseElement {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&hash[..16]);
    BaseElement::new(u128::from_le_bytes(buf))
}

#[inline]
pub fn bytes_lo(hash: &[u8; 32]) -> BaseElement {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&hash[16..]);
    BaseElement::new(u128::from_le_bytes(buf))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedBlockPublicInputs {
    pub block_index: u64,
    pub epoch_id: u64,
    pub tx_count: u32,
    pub blocks_per_epoch: u64,
    pub merkle_root_hash: [u8; 32],
    pub validator_pk_hash: [u8; 32],
    pub sk_seed_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub smt_root: [u8; 32],
    pub sig_commitment_root: [u8; 32],
    pub sig_count: u32,
    pub batch_seq_id: u64,
}

impl ToElements<BaseElement> for ExtendedBlockPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            BaseElement::new(self.block_index as u128),
            BaseElement::new(self.epoch_id as u128),
            BaseElement::new(self.tx_count as u128),
            BaseElement::new(self.blocks_per_epoch as u128),
            bytes_hi(&self.merkle_root_hash),
            bytes_lo(&self.merkle_root_hash),
            bytes_hi(&self.validator_pk_hash),
            bytes_lo(&self.validator_pk_hash),
            bytes_hi(&self.sk_seed_hash),
            bytes_lo(&self.sk_seed_hash),
            bytes_hi(&self.smt_root),
            bytes_lo(&self.smt_root),
            bytes_hi(&self.block_hash),
            bytes_lo(&self.block_hash),
            bytes_hi(&self.sig_commitment_root),
            bytes_lo(&self.sig_commitment_root),
            BaseElement::new(self.sig_count as u128),
            BaseElement::new(self.batch_seq_id as u128),
        ]
    }
}

impl ExtendedBlockPublicInputs {
    /// Check the metadata relationships enforced by this AIR.
    pub fn is_consistent(&self) -> bool {
        self.blocks_per_epoch != 0
            && self.tx_count == self.sig_count
            && self.tx_count <= MAX_BLOCK_TRANSACTIONS
            && self.sig_count <= MAX_BLOCK_TRANSACTIONS
            && self.batch_seq_id == self.block_index
            && self.epoch_id == self.block_index / self.blocks_per_epoch
    }
}

pub struct ExtendedBlockValidityAir {
    context: AirContext<BaseElement>,
    pub_inputs: ExtendedBlockPublicInputs,
    range_values: Vec<BaseElement>,
}

impl Air for ExtendedBlockValidityAir {
    type BaseField = BaseElement;
    type PublicInputs = ExtendedBlockPublicInputs;

    fn new(
        trace_info: TraceInfo,
        pub_inputs: ExtendedBlockPublicInputs,
        options: ProofOptions,
    ) -> Self {
        let mut degrees = Vec::with_capacity(NUM_TRANSITION_CONSTRAINTS);
        degrees.extend((0..18).map(|_| TransitionConstraintDegree::new(1)));
        degrees.extend((0..4).map(|_| TransitionConstraintDegree::new(1)));
        degrees.extend((0..16).map(|_| TransitionConstraintDegree::new(2)));
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.extend((0..4).map(|_| TransitionConstraintDegree::new(1)));
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.extend((0..9).map(|_| TransitionConstraintDegree::new(1)));
        assert_eq!(degrees.len(), NUM_TRANSITION_CONSTRAINTS);

        let epoch_remainder = if pub_inputs.blocks_per_epoch == 0 {
            0
        } else {
            pub_inputs.block_index % pub_inputs.blocks_per_epoch
        };
        let epoch_remainder_gap = pub_inputs
            .blocks_per_epoch
            .saturating_sub(epoch_remainder.saturating_add(1));
        let tx_count_gap = u64::from(MAX_BLOCK_TRANSACTIONS)
            .saturating_sub(u64::from(pub_inputs.tx_count));
        Self {
            context: AirContext::new(trace_info, degrees, NUM_ASSERTIONS, options),
            range_values: range_values(&pub_inputs, epoch_remainder, epoch_remainder_gap, tx_count_gap),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<BaseElement> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let one = E::ONE;
        let mut index = 0;

        for column in 0..18 {
            result[index] = next[column] - current[column];
            index += 1;
        }
        for column in COL_EPOCH_REMAINDER..=COL_BLOCKS_PER_EPOCH_INVERSE {
            result[index] = next[column] - current[column];
            index += 1;
        }

        let mut reconstructed = E::ZERO;
        let mut bit_weight = E::ONE;
        for bit_column in COL_RANGE_BITS_START..=COL_RANGE_BITS_END {
            let bit = current[bit_column];
            result[index] = bit * (bit - one);
            index += 1;
            reconstructed += bit * bit_weight;
            bit_weight += bit_weight;
        }
        result[index] = current[COL_RANGE_VALUE] - reconstructed;
        index += 1;

        result[index] = current[COL_BLOCK_INDEX]
            - current[COL_EPOCH_ID] * current[COL_BLOCKS_PER_EPOCH]
            - current[COL_EPOCH_REMAINDER];
        index += 1;
        result[index] = current[COL_EPOCH_REMAINDER]
            + current[COL_EPOCH_REMAINDER_GAP]
            + one
            - current[COL_BLOCKS_PER_EPOCH];
        index += 1;
        let max_tx = E::from(BaseElement::new(u64::from(MAX_BLOCK_TRANSACTIONS) as u128));
        result[index] = current[COL_TX_COUNT] + current[COL_TX_COUNT_GAP] - max_tx;
        index += 1;
        result[index] = current[COL_TX_COUNT] - current[COL_SIG_COUNT];
        index += 1;
        result[index] = current[COL_BATCH_SEQ_ID] - current[COL_BLOCK_INDEX];
        index += 1;
        result[index] = current[COL_BLOCKS_PER_EPOCH]
            * current[COL_BLOCKS_PER_EPOCH_INVERSE]
            - one;
        index += 1;

        for column in COL_RESERVED_START..=COL_RESERVED_END {
            result[index] = next[column] - current[column];
            index += 1;
        }
        debug_assert_eq!(index, NUM_TRANSITION_CONSTRAINTS);
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let mut assertions: Vec<_> = self
            .pub_inputs
            .to_elements()
            .into_iter()
            .enumerate()
            .map(|(column, value)| Assertion::single(column, 0, value))
            .collect();

        for (row, value) in self.range_values.iter().copied().enumerate() {
            assertions.push(Assertion::single(COL_RANGE_VALUE, row, value));
        }

        for row in [8, 14, 22] {
            for bit_column in COL_RANGE_BITS_START + 13..=COL_RANGE_BITS_END {
                assertions.push(Assertion::single(bit_column, row, BaseElement::ZERO));
            }
        }

        for column in COL_RESERVED_START..=COL_RESERVED_END {
            assertions.push(Assertion::single(column, 0, BaseElement::ZERO));
        }

        debug_assert_eq!(assertions.len(), NUM_ASSERTIONS);
        assertions
    }
}

pub(crate) fn range_values(
    inputs: &ExtendedBlockPublicInputs,
    epoch_remainder: u64,
    epoch_remainder_gap: u64,
    tx_count_gap: u64,
) -> Vec<BaseElement> {
    let mut values = Vec::with_capacity(NUM_RANGE_LIMBS);
    push_u64_limbs(&mut values, inputs.block_index);
    push_u64_limbs(&mut values, inputs.epoch_id);
    push_u32_limbs(&mut values, inputs.tx_count);
    push_u64_limbs(&mut values, inputs.blocks_per_epoch);
    push_u32_limbs(&mut values, inputs.sig_count);
    push_u64_limbs(&mut values, inputs.batch_seq_id);
    values.push(BaseElement::new(epoch_remainder as u128));
    values.push(BaseElement::new(epoch_remainder_gap as u128));
    values.push(BaseElement::new(tx_count_gap as u128));
    debug_assert_eq!(values.len(), NUM_RANGE_LIMBS);
    values
}

fn push_u64_limbs(values: &mut Vec<BaseElement>, value: u64) {
    for shift in [0, 16, 32, 48] {
        values.push(BaseElement::from(((value >> shift) & 0xffff) as u64));
    }
}

fn push_u32_limbs(values: &mut Vec<BaseElement>, value: u32) {
    for shift in [0, 16] {
        values.push(BaseElement::from(((value >> shift) & 0xffff) as u64));
    }
}

pub fn bleep_proof_options() -> ProofOptions {
    ProofOptions::new(
        27,
        8,
        16,
        FieldExtension::None,
        8,
        127,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_witness_has_fixed_48_column_trace_layout() {
        let inputs = ExtendedBlockPublicInputs {
            block_index: 999,
            epoch_id: 9,
            tx_count: 12,
            blocks_per_epoch: 100,
            merkle_root_hash: [0x11; 32],
            validator_pk_hash: [0x22; 32],
            sk_seed_hash: [0x33; 32],
            block_hash: [0x44; 32],
            smt_root: [0x55; 32],
            sig_commitment_root: [0x66; 32],
            sig_count: 12,
            batch_seq_id: 999,
        };
        let values = range_values(&inputs, 99, 0, 4_084);
        assert_eq!(TRACE_WIDTH, 48);
        assert_eq!(values.len(), NUM_RANGE_LIMBS);
        assert_eq!(values[EPOCH_REMAINDER_LIMB], BaseElement::from(99u64));
        assert_eq!(values[EPOCH_REMAINDER_GAP_LIMB], BaseElement::ZERO);
        assert_eq!(values[TX_COUNT_GAP_LIMB], BaseElement::from(4_084u64));
        assert!(inputs.is_consistent());
        let mut zero_epoch_length = inputs;
        zero_epoch_length.blocks_per_epoch = 0;
        assert!(!zero_epoch_length.is_consistent());
    }
}
