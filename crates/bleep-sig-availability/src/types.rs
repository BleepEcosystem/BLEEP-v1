//! Wire and internal data types for the Signature Availability Layer.
//!
//! ## Key change from v1
//!
//! `SigAvailabilityAttestation` (one 49,856-byte SPHINCS+ sig **per transaction**)
//! is replaced by `BatchBlockAttestation` (one 49,856-byte SPHINCS+ sig **per
//! validator per block**), paired with a compact `TxBitmap` recording exactly
//! which transactions that validator has verified.
//!
//! Bandwidth comparison for 512 tx, N validators:
//!
//! ```text
//! v1 (per-tx):   N × 512 × ~50 KB  = N × 25.6 MB  ← worse than the original
//! v2 (per-block): N × 1 × ~50 KB   = N × 50 KB    ← 99.8% reduction vs v1
//! ```

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

// ─────────────────────────────────────────────────────────────────────────────
// Primitive aliases
// ─────────────────────────────────────────────────────────────────────────────

/// SHA3-256 of a single SPHINCS+ transaction signature.
pub type SigHash = [u8; 32];

/// Blake3 Merkle root over all `SigHash` values in a block.
pub type SigCommitmentRoot = [u8; 32];

// ─────────────────────────────────────────────────────────────────────────────
// BlockId
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId {
    pub height: u64,
    pub block_hash: [u8; 32],
}

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "block@{}:{}",
            self.height,
            hex::encode(&self.block_hash[..4])
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TxBitmap — compact transaction coverage bitfield
// ─────────────────────────────────────────────────────────────────────────────

/// Compact bitfield recording which transactions a validator has verified.
///
/// For 512 transactions: 512 bits = 64 bytes — negligible overhead.
/// Bit `i` is 1 iff the holder has verified transaction `i`'s SPHINCS+ signature.
///
/// Used in `BatchBlockAttestation` to record per-tx coverage in a single
/// 64-byte field rather than one attestation message per transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxBitmap {
    bits: Vec<u8>,
    capacity: u32,
}

impl TxBitmap {
    /// Create a zeroed bitmap for `tx_count` transactions.
    pub fn new(tx_count: u32) -> Self {
        let byte_count = ((tx_count as usize) + 7) / 8;
        Self {
            bits: vec![0u8; byte_count],
            capacity: tx_count,
        }
    }

    /// Mark transaction `tx_index` as verified. No-op if out of range.
    pub fn set(&mut self, tx_index: u32) {
        if tx_index >= self.capacity {
            return;
        }
        let byte = tx_index as usize / 8;
        let bit = tx_index as usize % 8;
        self.bits[byte] |= 1 << bit;
    }

    /// Returns `true` if transaction `tx_index` is marked verified.
    pub fn is_set(&self, tx_index: u32) -> bool {
        if tx_index >= self.capacity {
            return false;
        }
        let byte = tx_index as usize / 8;
        let bit = tx_index as usize % 8;
        (self.bits[byte] >> bit) & 1 == 1
    }

    /// Number of transactions marked verified in this bitmap.
    #[inline]
    pub fn count_set(&self) -> u32 {
        self.bits.iter().map(|b| b.count_ones()).sum()
    }

    /// Maximum number of transactions this bitmap can represent.
    #[inline]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Returns `true` iff no transaction has been marked.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }

    /// Merge `other` into `self` (bitwise OR in-place).
    /// Expands `self` if `other` has higher capacity.
    pub fn merge(&mut self, other: &TxBitmap) {
        if other.capacity > self.capacity {
            let new_byte_count = ((other.capacity as usize) + 7) / 8;
            self.bits.resize(new_byte_count, 0);
            self.capacity = other.capacity;
        }
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= b;
        }
    }

    /// `SHA3-256(b"bleep_tx_bitmap_v1" || bits)` — included in the
    /// `BatchBlockAttestation` signing payload to prevent bitmap substitution.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"bleep_tx_bitmap_v1");
        h.update(&self.bits);
        h.finalize().into()
    }

    /// Raw bitmap bytes for serialisation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Announcement (proposer → mesh)
// ─────────────────────────────────────────────────────────────────────────────

/// Broadcast by the block proposer after producing a block.
/// Contains the full ordered sig_hashes list and the Blake3 Merkle root
/// that is bound inside the STARK proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigCommitmentAnnouncement {
    pub block_id: BlockId,
    pub sig_commitment_root: SigCommitmentRoot,
    pub sig_count: u32,
    /// `sig_hashes[i] = SHA3-256(tx[i].signature)` — 32 bytes per tx.
    pub sig_hashes: Vec<SigHash>,
    /// SPHINCS+ sig over `signing_payload(...)`.
    pub proposer_sig: Vec<u8>,
    /// Proposer SPHINCS+ public key (64 bytes).
    pub proposer_pk: Vec<u8>,
}

impl SigCommitmentAnnouncement {
    pub fn signing_payload(block_id: &BlockId, root: &SigCommitmentRoot, count: u32) -> Vec<u8> {
        let mut h = Sha3_256::new();
        h.update(b"bleep_sal_announcement_v1");
        h.update(block_id.height.to_le_bytes());
        h.update(block_id.block_hash);
        h.update(root);
        h.update(count.to_le_bytes());
        h.finalize().to_vec()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchBlockAttestation (validator → mesh)
// ─────────────────────────────────────────────────────────────────────────────

/// One attestation per validator per **block** — not per transaction.
///
/// A validator that has verified all 512 transactions produces a 64-byte
/// bitmap plus ONE 49,856-byte SPHINCS+ signature for the entire block.
///
/// ## Bandwidth
///
/// For N validators and 512 tx/block:
///
/// | N validators | Attestation bytes |
/// |---|---|
/// | 7   (testnet min) | 7  × ~50 KB = ~350 KB |
/// | 21  (typical)     | 21 × ~50 KB = ~1.05 MB |
/// | 50  (Phase 6 target) | 50 × ~50 KB = ~2.5 MB |
/// | 100 (mainnet target) | 100 × ~50 KB = ~5 MB  |
///
/// Compare to v1 per-tx design: 7 × 512 × ~50 KB = ~174 MB at N=7.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchBlockAttestation {
    pub block_id: BlockId,
    /// The sig_commitment_root this validator confirmed against its mempool.
    pub sig_commitment_root: SigCommitmentRoot,
    /// Compact bitfield: bit i = 1 means this validator verified tx[i].
    pub attested_bitmap: TxBitmap,
    /// `attested_bitmap.count_set()` — cached for fast threshold checks.
    pub attested_count: u32,
    /// SHA3-256 of this validator's SPHINCS+ public key.
    pub validator_pk_hash: [u8; 32],
    /// ONE 49,856-byte SPHINCS+ sig over `signing_payload(...)`.
    pub attestation_sig: Vec<u8>,
    /// SPHINCS+ public key (64 bytes) for verification.
    pub validator_pk: Vec<u8>,
}

impl BatchBlockAttestation {
    /// Canonical signing payload — covers block identity, commitment root,
    /// attested count, and a hash of the bitmap to prevent bitmap substitution.
    pub fn signing_payload(
        block_id: &BlockId,
        sig_commitment_root: &SigCommitmentRoot,
        attested_count: u32,
        bitmap_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut h = Sha3_256::new();
        h.update(b"bleep_batch_attestation_v1");
        h.update(block_id.height.to_le_bytes());
        h.update(block_id.block_hash);
        h.update(sig_commitment_root);
        h.update(attested_count.to_le_bytes());
        h.update(bitmap_hash);
        h.finalize().to_vec()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Retrieval (slashing evidence)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigRetrievalRequest {
    pub block_id: BlockId,
    pub tx_index: u32,
    pub requester_pk_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigRetrievalResponse {
    pub block_id: BlockId,
    pub tx_index: u32,
    pub full_sig: Vec<u8>,
    pub tx_signer_pk: Vec<u8>,
}

impl Drop for SigRetrievalResponse {
    fn drop(&mut self) {
        self.full_sig.zeroize();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level gossip envelope
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigAvailabilityMessage {
    Announcement(SigCommitmentAnnouncement),
    /// One batch attestation per validator per block.
    BatchAttestation(BatchBlockAttestation),
    RetrievalRequest(SigRetrievalRequest),
    RetrievalResponse(SigRetrievalResponse),
}

impl SigAvailabilityMessage {
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockSigAvailabilityStatus — dual-dimension coverage
// ─────────────────────────────────────────────────────────────────────────────

/// Availability status returned to the consensus gate before finalisation.
///
/// Two independent dimensions must both meet the threshold:
///
/// 1. **Validator coverage** — what fraction of the active validator set has
///    submitted a valid `BatchBlockAttestation`.
/// 2. **Transaction coverage** — what fraction of the block's transactions
///    appear in the union of all received attestation bitmaps.
///
/// Both must reach `required_threshold_bps` for `threshold_met = true`.
#[derive(Debug, Clone)]
pub struct BlockSigAvailabilityStatus {
    pub block_id: BlockId,
    pub sig_commitment_root: SigCommitmentRoot,

    // ── Transaction dimension ─────────────────────────────────────────────
    /// Total transactions in the block.
    pub total_txs: u32,
    /// Transactions covered by ≥ 1 validator's attestation bitmap.
    pub covered_txs: u32,
    /// `covered_txs / total_txs` in basis points (0–10,000).
    pub tx_coverage_bps: u32,

    // ── Validator dimension ───────────────────────────────────────────────
    /// Validators currently in the active set (from `ValidatorRegistry`).
    pub active_validator_count: u32,
    /// Validators that submitted a valid `BatchBlockAttestation`.
    pub attesting_validator_count: u32,
    /// `attesting_validator_count / active_validator_count` in basis points.
    pub validator_coverage_bps: u32,

    // ── Threshold gate ────────────────────────────────────────────────────
    /// `true` iff BOTH `tx_coverage_bps` AND `validator_coverage_bps` >= threshold.
    pub threshold_met: bool,
}

impl BlockSigAvailabilityStatus {
    #[inline]
    pub fn is_available(&self) -> bool {
        self.threshold_met
    }
}
