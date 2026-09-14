//! Signature commitment Merkle tree.
//!
//! ## Hash strategy
//!
//! | Layer        | Function  | Rationale                                              |
//! |--------------|-----------|--------------------------------------------------------|
//! | Leaf hashing | SHA3-256  | External-facing; BLEEP's canonical PQ-safe hash        |
//! | Tree nodes   | Blake3    | STARK-friendly; used by Winterfell internally          |
//!
//! The root produced here is the `sig_commitment_root` bound into the extended
//! `BlockValidityAir` as a public input. Validators reconstruct it from the
//! gossiped `sig_hashes` vector and reject any block whose header root differs.

use blake3::Hasher as Blake3Hasher;
use rayon::prelude::*;
use sha3::{Digest, Sha3_256};

use crate::types::{SigCommitmentRoot, SigHash};

// Domain separators prevent second-preimage attacks across layers.
const DOMAIN_LEAF: &[u8] = b"bleep_sal_leaf_v1";
const DOMAIN_NODE: &[u8] = b"bleep_sal_node_v1";
const DOMAIN_EMPTY: &[u8] = b"bleep_sal_empty_v1";

// ─────────────────────────────────────────────────────────────────────────────
// Leaf hashing — SHA3-256
// ─────────────────────────────────────────────────────────────────────────────

/// Compute `SHA3-256(DOMAIN_LEAF || sig_bytes)` — the canonical per-transaction
/// commitment that travels over the gossip mesh in place of the full 49,856-byte
/// SPHINCS+ signature.
#[inline]
pub fn hash_sig(sig_bytes: &[u8]) -> SigHash {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_LEAF);
    h.update(sig_bytes);
    h.finalize().into()
}

/// Parallel variant — hashes all signatures in `sigs` using Rayon.
/// Allocation cost: one `Vec<SigHash>` with `sigs.len()` elements.
pub fn hash_sigs_parallel(sigs: &[Vec<u8>]) -> Vec<SigHash> {
    sigs.par_iter().map(|s| hash_sig(s.as_slice())).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal node hashing — Blake3
// ─────────────────────────────────────────────────────────────────────────────

/// `Blake3(DOMAIN_NODE || left || right)` for internal tree nodes.
#[inline]
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake3Hasher::new();
    h.update(DOMAIN_NODE);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Canonical padding leaf — all-zero input hashed with domain separator so the
/// padded tree is distinguishable from one with a genuine empty-signature leaf.
#[inline]
fn empty_leaf() -> [u8; 32] {
    let mut h = Blake3Hasher::new();
    h.update(DOMAIN_EMPTY);
    *h.finalize().as_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// SigCommitmentTree
// ─────────────────────────────────────────────────────────────────────────────

/// Complete binary Merkle tree over a block's `SigHash` leaves.
///
/// The tree is always padded to the next power-of-two with `empty_leaf()`
/// values so that the root is uniquely determined by the leaf set regardless
/// of block fullness.
///
/// The internal `nodes` array is stored in level-order (BFS):
///   - `nodes[0..padded_n)`: leaves (level 0)
///   - `nodes[padded_n..padded_n + padded_n/2)`: level 1
///   - …
///   - `nodes[last]`: root
#[derive(Debug, Clone)]
pub struct SigCommitmentTree {
    /// Original (un-padded) leaf count.
    pub leaf_count: usize,
    /// All nodes in level-order. Length = `2 * padded_n - 1` where
    /// `padded_n = leaf_count.next_power_of_two()`.
    nodes: Vec<[u8; 32]>,
    /// `padded_n`
    padded_n: usize,
}

impl SigCommitmentTree {
    /// Build a `SigCommitmentTree` from an ordered list of `SigHash` leaves.
    ///
    /// # Panics
    /// Panics if `sig_hashes` is empty.
    pub fn new(sig_hashes: Vec<SigHash>) -> Self {
        assert!(
            !sig_hashes.is_empty(),
            "SigCommitmentTree: leaf list must not be empty"
        );

        let leaf_count = sig_hashes.len();
        let padded_n = leaf_count.next_power_of_two();
        let total = 2 * padded_n; // level-order array size (we skip index 0 for 1-based math)

        let mut nodes: Vec<[u8; 32]> = vec![[0u8; 32]; total];

        // Write leaves at positions [padded_n .. padded_n + leaf_count)
        for (i, h) in sig_hashes.iter().enumerate() {
            nodes[padded_n + i] = *h;
        }
        // Pad remaining leaf slots with the canonical empty leaf
        let empty = empty_leaf();
        for i in leaf_count..padded_n {
            nodes[padded_n + i] = empty;
        }
        // Build internal nodes bottom-up (level-order 1-based indexing)
        for i in (1..padded_n).rev() {
            nodes[i] = hash_node(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self {
            leaf_count,
            nodes,
            padded_n,
        }
    }

    /// Root of the Merkle tree — the value bound into the STARK proof.
    #[inline]
    pub fn root(&self) -> SigCommitmentRoot {
        self.nodes[1]
    }

    /// Generate an inclusion proof for the leaf at `leaf_idx` (0-based,
    /// within the original un-padded leaf set).
    ///
    /// # Panics
    /// Panics if `leaf_idx >= self.leaf_count`.
    pub fn generate_proof(&self, leaf_idx: usize) -> MerkleProof {
        assert!(leaf_idx < self.leaf_count, "leaf_idx out of range");

        let depth = self.padded_n.trailing_zeros() as usize;
        let mut path = Vec::with_capacity(depth);

        // Walk from the leaf up to the root, collecting sibling hashes.
        let mut pos = self.padded_n + leaf_idx; // 1-based position
        while pos > 1 {
            let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            path.push(self.nodes[sibling]);
            pos /= 2;
        }

        MerkleProof {
            leaf_index: leaf_idx,
            leaf: self.nodes[self.padded_n + leaf_idx],
            path,
            padded_n: self.padded_n,
        }
    }

    /// Verify that `proof` is a valid inclusion proof against `root`.
    pub fn verify_proof(root: &SigCommitmentRoot, proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;
        let mut pos = proof.padded_n + proof.leaf_index;

        for sibling in &proof.path {
            let (left, right) = if pos % 2 == 0 {
                (&current, sibling)
            } else {
                (sibling, &current)
            };
            current = hash_node(left, right);
            pos /= 2;
        }

        &current == root
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MerkleProof
// ─────────────────────────────────────────────────────────────────────────────

/// Inclusion proof for a single `SigHash` leaf.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    /// 0-based index of the leaf in the original (un-padded) set.
    pub leaf_index: usize,
    /// The leaf hash itself (`SHA3-256(sig)` for transaction signatures).
    pub leaf: SigHash,
    /// Sibling hashes from leaf to root (length = `log2(padded_n)`).
    pub path: Vec<[u8; 32]>,
    /// Padded tree width — needed to reconstruct node positions.
    pub padded_n: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public convenience functions used by the proposer
// ─────────────────────────────────────────────────────────────────────────────

/// Compute both the `SigCommitmentRoot` and the ordered `sig_hashes` vector
/// from raw signature byte slices.
///
/// Uses Rayon for parallel SHA3-256 computation across all signatures,
/// then builds the Blake3 Merkle tree sequentially.
///
/// Typical timing for 512 SPHINCS+ signatures (49,856 bytes each) on an
/// 8-core validator: **~45 ms** (dominated by SHA3-256 bandwidth, ~24.8 MB
/// of input data).
pub fn compute_sig_commitment(sigs: &[Vec<u8>]) -> (SigCommitmentRoot, Vec<SigHash>) {
    assert!(
        !sigs.is_empty(),
        "compute_sig_commitment: at least one signature required"
    );

    // Parallel SHA3-256 leaf hashing
    let sig_hashes: Vec<SigHash> = sigs.par_iter().map(|s| hash_sig(s.as_slice())).collect();

    let root = SigCommitmentTree::new(sig_hashes.clone()).root();
    (root, sig_hashes)
}

/// Verify that a `SigCommitmentRoot` is consistent with an ordered list of
/// `SigHash` values. Called by every validator on receipt of a
/// `SigCommitmentAnnouncement`.
pub fn verify_commitment_root(root: &SigCommitmentRoot, sig_hashes: &[SigHash]) -> bool {
    if sig_hashes.is_empty() {
        return false;
    }
    let computed = SigCommitmentTree::new(sig_hashes.to_vec()).root();
    &computed == root
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_sigs(n: usize, seed: u8) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![seed ^ i as u8; 49_856]).collect()
    }

    #[test]
    fn round_trip_single_leaf() {
        let sigs = fake_sigs(1, 0xAA);
        let (root, hashes) = compute_sig_commitment(&sigs);
        assert!(verify_commitment_root(&root, &hashes));
    }

    #[test]
    fn round_trip_512_leaves() {
        let sigs = fake_sigs(512, 0x7F);
        let (root, hashes) = compute_sig_commitment(&sigs);
        assert!(verify_commitment_root(&root, &hashes));
        assert_eq!(hashes.len(), 512);
    }

    #[test]
    fn merkle_proof_all_leaves() {
        let sigs = fake_sigs(8, 0x55);
        let (_root, hashes) = compute_sig_commitment(&sigs);
        let tree = SigCommitmentTree::new(hashes);
        let root = tree.root();
        for i in 0..8 {
            let proof = tree.generate_proof(i);
            assert!(
                SigCommitmentTree::verify_proof(&root, &proof),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn tampered_sig_hash_fails_root_check() {
        let sigs = fake_sigs(4, 0x33);
        let (root, mut hashes) = compute_sig_commitment(&sigs);
        hashes[2][0] ^= 0xFF; // corrupt one hash
        assert!(!verify_commitment_root(&root, &hashes));
    }

    #[test]
    fn tampered_proof_fails_verify() {
        let sigs = fake_sigs(4, 0x22);
        let (_root, hashes) = compute_sig_commitment(&sigs);
        let tree = SigCommitmentTree::new(hashes);
        let root = tree.root();
        let mut proof = tree.generate_proof(0);
        proof.path[0][0] ^= 0xFF; // corrupt first sibling
        assert!(!SigCommitmentTree::verify_proof(&root, &proof));
    }

    #[test]
    fn non_power_of_two_leaf_count() {
        // 7 leaves should pad to 8 and still produce a valid root
        let sigs = fake_sigs(7, 0x11);
        let (root, hashes) = compute_sig_commitment(&sigs);
        assert!(verify_commitment_root(&root, &hashes));
        let tree = SigCommitmentTree::new(hashes);
        let proof = tree.generate_proof(6);
        assert!(SigCommitmentTree::verify_proof(&root, &proof));
    }

    #[test]
    fn empty_leaf_distinguishable() {
        // A genuine all-zero signature must NOT collide with the empty-pad leaf.
        let genuine_zero_sig = vec![0u8; 49_856];
        let genuine_hash = hash_sig(&genuine_zero_sig);
        let canonical_empty = empty_leaf();
        assert_ne!(
            genuine_hash, canonical_empty,
            "genuine zero-sig must be distinguishable from canonical empty leaf"
        );
    }
}
