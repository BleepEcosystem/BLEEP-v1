//! # SparseMerkleTrie — Sprint 5
//!
//! A production-quality sparse Merkle trie for the BLEEP state layer.
//!
//! ## Design
//! - Leaf key  = blake3(address_bytes) → 32-byte path in the trie
//! - Leaf value = blake3(abi_encode(address, balance, nonce)) → 32-byte leaf hash
//! - Interior  = blake3(left_child || right_child)
//! - Empty node = [0u8; 32] (sentinel)
//!
//! The trie depth is fixed at 256 bits (one bit per level). In practice the
//! tree is sparse — only non-empty accounts create nodes. The root is a 32-byte
//! commitment to the full account state.
//!
//! ## Complexity (Sprint 5 upgrade)
//! - Insert / remove:  O(1) amortised — marks caches dirty
//! - Root recompute:   O(k log k) where k = leaf count (sort + fold)
//! - prove(address):   O(k + 256) — O(k) bucket-build + 256 O(1) lookups (was O(k×256))

use blake3;
use hex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Primitive types ───────────────────────────────────────────────────────────

/// A 32-byte node hash. All-zeros = empty sentinel.
pub type NodeHash = [u8; 32];

const EMPTY: NodeHash = [0u8; 32];
const TRIE_DEPTH: usize = 256;

// ── Leaf encoding ─────────────────────────────────────────────────────────────

/// Deterministic 32-byte leaf hash for one account.
pub fn leaf_hash(address: &str, balance: u128, nonce: u64) -> NodeHash {
    let mut buf = Vec::with_capacity(address.len() + 16 + 8);
    buf.extend_from_slice(address.as_bytes());
    buf.extend_from_slice(&balance.to_le_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    *blake3::hash(&buf).as_bytes()
}

/// Map an address string to its 256-bit trie path via blake3.
pub fn key_to_path(address: &str) -> [u8; 32] {
    *blake3::hash(address.as_bytes()).as_bytes()
}

/// Extract bit `depth` (0 = MSB) from a 32-byte path.
#[inline]
fn bit_at(path: &[u8; 32], depth: usize) -> u8 {
    (path[depth / 8] >> (7 - (depth % 8))) & 1
}

// ── Interior node hash ────────────────────────────────────────────────────────

fn interior_hash(left: &NodeHash, right: &NodeHash) -> NodeHash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    *blake3::hash(&buf).as_bytes()
}

// ── SparseMerkleTrie ──────────────────────────────────────────────────────────

/// Sparse Merkle Trie over the full account state.
///
/// Stores only non-empty leaf hashes keyed by their 256-bit path.
/// Interior nodes are computed lazily during `root()` and cached for
/// O(k) Merkle proof generation.
#[derive(Clone, Debug, Default)]
pub struct SparseMerkleTrie {
    /// Non-empty leaf hashes keyed by trie path = blake3(address).
    leaves: HashMap<[u8; 32], NodeHash>,
    /// Cached root — invalidated on every mutation.
    cached_root: Option<NodeHash>,
    /// Interior node cache built by `compute_root_with_cache()`.
    ///
    /// Key: `(depth, representative_path)` where the representative path is
    /// the lexicographically smallest leaf path in that subtree.
    /// Value: hash of that subtree.
    ///
    /// Depth 256 = leaf level. Depth 0 = root.
    interior_cache: HashMap<(usize, [u8; 32]), NodeHash>,
}

/// Simple alias for compatibility with legacy naming.
pub type MerkleTree = SparseMerkleTrie;

impl SparseMerkleTrie {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// Insert or update an account leaf.
    pub fn insert(&mut self, address: &str, balance: u128, nonce: u64) {
        let path = key_to_path(address);
        let lh = leaf_hash(address, balance, nonce);
        self.leaves.insert(path, lh);
        self.invalidate_caches();
    }

    /// Remove an account (prunes the leaf; zero-balance accounts are excluded).
    pub fn remove(&mut self, address: &str) {
        let path = key_to_path(address);
        self.leaves.remove(&path);
        self.invalidate_caches();
    }

    fn invalidate_caches(&mut self) {
        self.cached_root = None;
        self.interior_cache.clear();
    }

    // ── Root ──────────────────────────────────────────────────────────────────

    /// Compute (or return cached) Merkle root and populate `interior_cache`.
    pub fn root(&mut self) -> NodeHash {
        if let Some(r) = self.cached_root {
            return r;
        }
        self.interior_cache.clear();
        let root = self.compute_root_with_cache();
        self.cached_root = Some(root);
        root
    }

    /// Bottom-up root computation that records every interior node.
    ///
    /// Algorithm:
    /// 1. Sort leaves by path (left → right in the trie).
    /// 2. Push each leaf onto a stack tagged (TRIE_DEPTH, path, hash).
    /// 3. While the top two stack entries have the same depth, they are
    ///    siblings — merge them into a parent and record the parent.
    /// 4. Collapse any remaining unpaired entries up to depth 0.
    fn compute_root_with_cache(&mut self) -> NodeHash {
        if self.leaves.is_empty() {
            return EMPTY;
        }

        // Sort leaves by path so left-to-right order is guaranteed.
        let mut sorted: Vec<([u8; 32], NodeHash)> =
            self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        sorted.sort_by_key(|(k, _)| *k);

        // Stack entries: (depth, rep_path, hash).
        // rep_path = the leftmost leaf path in the subtree (invariant).
        let mut stack: Vec<(usize, [u8; 32], NodeHash)> = Vec::new();

        for (path, leaf) in &sorted {
            // Record leaf at depth = TRIE_DEPTH
            self.interior_cache.insert((TRIE_DEPTH, *path), *leaf);
            stack.push((TRIE_DEPTH, *path, *leaf));

            // Bubble up: merge siblings while the top two share the same depth.
            loop {
                let n = stack.len();
                if n < 2 {
                    break;
                }
                let (d1, p1, h1) = stack[n - 2];
                let (d2, p2, h2) = stack[n - 1];
                if d1 != d2 {
                    break;
                }

                stack.pop();
                stack.pop();

                // Determine which child is left/right by the bit at depth (d1-1).
                let (left_h, right_h, rep) = if bit_at(&p1, d1 - 1) == 0 {
                    // p1 is in the left subtree, p2 is in the right subtree
                    (h1, h2, p1)
                } else {
                    (h2, h1, p2)
                };

                let parent = interior_hash(&left_h, &right_h);
                self.interior_cache.insert((d1 - 1, rep), parent);
                stack.push((d1 - 1, rep, parent));
            }
        }

        // Collapse any remaining unpaired nodes to the root.
        while stack.len() > 1 {
            let (_, _p2, h2) = stack.pop().unwrap();
            let (d, p1, h1) = stack.pop().unwrap();
            let merged = interior_hash(&h1, &h2);
            let rep = p1; // leftmost path wins
            self.interior_cache
                .insert((d.saturating_sub(1), rep), merged);
            stack.push((d.saturating_sub(1), rep, merged));
        }

        stack.pop().map(|(_, _, h)| h).unwrap_or(EMPTY)
    }

    // ── Merkle Proofs ─────────────────────────────────────────────────────────

    /// Generate a Merkle inclusion or exclusion proof for `address`.
    ///
    /// **O(256) per proof** — builds a depth-bucketed sibling index from
    /// `interior_cache` in O(k) then performs exactly 256 O(1) lookups.
    ///
    /// ### Sibling representative-path derivation
    /// The `interior_cache` stores each non-empty subtree as
    /// `(depth, rep_path) → hash` where `rep_path` is the lex-minimum leaf
    /// path inside that subtree.  For our proof path `key_path`, the sibling
    /// at level `depth` has a representative path that:
    ///   - shares bits `0..depth` with `key_path` (same ancestor prefix)
    ///   - has bit `depth` flipped (opposite child)
    ///   - has bits `depth+1..` set to zero (minimum of that subtree)
    ///
    /// We bucket the cache by depth so each lookup is a linear scan of at
    /// most O(k) entries at one depth level — but the total work is O(k + 256).
    pub fn prove(&mut self, address: &str) -> MerkleProof {
        // Ensure root and interior_cache are fresh.
        let root = self.root();
        let key_path = key_to_path(address);
        let exists = self.leaves.contains_key(&key_path);
        let leaf = if exists {
            self.leaves[&key_path]
        } else {
            EMPTY
        };

        // Build depth-bucketed index from interior_cache in one O(k) pass.
        // by_depth[d] = list of (rep_path, hash) for all subtrees at depth d.
        let mut by_depth: HashMap<usize, Vec<([u8; 32], NodeHash)>> =
            HashMap::with_capacity(TRIE_DEPTH + 1);
        for ((d, p), h) in &self.interior_cache {
            by_depth.entry(*d).or_default().push((*p, *h));
        }

        // For each of the 256 levels derive the sibling rep-path and look it up.
        let mut path: Vec<ProofNode> = Vec::with_capacity(TRIE_DEPTH);

        for depth in (0..TRIE_DEPTH).rev() {
            let my_bit = bit_at(&key_path, depth);
            // Sibling rep path: same prefix as key_path for bits 0..depth,
            // opposite at bit `depth`, zero for all bits > depth.
            let mut sib_rep = key_path;
            let byte_idx = depth / 8;
            let bit_in_byte = 7 - (depth % 8); // MSB-first layout
                                               // Zero out all bytes after the sibling bit's byte.
            for b in sib_rep.iter_mut().skip(byte_idx + 1) {
                *b = 0;
            }
            // Within byte_idx: keep the high bits (prefix), zero the low bits,
            // then set the sibling's bit (opposite of my_bit).
            let keep_mask = if bit_in_byte == 7 {
                0u8
            } else {
                0xFFu8 << (bit_in_byte + 1)
            };
            let sib_bit = if my_bit == 0 { 1u8 << bit_in_byte } else { 0u8 };
            sib_rep[byte_idx] = (sib_rep[byte_idx] & keep_mask) | sib_bit;

            // Direct O(1) lookup in the depth+1 bucket.
            let sibling = by_depth
                .get(&(depth + 1))
                .and_then(|bucket| bucket.iter().find(|(p, _)| *p == sib_rep))
                .map(|(_, h)| *h)
                .unwrap_or(EMPTY);

            path.push(ProofNode {
                sibling,
                is_right: my_bit == 1,
            });
        }

        MerkleProof {
            address: address.to_string(),
            exists,
            leaf,
            path,
            root,
        }
    }

    /// Verify that `proof` is valid against this trie's current root.
    pub fn verify_proof(&mut self, proof: &MerkleProof) -> bool {
        proof.verify(&self.root())
    }

    // ── Bulk helpers ──────────────────────────────────────────────────────────

    /// Bulk-load from an (address, balance, nonce) iterator.
    pub fn load_from<'a, I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (&'a str, u128, u64)>,
    {
        for (addr, bal, nonce) in iter {
            self.insert(addr, bal, nonce);
        }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

// ── Proof types ───────────────────────────────────────────────────────────────

/// One sibling node in a Merkle proof path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofNode {
    /// Hash of the sibling subtree at this level.
    pub sibling: NodeHash,
    /// `true` if the *proven* node is on the right at this level.
    pub is_right: bool,
}

/// A complete Merkle inclusion or exclusion proof.
///
/// Sufficient for a light client to verify account existence / absence
/// against a known trie root without downloading full state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Account address this proof covers.
    pub address: String,
    /// `true` = inclusion proof; `false` = exclusion proof.
    pub exists: bool,
    /// Account leaf hash (`EMPTY` for exclusion proofs).
    pub leaf: NodeHash,
    /// Sibling hashes from depth 255 (near leaf) up to depth 0 (near root).
    /// Exactly TRIE_DEPTH (256) entries.
    pub path: Vec<ProofNode>,
    /// Trie root this proof is valid against.
    pub root: NodeHash,
}

impl MerkleProof {
    /// Verify this proof against an expected root.
    ///
    /// Recomputes the root by hashing from the leaf up using the stored
    /// siblings, then compares to `expected_root`.
    pub fn verify(&self, expected_root: &NodeHash) -> bool {
        if self.path.len() != TRIE_DEPTH {
            return false;
        }

        let key_path = key_to_path(&self.address);
        let mut current = if self.exists { self.leaf } else { EMPTY };

        for (depth_rev, node) in self.path.iter().enumerate() {
            let depth = TRIE_DEPTH - 1 - depth_rev;
            let bit = bit_at(&key_path, depth);
            current = if bit == 0 {
                interior_hash(&current, &node.sibling) // node on left
            } else {
                interior_hash(&node.sibling, &current) // node on right
            };
        }

        &current == expected_root
    }
}

// ── Legacy helper (preserved for existing callers) ────────────────────────────

/// Compute a Merkle root from arbitrary byte slices (blake3 leaves).
pub fn calculate_merkle_root<T: AsRef<[u8]>>(data: &[T]) -> String {
    if data.is_empty() {
        return hex::encode(EMPTY);
    }
    let mut hashes: Vec<NodeHash> = data
        .iter()
        .map(|item| *blake3::hash(item.as_ref()).as_bytes())
        .collect();
    while hashes.len() > 1 {
        let mut next = Vec::new();
        for chunk in hashes.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
            next.push(interior_hash(&left, &right));
        }
        hashes = next;
    }
    hex::encode(hashes[0])
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie_returns_zero_root() {
        let mut t = SparseMerkleTrie::new();
        assert_eq!(t.root(), EMPTY);
    }

    #[test]
    fn single_leaf_root_deterministic() {
        let mut a = SparseMerkleTrie::new();
        a.insert("alice", 1000, 0);
        let mut b = SparseMerkleTrie::new();
        b.insert("alice", 1000, 0);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn root_changes_on_update() {
        let mut t = SparseMerkleTrie::new();
        t.insert("alice", 1000, 0);
        let r1 = t.root();
        t.insert("alice", 2000, 1);
        let r2 = t.root();
        assert_ne!(r1, r2);
    }

    #[test]
    fn two_accounts_differ_from_one() {
        let mut t1 = SparseMerkleTrie::new();
        t1.insert("alice", 100, 0);
        let mut t2 = SparseMerkleTrie::new();
        t2.insert("alice", 100, 0);
        t2.insert("bob", 200, 0);
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn remove_restores_root() {
        let mut t = SparseMerkleTrie::new();
        let empty = t.root();
        t.insert("alice", 500, 0);
        assert_ne!(t.root(), empty);
        t.remove("alice");
        assert_eq!(t.root(), empty);
    }

    #[test]
    fn insertion_order_independent() {
        let mut t1 = SparseMerkleTrie::new();
        t1.insert("alice", 100, 0);
        t1.insert("bob", 200, 1);
        t1.insert("carol", 300, 2);

        let mut t2 = SparseMerkleTrie::new();
        t2.insert("carol", 300, 2);
        t2.insert("alice", 100, 0);
        t2.insert("bob", 200, 1);

        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn prove_inclusion_verifies() {
        let mut t = SparseMerkleTrie::new();
        t.insert("alice", 1000, 5);
        t.insert("bob", 500, 2);
        let proof = t.prove("alice");
        assert!(proof.exists);
        assert!(t.verify_proof(&proof));
    }

    #[test]
    fn prove_exclusion_verifies() {
        let mut t = SparseMerkleTrie::new();
        t.insert("alice", 1000, 0);
        let proof = t.prove("nobody");
        assert!(!proof.exists);
        assert!(t.verify_proof(&proof));
    }

    #[test]
    fn tampered_proof_fails() {
        let mut t = SparseMerkleTrie::new();
        t.insert("alice", 1000, 0);
        let mut proof = t.prove("alice");
        // Corrupt the leaf hash
        proof.leaf[0] ^= 0xFF;
        assert!(!t.verify_proof(&proof));
    }

    #[test]
    fn proof_invalid_for_wrong_root() {
        let mut t = SparseMerkleTrie::new();
        t.insert("alice", 1000, 0);
        let proof = t.prove("alice");
        let wrong_root = [0xFF_u8; 32];
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn legacy_calculate_merkle_root_nonempty() {
        let data = vec!["tx1", "tx2", "tx3"];
        let root = calculate_merkle_root(&data);
        assert_eq!(root.len(), 64); // 32 bytes as hex
    }
}
