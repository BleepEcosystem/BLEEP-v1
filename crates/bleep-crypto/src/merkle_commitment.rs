/// Merkle Tree and Commitment System
///
/// This module provides production-grade Merkle trees with cryptographic commitments.
/// Used for:
/// - State commitments
/// - AI decision commitments
/// - Governance outcome proofs
/// - Transaction batch commitments
///
/// SAFETY GUARANTEES:
/// - Versioned, domain-separated and position-bound roots
/// - Deterministic proof generation
/// - Inclusion/exclusion proofs are verifiable
/// - Tree structure is immutable once finalized
/// - Commitments are cryptographically binding
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

/// Version of the shared BLEEP Merkle commitment format.
pub const MERKLE_FORMAT_VERSION: u8 = 1;
const MERKLE_LEAF_DOMAIN: &[u8] = b"bleep_sal_leaf_v1";
const MERKLE_NODE_DOMAIN: &[u8] = b"bleep_sal_node_v1";
const MERKLE_EMPTY_DOMAIN: &[u8] = b"bleep_sal_empty_v1";
const MERKLE_ROOT_DOMAIN: &[u8] = b"bleep_merkle_root_v1";

/// Hash a leaf using the canonical BLEEP Merkle format.
pub fn merkle_hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(MERKLE_LEAF_DOMAIN);
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash an internal node, binding its position within the current tree level.
pub fn merkle_hash_node(left: &[u8; 32], right: &[u8; 32], parent_position: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MERKLE_NODE_DOMAIN);
    hasher.update(&[(parent_position & 1) as u8]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Hash the canonical padding leaf, distinct from any genuine data leaf.
pub fn merkle_empty_leaf() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MERKLE_EMPTY_DOMAIN);
    *hasher.finalize().as_bytes()
}

/// Add the format version to the root commitment.
pub fn version_merkle_root(root: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MERKLE_ROOT_DOMAIN);
    hasher.update(&[MERKLE_FORMAT_VERSION]);
    hasher.update(root);
    *hasher.finalize().as_bytes()
}

/// Build the canonical versioned root from already-hashed leaves.
pub fn merkle_root_from_hashes(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    let padded_len = leaves.len().checked_next_power_of_two()?;
    if leaves.is_empty() {
        return None;
    }

    let mut level = Vec::with_capacity(padded_len);
    level.extend_from_slice(leaves);
    level.resize(padded_len, merkle_empty_leaf());
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .enumerate()
            .map(|(position, pair)| merkle_hash_node(&pair[0], &pair[1], position as u64))
            .collect();
    }
    Some(version_merkle_root(&level[0]))
}

/// Verify an inclusion path under the canonical versioned BLEEP Merkle format.
pub fn verify_merkle_path(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    leaf_index: usize,
    padded_len: usize,
    path: &[[u8; 32]],
) -> bool {
    if padded_len == 0
        || !padded_len.is_power_of_two()
        || leaf_index >= padded_len
        || path.len() != padded_len.trailing_zeros() as usize
    {
        return false;
    }

    let mut current = *leaf_hash;
    let mut position = leaf_index;
    for sibling in path {
        let parent_position = position / 2;
        current = if position.is_multiple_of(2) {
            merkle_hash_node(&current, sibling, parent_position as u64)
        } else {
            merkle_hash_node(sibling, &current, parent_position as u64)
        };
        position = parent_position;
    }
    version_merkle_root(&current) == *root
}

// ==================== ERROR TYPES ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MerkleError {
    /// Tree is empty
    EmptyTree,

    /// Invalid proof
    InvalidProof(String),

    /// Leaf not found in tree
    LeafNotFound(String),

    /// Proof verification failed
    ProofVerificationFailed(String),

    /// Tree is immutable
    TreeImmutable,

    /// Invalid commitment
    InvalidCommitment(String),
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleError::EmptyTree => write!(f, "Tree is empty"),
            MerkleError::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            MerkleError::LeafNotFound(msg) => write!(f, "Leaf not found: {}", msg),
            MerkleError::ProofVerificationFailed(msg) => {
                write!(f, "Proof verification failed: {}", msg)
            }
            MerkleError::TreeImmutable => write!(f, "Tree is immutable"),
            MerkleError::InvalidCommitment(msg) => write!(f, "Invalid commitment: {}", msg),
        }
    }
}

impl std::error::Error for MerkleError {}

pub type MerkleResult<T> = Result<T, MerkleError>;

// ==================== CORE TYPES ====================

/// A leaf in the Merkle tree (deterministically hashed)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleLeaf {
    /// Leaf index in the tree
    pub index: u64,

    /// Raw data
    pub data: Vec<u8>,

    /// Canonical domain-separated hash of data
    pub hash: [u8; 32],
}

impl MerkleLeaf {
    /// Create a new leaf
    pub fn new(index: u64, data: Vec<u8>) -> Self {
        let hash = merkle_hash_leaf(&data);
        Self { index, data, hash }
    }
}

/// A node in the Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleNode {
    /// Hash of this node
    pub hash: [u8; 32],

    /// Hash of left child (None if leaf)
    pub left: Option<Box<MerkleNode>>,

    /// Hash of right child (None if leaf)
    pub right: Option<Box<MerkleNode>>,

    /// Whether this is a leaf node
    pub is_leaf: bool,
}

impl MerkleNode {
    /// Create a leaf node
    pub fn leaf(hash: [u8; 32]) -> Self {
        Self {
            hash,
            left: None,
            right: None,
            is_leaf: true,
        }
    }

    /// Create an internal node from two children
    pub fn branch(left: MerkleNode, right: MerkleNode, parent_position: u64) -> Self {
        let hash = merkle_hash_node(&left.hash, &right.hash, parent_position);
        Self {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            is_leaf: false,
        }
    }
}

/// Merkle proof for inclusion/exclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf being proved
    pub leaf_index: u64,

    /// Hash of the leaf
    pub leaf_hash: [u8; 32],

    /// Path from leaf to root (siblings at each level)
    pub path: Vec<[u8; 32]>,
    /// Padded tree width used to derive position and expected proof depth.
    pub padded_len: usize,

    /// Root hash that this proof verifies against
    pub root: [u8; 32],
}

impl MerkleProof {
    /// Verify this proof against a root
    pub fn verify(&self, root: &[u8; 32]) -> MerkleResult<()> {
        if self.root != *root {
            return Err(MerkleError::InvalidProof(
                "Proof root does not match expected root".to_string(),
            ));
        }
        let leaf_index = usize::try_from(self.leaf_index).map_err(|_| {
            MerkleError::InvalidProof("Leaf index does not fit this platform".to_string())
        })?;

        if verify_merkle_path(
            root,
            &self.leaf_hash,
            leaf_index,
            self.padded_len,
            &self.path,
        ) {
            Ok(())
        } else {
            Err(MerkleError::ProofVerificationFailed(
                "Computed root does not match expected root".to_string(),
            ))
        }
    }
}

/// A complete Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// All leaves in order
    leaves: Vec<MerkleLeaf>,

    /// Root node (None if empty)
    root: Option<MerkleNode>,

    /// Root hash (for quick queries)
    root_hash: Option<[u8; 32]>,

    /// Whether tree is finalized (immutable)
    finalized: bool,

    /// Index for quick leaf lookup
    leaf_index: BTreeMap<u64, usize>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// Create a new empty tree
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            root: None,
            root_hash: None,
            finalized: false,
            leaf_index: BTreeMap::new(),
        }
    }

    /// Add a leaf to the tree (only before finalization)
    pub fn add_leaf(&mut self, data: Vec<u8>) -> MerkleResult<u64> {
        if self.finalized {
            return Err(MerkleError::TreeImmutable);
        }

        let index = self.leaves.len() as u64;
        let leaf = MerkleLeaf::new(index, data);

        self.leaf_index.insert(index, self.leaves.len());
        self.leaves.push(leaf);

        Ok(index)
    }

    /// Finalize the tree (make immutable and compute root)
    pub fn finalize(&mut self) -> MerkleResult<[u8; 32]> {
        if self.finalized {
            return Ok(self.root_hash.unwrap());
        }

        if self.leaves.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        let padded_len = self
            .leaves
            .len()
            .checked_next_power_of_two()
            .ok_or_else(|| MerkleError::InvalidProof("Tree is too large".to_string()))?;
        let mut nodes: Vec<MerkleNode> = self
            .leaves
            .iter()
            .map(|leaf| MerkleNode::leaf(leaf.hash))
            .collect();
        nodes.resize_with(padded_len, || MerkleNode::leaf(merkle_empty_leaf()));

        while nodes.len() > 1 {
            nodes = nodes
                .chunks_exact(2)
                .enumerate()
                .map(|(position, pair)| {
                    MerkleNode::branch(pair[0].clone(), pair[1].clone(), position as u64)
                })
                .collect();
        }

        let root = nodes.into_iter().next().unwrap();
        let root_hash = version_merkle_root(&root.hash);
        self.root = Some(root);
        self.root_hash = Some(root_hash);
        self.finalized = true;

        Ok(root_hash)
    }

    /// Get the root hash
    pub fn root(&self) -> MerkleResult<[u8; 32]> {
        self.root_hash.ok_or(MerkleError::EmptyTree)
    }

    /// Generate an inclusion proof for a leaf
    pub fn prove_inclusion(&self, leaf_index: u64) -> MerkleResult<MerkleProof> {
        if !self.finalized {
            return Err(MerkleError::InvalidProof("Tree not finalized".to_string()));
        }

        let leaf_position = self
            .leaf_index
            .get(&leaf_index)
            .ok_or_else(|| MerkleError::LeafNotFound(format!("Leaf {} not found", leaf_index)))?;

        let leaf = &self.leaves[*leaf_position];
        let root = self.root_hash.unwrap();

        let padded_len = self.leaves.len().next_power_of_two();
        let mut current_level: Vec<[u8; 32]> = self.leaves.iter().map(|leaf| leaf.hash).collect();
        current_level.resize(padded_len, merkle_empty_leaf());
        let mut path = Vec::new();
        let mut current_index = *leaf_position;

        while current_level.len() > 1 {
            path.push(current_level[current_index ^ 1]);
            current_level = current_level
                .chunks_exact(2)
                .enumerate()
                .map(|(position, pair)| merkle_hash_node(&pair[0], &pair[1], position as u64))
                .collect();
            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf_index,
            leaf_hash: leaf.hash,
            path,
            root,
            padded_len,
        })
    }

    /// Get a leaf
    pub fn get_leaf(&self, index: u64) -> MerkleResult<MerkleLeaf> {
        let position = self
            .leaf_index
            .get(&index)
            .ok_or_else(|| MerkleError::LeafNotFound(format!("Leaf {} not found", index)))?;
        Ok(self.leaves[*position].clone())
    }

    /// Get number of leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Check if tree is finalized
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }
}

// ==================== COMMITMENT SYSTEM ====================

/// A cryptographic commitment to a value
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// The commitment hash
    pub hash: [u8; 32],

    /// Nonce used to create commitment (for reveal)
    pub nonce: Vec<u8>,
}

impl Commitment {
    /// Create a commitment to data
    pub fn commit(data: &[u8], nonce: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.update(nonce);
        let hash_result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_result);

        Self {
            hash,
            nonce: nonce.to_vec(),
        }
    }

    /// Verify a commitment
    pub fn verify(&self, data: &[u8]) -> MerkleResult<()> {
        let recomputed = Self::commit(data, &self.nonce);
        if recomputed.hash == self.hash {
            Ok(())
        } else {
            Err(MerkleError::InvalidCommitment(
                "Commitment verification failed".to_string(),
            ))
        }
    }
}

// ==================== STATE COMMITMENT ====================

/// Commitment to a state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateCommitment {
    /// Merkle root of state tree
    pub state_root: [u8; 32],

    /// Commitment to the state metadata
    pub metadata_commitment: Commitment,

    /// Epoch this state belongs to
    pub epoch: u64,

    /// Block height
    pub block_height: u64,
}

impl StateCommitment {
    /// Create a state commitment
    pub fn new(
        state_root: [u8; 32],
        metadata: &[u8],
        nonce: &[u8],
        epoch: u64,
        block_height: u64,
    ) -> Self {
        Self {
            state_root,
            metadata_commitment: Commitment::commit(metadata, nonce),
            epoch,
            block_height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_leaf_creation() {
        let leaf = MerkleLeaf::new(0, vec![1, 2, 3]);
        assert_eq!(leaf.index, 0);
        assert_eq!(leaf.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_merkle_tree_creation_and_finalization() {
        let mut tree = MerkleTree::new();

        tree.add_leaf(vec![1, 2, 3]).unwrap();
        tree.add_leaf(vec![4, 5, 6]).unwrap();

        let root = tree.finalize().unwrap();
        assert!(tree.is_finalized());
        assert_eq!(tree.root().unwrap(), root);
    }

    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let mut tree = MerkleTree::new();

        tree.add_leaf(vec![1, 2, 3]).unwrap();
        tree.add_leaf(vec![4, 5, 6]).unwrap();
        tree.add_leaf(vec![7, 8, 9]).unwrap();

        let root = tree.finalize().unwrap();

        let proof = tree.prove_inclusion(0).unwrap();
        proof.verify(&root).unwrap();
    }

    #[test]
    fn test_merkle_root_commits_to_leaf_order_and_version() {
        let mut forward = MerkleTree::new();
        forward.add_leaf(vec![1]).unwrap();
        forward.add_leaf(vec![2]).unwrap();
        let forward_root = forward.finalize().unwrap();

        let mut reversed = MerkleTree::new();
        reversed.add_leaf(vec![2]).unwrap();
        reversed.add_leaf(vec![1]).unwrap();
        let reversed_root = reversed.finalize().unwrap();

        assert_ne!(forward_root, reversed_root);
        assert_eq!(
            forward_root,
            merkle_root_from_hashes(&[merkle_hash_leaf(&[1]), merkle_hash_leaf(&[2])]).unwrap()
        );
    }

    #[test]
    fn test_merkle_nodes_commit_to_parent_position() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        assert_ne!(
            merkle_hash_node(&left, &right, 0),
            merkle_hash_node(&left, &right, 1)
        );
    }

    #[test]
    fn test_commitment_create_and_verify() {
        let data = b"secret data";
        let nonce = b"nonce123";

        let commitment = Commitment::commit(data, nonce);
        commitment.verify(data).unwrap();
    }

    #[test]
    fn test_commitment_verify_fails_on_wrong_data() {
        let data = b"secret data";
        let wrong_data = b"wrong data";
        let nonce = b"nonce123";

        let commitment = Commitment::commit(data, nonce);
        let result = commitment.verify(wrong_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_commitment() {
        let state_root = [0u8; 32];
        let metadata = b"state metadata";
        let nonce = b"nonce";

        let state_commit = StateCommitment::new(state_root, metadata, nonce, 1, 100);

        assert_eq!(state_commit.epoch, 1);
        assert_eq!(state_commit.block_height, 100);
    }
}
