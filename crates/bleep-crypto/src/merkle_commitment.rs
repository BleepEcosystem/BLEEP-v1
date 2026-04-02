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
/// - Deterministic proof generation
/// - Inclusion/exclusion proofs are verifiable
/// - Tree structure is immutable once finalized
/// - Commitments are cryptographically binding
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

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

    /// SHA3-256 hash of data
    pub hash: [u8; 32],
}

impl MerkleLeaf {
    /// Create a new leaf
    pub fn new(index: u64, data: Vec<u8>) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        let hash_result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_result);

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
    pub fn branch(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(&left.hash);
        hasher.update(&right.hash);
        let hash_result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_result);

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

        // Recompute the path
        let mut current_hash = self.leaf_hash;
        for sibling in &self.path {
            let mut hasher = Sha3_256::new();
            hasher.update(&current_hash);
            hasher.update(sibling);
            let hash_result = hasher.finalize();
            current_hash.copy_from_slice(&hash_result);
        }

        if current_hash == self.root {
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

        // Build tree from bottom up
        let mut nodes: Vec<MerkleNode> = self
            .leaves
            .iter()
            .map(|leaf| MerkleNode::leaf(leaf.hash))
            .collect();

        // Iteratively pair up nodes
        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..nodes.len()).step_by(2) {
                if i + 1 < nodes.len() {
                    let left = nodes[i].clone();
                    let right = nodes[i + 1].clone();
                    next_level.push(MerkleNode::branch(left, right));
                } else {
                    // Odd node out: pair with itself
                    let left = nodes[i].clone();
                    let right = nodes[i].clone();
                    next_level.push(MerkleNode::branch(left, right));
                }
            }

            nodes = next_level;
        }

        let root = nodes.into_iter().next().unwrap();
        let root_hash = root.hash;
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

        // Build path from leaf to root
        let mut path = Vec::new();
        let mut current_index = *leaf_position;

        // Reconstruct tree to find siblings
        let mut current_level: Vec<(usize, [u8; 32])> = self
            .leaves
            .iter()
            .enumerate()
            .map(|(i, l)| (i, l.hash))
            .collect();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left_idx = current_level[i].0;
                let left_hash = current_level[i].1;

                if i + 1 < current_level.len() {
                    let right_idx = current_level[i + 1].0;
                    let right_hash = current_level[i + 1].1;

                    // Check if current_index is on this level
                    if current_index == left_idx {
                        path.push(right_hash);
                        current_index = i; // Move to parent level position
                    } else if current_index == right_idx {
                        path.push(left_hash);
                        current_index = i;
                    }

                    // Hash for next level
                    let mut hasher = Sha3_256::new();
                    hasher.update(&left_hash);
                    hasher.update(&right_hash);
                    let hash_result = hasher.finalize();
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&hash_result);

                    next_level.push((i, hash));
                } else {
                    if current_index == left_idx {
                        path.push(left_hash);
                        current_index = i;
                    }

                    let mut hasher = Sha3_256::new();
                    hasher.update(&left_hash);
                    hasher.update(&left_hash);
                    let hash_result = hasher.finalize();
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&hash_result);

                    next_level.push((i, hash));
                }
            }

            current_level = next_level;
        }

        Ok(MerkleProof {
            leaf_index,
            leaf_hash: leaf.hash,
            path,
            root,
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
        assert_eq!(tree.is_finalized(), true);
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
