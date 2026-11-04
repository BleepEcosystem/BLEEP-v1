use bleep_crypto::merkle_commitment::verify_merkle_path;
use bleep_state::state_merkle::SparseMerkleTrie;
use serde::{Deserialize, Serialize};

/// Hash-based Merkle path for identity verification (post-quantum secure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePath {
    pub leaf_hash: [u8; 32],
    pub root_hash: [u8; 32],
    pub proof_elements: Vec<[u8; 32]>,
    pub path_indices: Vec<bool>, // true = right, false = left
}

impl MerklePath {
    pub fn new(
        leaf_hash: [u8; 32],
        root_hash: [u8; 32],
        proof_elements: Vec<[u8; 32]>,
        path_indices: Vec<bool>,
    ) -> Self {
        Self {
            leaf_hash,
            root_hash,
            proof_elements,
            path_indices,
        }
    }

    /// Verify the Merkle path against a root obtained from a trusted source.
    pub fn verify(&self, trusted_root: &[u8; 32]) -> bool {
        if self.root_hash != *trusted_root {
            return false;
        }

        let depth = self.proof_elements.len();
        if self.path_indices.len() != depth || depth >= usize::BITS as usize {
            return false;
        }

        let Some(padded_len) = 1usize.checked_shl(depth as u32) else {
            return false;
        };
        let mut leaf_index = 0usize;
        for (level, is_right) in self.path_indices.iter().enumerate() {
            if *is_right {
                let Some(bit) = 1usize.checked_shl(level as u32) else {
                    return false;
                };
                leaf_index |= bit;
            }
        }

        verify_merkle_path(
            &self.root_hash,
            &self.leaf_hash,
            leaf_index,
            padded_len,
            &self.proof_elements,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityProof {
    pub merkle_path: MerklePath,
    pub leaf_hash: [u8; 32],
    pub proof: Vec<u8>, // SPHINCS+ signature proof
}

pub struct ProofOfIdentity {
    merkle_tree: SparseMerkleTrie,
}

impl ProofOfIdentity {
    /// Create a new identity proof system
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            merkle_tree: SparseMerkleTrie::new(),
        })
    }

    /// Generate a proof for a user
    pub fn generate_proof(
        &self,
        user_address: &str,
        balance: u128,
        nonce: u64,
    ) -> Result<IdentityProof, String> {
        // Insert the user into the tree
        let mut temp_tree = self.merkle_tree.clone();
        temp_tree.insert(user_address, balance, nonce);

        // Generate Merkle proof
        let leaf_hash = bleep_state::state_merkle::leaf_hash(user_address, balance, nonce);
        let root_hash = temp_tree.root();

        // For simplicity, we'll create a basic proof structure
        // In production, you'd need to implement proper Merkle proof generation
        let proof_elements = vec![[0u8; 32]; 256]; // Placeholder
        let path_indices = vec![false; 256]; // Placeholder

        let merkle_path = MerklePath::new(leaf_hash, root_hash, proof_elements, path_indices);

        // Generate SPHINCS+ proof (placeholder)
        let proof = vec![0u8; 64]; // SPHINCS+ signature would go here

        Ok(IdentityProof {
            merkle_path,
            leaf_hash,
            proof,
        })
    }

    pub fn verify_proof(&self, proof: &IdentityProof, trusted_root: &[u8; 32]) -> bool {
        proof.merkle_path.verify(trusted_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_crypto::merkle_commitment::{merkle_hash_node, version_merkle_root};

    #[test]
    fn verifies_canonical_position_bound_path() {
        let leaf_hash = [1u8; 32];
        let sibling_at_level_0 = [2u8; 32];
        let sibling_at_level_1 = [3u8; 32];
        let left_parent = merkle_hash_node(&leaf_hash, &sibling_at_level_0, 1);
        let tree_root = merkle_hash_node(&sibling_at_level_1, &left_parent, 0);
        let proof = MerklePath::new(
            leaf_hash,
            version_merkle_root(&tree_root),
            vec![sibling_at_level_0, sibling_at_level_1],
            vec![false, true],
        );

        assert!(proof.verify(&version_merkle_root(&tree_root)));
    }

    #[test]
    fn rejects_path_direction_length_mismatch() {
        let proof = MerklePath::new([1u8; 32], [2u8; 32], vec![[3u8; 32]], vec![]);
        assert!(!proof.verify(&[2u8; 32]));
    }

    #[test]
    fn rejects_unrepresentable_path_depth() {
        let proof = MerklePath::new(
            [1u8; 32],
            [2u8; 32],
            vec![[3u8; 32]; usize::BITS as usize],
            vec![false; usize::BITS as usize],
        );
        assert!(!proof.verify(&[2u8; 32]));
    }
}
