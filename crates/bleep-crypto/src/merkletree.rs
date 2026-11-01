use crate::merkle_commitment::{merkle_hash_leaf, merkle_root_from_hashes};

#[derive(Default, Clone, Debug)]
pub struct MerkleTree {
    leaves: Vec<Vec<u8>>,
    root: Vec<u8>,
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree {
            leaves: Vec::new(),
            root: Vec::new(),
        }
    }

    pub fn add_leaf(&mut self, leaf: Vec<u8>) {
        self.leaves.push(leaf);
        self.root = self.calculate_root();
    }

    pub fn contains_leaf(&self, leaf: &[u8]) -> bool {
        self.leaves.iter().any(|existing| existing == leaf)
    }

    pub fn root(&self) -> Vec<u8> {
        self.root.clone()
    }

    fn calculate_root(&self) -> Vec<u8> {
        if self.leaves.is_empty() {
            return vec![0u8; 32];
        }

        let leaf_hashes: Vec<_> = self
            .leaves
            .iter()
            .map(|leaf| merkle_hash_leaf(leaf))
            .collect();
        merkle_root_from_hashes(&leaf_hashes)
            .expect("non-empty leaf hashes have a Merkle root")
            .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_uses_shared_versioned_merkle_format() {
        let leaves = vec![b"left".to_vec(), b"right".to_vec()];
        let expected_hashes: Vec<_> = leaves.iter().map(|leaf| merkle_hash_leaf(leaf)).collect();
        let expected_root = merkle_root_from_hashes(&expected_hashes).unwrap();
        let mut tree = MerkleTree::new();
        for leaf in leaves {
            tree.add_leaf(leaf);
        }
        assert_eq!(tree.root(), expected_root);
    }
}
