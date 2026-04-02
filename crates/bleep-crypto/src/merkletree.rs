use sha3::{Digest, Sha3_256};

#[derive(Default, Clone, Debug)]
pub struct MerkleTree {
    leaves: Vec<Vec<u8>>,
    root: Vec<u8>,
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree {
            leaves: vec![],
            root: vec![],
        }
    }

    pub fn add_leaf(&mut self, leaf: Vec<u8>) {
        self.leaves.push(leaf);
        self.root = self.calculate_root();
    }

    pub fn contains_leaf(&self, leaf: &[u8]) -> bool {
        self.leaves.iter().any(|l| l == leaf)
    }

    pub fn root(&self) -> Vec<u8> {
        self.root.clone()
    }

    fn calculate_root(&self) -> Vec<u8> {
        if self.leaves.is_empty() {
            return vec![0u8; 32];
        }
        let mut hashes: Vec<Vec<u8>> = self
            .leaves
            .iter()
            .map(|leaf| {
                let mut hasher = Sha3_256::new();
                hasher.update(leaf);
                hasher.finalize().to_vec()
            })
            .collect();
        while hashes.len() > 1 {
            let mut next_level = vec![];
            for pair in hashes.chunks(2) {
                let mut hasher = Sha3_256::new();
                hasher.update(&pair[0]);
                if pair.len() == 2 {
                    hasher.update(&pair[1]);
                }
                next_level.push(hasher.finalize().to_vec());
            }
            hashes = next_level;
        }
        hashes[0].clone()
    }
}
