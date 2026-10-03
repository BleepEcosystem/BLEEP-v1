use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Hash-based Merkle path for identity verification (post-quantum secure)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    pub leaf: [u8; 32],
    pub root: [u8; 32],
    pub auth_path: Vec<([u8; 32], bool)>,
}

impl MerklePath {
    pub fn new(leaf: [u8; 32], root: [u8; 32], auth_path: Vec<([u8; 32], bool)>) -> Self {
        Self {
            leaf,
            root,
            auth_path,
        }
    }

    pub fn verify(&self) -> bool {
        let mut current = self.leaf;

        for (sibling, is_right) in &self.auth_path {
            let mut hasher = Sha3_256::new();
            if *is_right {
                hasher.update(sibling);
                hasher.update(current);
            } else {
                hasher.update(current);
                hasher.update(sibling);
            }
            current = hasher.finalize().into();
        }

        current == self.root
    }
}

/// Proof of identity using hash-based Merkle paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProof {
    pub path: MerklePath,
    pub timestamp: u64,
}

pub struct IdentityVerifier {
    pub root: [u8; 32],
}

impl IdentityVerifier {
    pub fn new(root: [u8; 32]) -> Self {
        Self { root }
    }

    pub fn verify_proof(&self, proof: &IdentityProof) -> bool {
        // Verify that the merkle path leads to our trusted root
        proof.path.root == self.root && proof.path.verify()
    }
}

impl IdentityProof {
    pub fn new(path: MerklePath) -> Self {
        Self {
            path,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn verify(&self) -> bool {
        // Verify merkle path
        self.path.verify()
    }
}
