use sha2::{Digest, Sha256};
// use serde::{Deserialize, Serialize};
use ark_ff::PrimeField;
// use ark_ff::{PrimeField, Field};
use ark_bls12_381::Fr;

/// Simple merkle tree path for identity verification
#[derive(Clone, Debug)]
pub struct MerklePath {
    pub leaf: Fr,
    pub root: Fr,
    pub auth_path: Vec<(Fr, bool)>,
}

impl MerklePath {
    pub fn new(leaf: Fr, root: Fr, auth_path: Vec<(Fr, bool)>) -> Self {
        Self {
            leaf,
            root,
            auth_path,
        }
    }

    pub fn verify(&self) -> bool {
        let mut current = self.leaf;

        for (sibling, is_right) in &self.auth_path {
            let mut hasher = Sha256::new();
            let current_bytes = current.to_string().as_bytes().to_vec();
            let sibling_bytes = sibling.to_string().as_bytes().to_vec();
            if *is_right {
                hasher.update(&current_bytes);
                hasher.update(&sibling_bytes);
            } else {
                hasher.update(&sibling_bytes);
                hasher.update(&current_bytes);
            }
            let hash = hasher.finalize();
            current = Fr::from_be_bytes_mod_order(&hash[..]);
        }

        current == self.root
    }
}

/// Proof of identity using merkle paths
#[derive(Debug, Clone)]
pub struct IdentityProof {
    pub path: MerklePath,
    pub timestamp: u64,
}

pub struct IdentityVerifier {
    pub root: Fr,
}

impl IdentityVerifier {
    pub fn new(root: Fr) -> Self {
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
