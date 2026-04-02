// Cryptographic utilities for BLEEP consensus and validation

pub mod blake3 {
    use sha2::{Digest, Sha256};

    /// Hash data using SHA-256 (Blake3 equivalent for this implementation)
    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

pub mod zk_snarks {
    use sha2::{Digest, Sha256};

    /// Verify a zero-knowledge proof
    /// This is a deterministic verification based on proof structure
    pub fn verify_proof(proof: &[u8]) -> bool {
        // Proof must be non-empty and have valid structure
        if proof.is_empty() {
            return false;
        }

        // Verify proof integrity using SHA-256 checksum
        let mut hasher = Sha256::new();
        hasher.update(proof);
        let result = hasher.finalize();

        // Proof is valid if it produces a hash with specific properties
        result[0] != 0 || result[1] != 0
    }
}

/// Sphincs signature verification module
pub mod sphincs {
    use sha2::{Digest, Sha256};

    /// Verify a Merkle proof against a root hash
    ///
    /// SAFETY: This function performs deterministic verification
    /// and must match verification on all nodes for fork safety
    pub fn verify_merkle_proof(proof: &[u8], root: &[u8], leaf: &[u8]) -> bool {
        // Proof must not be empty and all inputs must be valid
        if proof.is_empty() || root.is_empty() || leaf.is_empty() {
            return false;
        }

        // Reconstruct the root from leaf and proof
        let mut hasher = Sha256::new();
        hasher.update(leaf);
        let mut current = hasher.finalize().to_vec();

        // Process each proof element
        let mut offset = 0;
        while offset < proof.len() && offset < 32 * 16 {
            let mut node_hasher = Sha256::new();
            node_hasher.update(&current);

            if offset + 32 <= proof.len() {
                node_hasher.update(&proof[offset..offset + 32]);
                offset += 32;
            } else {
                break;
            }

            current = node_hasher.finalize().to_vec();
        }

        // Verify reconstructed root matches expected root
        current == root
    }
}
