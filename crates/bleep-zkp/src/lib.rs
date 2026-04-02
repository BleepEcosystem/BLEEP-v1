//! # BLEEP Post-Quantum Proofs
//!
//! ## Block validity proofs
//!
//! Replaces Groth16/BLS12-381 with post-quantum SPHINCS+ detached signatures over
//! canonical block proof messages. Verifiers check that the registered validator
//! public key signed the expected proof payload.

use bleep_crypto::tx_signer::{generate_tx_keypair, sign_tx_payload, verify_tx_signature};
use sha3::{Digest, Sha3_256};

pub const BLOCK_CIRCUIT_PUBLIC_INPUTS: usize = 5;

/// A raw proving key for post-quantum proof generation (SPHINCS+ secret key bytes).
pub type ProvingKey = Vec<u8>;
/// A raw verifying key for post-quantum proof verification (SPHINCS+ public key bytes).
pub type VerifyingKey = Vec<u8>;

/// Generate a post-quantum keypair for devnet startup.
pub fn devnet_setup() -> (ProvingKey, VerifyingKey) {
    let (pk, sk) = generate_tx_keypair();
    (sk, pk)
}

/// Post-quantum block prover that signs canonical proof messages.
pub struct BlockProver {
    sk_bytes: Vec<u8>,
}

impl BlockProver {
    pub fn new(sk_bytes: Vec<u8>) -> Self {
        Self { sk_bytes }
    }

    /// Sign the canonical block proof message using SPHINCS+.
    pub fn prove(&self, proof_message: &[u8]) -> Result<Vec<u8>, String> {
        sign_tx_payload(proof_message, &self.sk_bytes)
    }
}

/// Post-quantum block verifier that validates SPHINCS+ detached signatures.
pub struct BlockVerifier {
    pk_bytes: Vec<u8>,
}

impl BlockVerifier {
    pub fn new(pk_bytes: Vec<u8>) -> Self {
        Self { pk_bytes }
    }

    /// Verify a post-quantum block proof signature.
    pub fn verify(&self, proof_bytes: &[u8], proof_message: &[u8]) -> bool {
        verify_tx_signature(proof_message, proof_bytes, &self.pk_bytes)
    }
}

/// Post-quantum batch prover that signs batched transaction commitments.
pub struct BatchProver {
    sk_bytes: Vec<u8>,
}

impl BatchProver {
    pub fn new(sk_bytes: Vec<u8>) -> Self {
        Self { sk_bytes }
    }

    /// Sign a batch proof payload using SPHINCS+.
    pub fn prove_batch(&self, batch_message: &[u8]) -> Result<Vec<u8>, String> {
        sign_tx_payload(batch_message, &self.sk_bytes)
    }
}

/// Generate a post-quantum keypair for batch proof startup.
pub fn devnet_batch_setup() -> (ProvingKey, VerifyingKey) {
    let (pk, sk) = generate_tx_keypair();
    (sk, pk)
}

/// Compatibility shim: generates a stub proof.
pub fn generate_proof(_witness: &[u8]) -> Vec<u8> {
    vec![0u8; 32]
}

pub struct Prover;
pub struct Verifier;

impl Prover {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier {
    pub fn new() -> Self {
        Self
    }
    /// Stub verifier — always returns true (legacy compat).
    pub fn verify(&self, _proof: &[u8], _public_inputs: &[u8]) -> bool {
        true
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hash_to_31_bytes(data: &[u8]) -> [u8; 31] {
    let digest = Sha3_256::digest(data);
    let mut out = [0u8; 31];
    out.copy_from_slice(&digest[..31]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_devnet_setup_and_block_prove_verify() {
        let (sk, pk) = devnet_setup();
        let prover = BlockProver::new(sk.clone());
        let verifier = BlockVerifier::new(pk.clone());

        let message = b"bleep-block-proof-test";
        let proof_bytes = prover.prove(message).expect("prove failed");

        assert!(!proof_bytes.is_empty(), "proof should be non-empty");
        assert!(
            verifier.verify(&proof_bytes, message),
            "proof verification failed"
        );
    }

    #[test]
    fn test_block_proof_wrong_inputs_fails() {
        let (sk, pk) = devnet_setup();
        let prover = BlockProver::new(sk);
        let verifier = BlockVerifier::new(pk);

        let message = b"bleep-block-proof-test";
        let bad_message = b"bleep-block-proof-fail";
        let proof_bytes = prover.prove(message).expect("prove failed");

        assert!(
            !verifier.verify(&proof_bytes, bad_message),
            "wrong message must fail"
        );
    }

    #[test]
    fn test_batch_proof_and_verify() {
        let (sk, pk) = devnet_batch_setup();
        let prover = BatchProver::new(sk);
        let verifier = BlockVerifier::new(pk);

        let batch_message = b"bleep-batch-proof-test";
        let proof_bytes = prover
            .prove_batch(batch_message)
            .expect("batch prove failed");

        assert!(!proof_bytes.is_empty(), "batch proof should be non-empty");
        assert!(
            verifier.verify(&proof_bytes, batch_message),
            "batch proof verification failed"
        );
    }

    #[test]
    fn test_hash_to_31_bytes() {
        let hash = hash_to_31_bytes(b"bleep test");
        assert_eq!(hash.len(), 31);
    }
}
// ── Hardening-phase modules ────────────────────────────────────────────────────
pub mod mpc_ceremony;

pub use mpc_ceremony::{
    CeremonyError, CeremonyState, MPCCeremony, Participant, StructuredReferenceString,
    VerificationResult, CEREMONY_PHASE, MIN_PARTICIPANTS,
};
