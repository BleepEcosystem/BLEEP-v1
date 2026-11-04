use bleep_core::merkle_tree::MerklePath as CanonicalMerklePath;
use bleep_core::proof_of_identity::{IdentityProof, IdentityVerifier, MerklePath};
use bleep_crypto::merkle_commitment::{merkle_hash_leaf, version_merkle_root};

fn main() {
    let self_declared_root = [0x11; 32];
    let identity_proof = IdentityProof::new(MerklePath::new(
        self_declared_root,
        self_declared_root,
        vec![],
    ));
    let identity_verifier = IdentityVerifier::new([0x22; 32]);
    println!("H-08a: {}", identity_verifier.verify_proof(&identity_proof));

    let leaf = merkle_hash_leaf(b"attacker-controlled leaf");
    let claimed_root = version_merkle_root(&leaf);
    let merkle_path = CanonicalMerklePath::new(leaf, claimed_root, vec![], vec![]);
    println!("H-08b: {}", merkle_path.verify(&[0x22; 32]));
}
