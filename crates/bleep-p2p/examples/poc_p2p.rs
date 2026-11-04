use bleep_p2p::error::P2PError;
use bleep_p2p::peer_manager::{PeerManager, PeerManagerConfig};
use bleep_p2p::quantum_crypto::SphincsKeypair;
use bleep_p2p::types::NodeId;

fn main() {
    let identity_key = SphincsKeypair::generate();
    let signing_key = SphincsKeypair::generate();
    let identity_public_key = identity_key.public_key_bytes();
    let node_id = NodeId::from_bytes(&identity_public_key);
    let (peer_manager, _) = PeerManager::new(node_id.clone(), PeerManagerConfig::default());

    let challenge = peer_manager
        .issue_identity_challenge(node_id)
        .expect("issue verifier-owned challenge");
    let signature = signing_key.sign(&challenge.nonce);
    let result = peer_manager.verify_identity_proof(
        challenge.connection_id,
        identity_public_key,
        signing_key.public_key_bytes(),
        &signature,
    );

    match result {
        Err(P2PError::AuthenticationFailed) => {
            println!("[3] AuthenticationFailed (mismatched identity and signer rejected)");
        }
        Err(error) => panic!("PoC failed at step [3] with unexpected error: {error}"),
        Ok(_) => panic!("PoC unexpectedly authenticated mismatched identity and signer keys"),
    }
}
