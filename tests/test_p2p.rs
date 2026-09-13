use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bleep_p2p::p2p_node::{NodeHandle, P2PNode, P2PNodeConfig};

async fn start_node(port: u16) -> (Arc<P2PNode>, NodeHandle) {
    let config = P2PNodeConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        bootstrap_peers: vec![],
        peer_manager_config: Default::default(),
    };
    P2PNode::start(config)
        .await
        .expect("Failed to start P2P node")
}

#[tokio::test]
async fn test_p2p_node_connects_peer_and_reports_peer_count() {
    let (node1, handle1) = start_node(17001).await;
    let (node2, handle2) = start_node(17002).await;

    tokio::time::sleep(Duration::from_millis(250)).await;

    let challenge = b"handshake-challenge";
    let proof = node2
        .make_identity_proof(challenge)
        .expect("Failed to create identity proof");

    let peer_id = node1
        .connect_peer(
            SocketAddr::from(([127, 0, 0, 1], 17002)),
            node2.identity.ed_keypair.public_key_bytes(),
            node2.identity.sphincs_keypair.public_key.0.clone(),
            challenge,
            &proof,
        )
        .await
        .expect("Failed to connect peer");

    assert!(!peer_id.as_bytes().is_empty(), "Peer ID must be valid");
    assert_eq!(node1.peer_count(), 1, "Node1 should report one peer");
    assert_eq!(
        node2.peer_count(),
        0,
        "Node2 should report zero peers until it initiates a connection"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}
