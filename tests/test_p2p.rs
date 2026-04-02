use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use core::block::block::Block;
use core::blockchain_state::BlockchainState;
use core::p2p::message_protocol::P2PMessage;
use core::p2p::P2PNode;
use core::transaction::transaction::Transaction;

#[test]
fn test_block_propagation_between_nodes() {
    // Set up blockchain states
    let blockchain1 = Arc::new(Mutex::new(BlockchainState::new()));
    let blockchain2 = Arc::new(Mutex::new(BlockchainState::new()));

    // Initialize nodes
    let node1 = P2PNode::new(
        "Node1".into(),
        "127.0.0.1:9101".parse::<SocketAddr>().unwrap(),
        blockchain1.clone(),
    );
    let node2 = P2PNode::new(
        "Node2".into(),
        "127.0.0.1:9102".parse::<SocketAddr>().unwrap(),
        blockchain2.clone(),
    );

    // Start both nodes
    node1.start();
    node2.start();

    thread::sleep(Duration::from_secs(2)); // Wait for nodes to bind and be ready

    // Create and send block from node1 to node2
    let tx = Transaction::new("alice", "bob", 500, "zk_sig");
    let block = Block::new(1, "0".to_string(), vec![tx.clone()]).unwrap();

    node1.send_message(
        "127.0.0.1:9102".parse().unwrap(),
        P2PMessage::NewBlock(block.clone()),
    );

    thread::sleep(Duration::from_secs(2)); // Wait for message to be processed

    // Check blockchain2 state
    let chain2 = blockchain2.lock().unwrap();
    assert_eq!(
        chain2.chain.len(),
        2,
        "Node2 should have received the new block"
    );
    assert_eq!(chain2.chain[1].transactions[0], tx);
}
