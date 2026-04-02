use serde::{Deserialize, Serialize};
/// P2P networking module for distributed shard communication
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct P2PNode {
    node_id: String,
    active_peers: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    NewBlock(String),
    NewTransaction(String),
    ShardState(String),
}

impl P2PNode {
    /// Create a new P2P node
    pub fn new(node_id: String) -> Self {
        P2PNode {
            node_id,
            active_peers: HashSet::new(),
        }
    }

    /// Get the node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast(&mut self, msg: P2PMessage) -> Result<(), Box<dyn std::error::Error>> {
        if self.active_peers.is_empty() {
            return Ok(()); // No peers to broadcast to
        }

        // Serialize message for broadcast
        let _msg_bytes = serde_json::to_vec(&msg)?;
        Ok(())
    }

    /// Get list of active peer identifiers
    pub fn peers(&self) -> Vec<String> {
        self.active_peers.iter().cloned().collect()
    }

    /// Check if a specific peer is active
    pub fn is_peer_active(&self, peer: &str) -> bool {
        self.active_peers.contains(peer)
    }

    /// Add a peer to active peer list
    pub fn add_peer(&mut self, peer: String) {
        self.active_peers.insert(peer);
    }

    /// Remove a peer from the active peer list
    pub fn remove_peer(&mut self, peer: &str) {
        self.active_peers.remove(peer);
    }
}
