//! Core types shared across the bleep-p2p crate.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// NODE IDENTITY
// ─────────────────────────────────────────────────────────────────────────────

/// A 32-byte node identifier derived from the node's public key via SHA-256.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, zeroize::Zeroize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Derive a NodeId from arbitrary bytes (e.g., a public key).
    pub fn from_bytes(input: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(input);
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        NodeId(id)
    }

    /// Generate a random NodeId (for testing / bootstrap nodes).
    pub fn random() -> Self {
        use rand::RngCore;
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        NodeId(id)
    }

    /// XOR distance metric used by Kademlia.
    pub fn xor_distance(&self, other: &NodeId) -> [u8; 32] {
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = self.0[i] ^ other.0[i];
        }
        dist
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PEER STATUS & INFO
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    /// Newly seen, not yet vetted.
    Candidate,
    /// Verified, trust score above threshold.
    Healthy,
    /// Borderline trust score; monitored.
    Suspicious,
    /// Confirmed malicious behaviour.
    Malicious,
    /// Permanently removed; no reconnection allowed.
    Banned,
}

impl fmt::Display for PeerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerStatus::Candidate => write!(f, "candidate"),
            PeerStatus::Healthy => write!(f, "healthy"),
            PeerStatus::Suspicious => write!(f, "suspicious"),
            PeerStatus::Malicious => write!(f, "malicious"),
            PeerStatus::Banned => write!(f, "banned"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub status: PeerStatus,
    /// Score in [0.0, 100.0].  Above 70 → Healthy, 40–70 → Suspicious, below 40 → Malicious.
    pub trust_score: f64,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Number of successful interactions.
    pub success_count: u64,
    /// Number of failed / anomalous interactions.
    pub failure_count: u64,
    /// Ed25519 public key bytes (32 bytes).
    pub public_key: Vec<u8>,
    /// SPHINCS+ public key bytes for post-quantum identity.
    pub sphincs_public_key: Vec<u8>,
}

impl PeerInfo {
    pub fn new(
        id: NodeId,
        addr: SocketAddr,
        public_key: Vec<u8>,
        sphincs_public_key: Vec<u8>,
    ) -> Self {
        let now = unix_now();
        PeerInfo {
            id,
            addr,
            status: PeerStatus::Candidate,
            trust_score: 50.0,
            first_seen: now,
            last_seen: now,
            success_count: 0,
            failure_count: 0,
            public_key,
            sphincs_public_key,
        }
    }

    pub fn touch(&mut self) {
        self.last_seen = unix_now();
    }

    pub fn record_success(&mut self) {
        self.success_count += 1;
        self.last_seen = unix_now();
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_seen = unix_now();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MESSAGE TYPES
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Raw blockchain transaction.
    Transaction,
    /// New or syncing block.
    Block,
    /// Kademlia peer discovery (FIND_NODE / FIND_VALUE).
    PeerDiscovery,
    /// On-chain governance vote or proposal.
    Governance,
    /// Gossip envelope (contains another message).
    Gossip,
    /// Onion routing relay layer.
    OnionRelay,
    /// Health-check ping.
    Ping,
    /// Health-check pong.
    Pong,
    /// ZK identity proof exchange.
    ZkHandshake,
    /// Protocol-defined extension.
    Custom(String),
}

/// A signed, authenticated P2P message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessage {
    /// Version number for forward-compatibility.
    pub version: u8,
    /// Sender's NodeId (hex string of 32 bytes).
    pub sender_id: NodeId,
    pub message_type: MessageType,
    /// Encrypted payload bytes (AES-256-GCM over bincode-serialised inner data).
    pub payload: Vec<u8>,
    /// Ed25519 signature over (version ‖ sender_id ‖ message_type_tag ‖ payload).
    pub signature: Vec<u8>,
    /// Number of relay hops this message has traversed.
    pub hop_count: u8,
    /// Unique nonce to prevent replay attacks (random 16 bytes).
    pub nonce: [u8; 16],
    /// UNIX timestamp (seconds) when the message was created.
    pub timestamp: u64,
}

impl SecureMessage {
    /// Returns the canonical bytes to be signed / verified.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.push(self.version);
        buf.extend_from_slice(self.sender_id.as_bytes());
        // Encode message type as a discriminant byte
        buf.push(message_type_tag(&self.message_type));
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf
    }
}

fn message_type_tag(mt: &MessageType) -> u8 {
    match mt {
        MessageType::Transaction => 0,
        MessageType::Block => 1,
        MessageType::PeerDiscovery => 2,
        MessageType::Governance => 3,
        MessageType::Gossip => 4,
        MessageType::OnionRelay => 5,
        MessageType::Ping => 6,
        MessageType::Pong => 7,
        MessageType::ZkHandshake => 8,
        MessageType::Custom(_) => 255,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROUTING
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved multi-hop path from source to destination.
#[derive(Debug, Clone)]
pub struct RoutePath {
    pub hops: Vec<NodeId>,
}

impl RoutePath {
    pub fn len(&self) -> usize {
        self.hops.len()
    }
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
