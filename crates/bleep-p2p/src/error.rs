//! Unified error types for bleep-p2p.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum P2PError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Peer not found: {peer_id}")]
    PeerNotFound { peer_id: String },

    #[error("Peer already present: {0}")]
    PeerAlreadyPresent(crate::types::NodeId),

    #[error("Peer is banned: {peer_id}")]
    PeerBanned { peer_id: String },

    #[error("Peer rejected (trust score {score:.2} below threshold {threshold:.2})")]
    PeerUntrusted { score: f64, threshold: f64 },

    #[error("ZK proof verification failed for peer {peer_id}")]
    ZkProofFailed { peer_id: String },

    #[error("Quantum identity verification failed for peer {peer_id}")]
    QuantumIdentityFailed { peer_id: String },

    #[error("Message authentication failed")]
    AuthenticationFailed,

    #[error("Message decryption failed")]
    DecryptionFailed,

    #[error("Onion routing: no valid route from {sender}")]
    NoRoute { sender: String },

    #[error("DHT error: {0}")]
    Dht(String),

    #[error("Max hops exceeded (limit {limit})")]
    MaxHopsExceeded { limit: usize },

    #[error("Connection timeout to {addr}")]
    ConnectionTimeout { addr: String },

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Node already running")]
    AlreadyRunning,

    #[error("Sybil attack detected from {peer_id}")]
    SybilDetected { peer_id: String },
}

pub type P2PResult<T> = Result<T, P2PError>;
