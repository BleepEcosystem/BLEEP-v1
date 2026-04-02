//! # GossipBridge
//!
//! Broadcasts `FinalizedBlock` events to all connected P2P peers using
//! `P2PNode::broadcast(MessageType::Block, payload)`.
//!
//! ## Message format (payload)
//! ```text
//! [0..8]   block height (u64 little-endian)
//! [8..16]  epoch       (u64 little-endian)
//! [16..48] state_root  ([u8; 32])
//! [48..52] tx_count    (u32 little-endian)
//! [52..]   block_hash  (UTF-8 hex string, variable length)
//! ```

use std::sync::Arc;
use tracing::{debug, info, warn};

use bleep_p2p::p2p_node::P2PNode;
use bleep_p2p::types::MessageType;

use crate::block_producer::FinalizedBlock;

/// Serialize a `FinalizedBlock` into a compact binary payload.
pub fn encode_finalized_block(fb: &FinalizedBlock) -> Vec<u8> {
    let mut buf = Vec::with_capacity(52 + fb.hash.len());
    buf.extend_from_slice(&fb.height.to_le_bytes()); // [0..8]
    buf.extend_from_slice(&fb.epoch.to_le_bytes()); // [8..16]
    buf.extend_from_slice(&fb.state_root); // [16..48]
    buf.extend_from_slice(&(fb.tx_count as u32).to_le_bytes()); // [48..52]
    buf.extend_from_slice(fb.hash.as_bytes()); // [52..]
    buf
}

/// Deserialize a `FinalizedBlock` from the binary payload.
pub fn decode_finalized_block(data: &[u8]) -> Option<FinalizedBlock> {
    if data.len() < 52 {
        return None;
    }
    let height = u64::from_le_bytes(data[0..8].try_into().ok()?);
    let epoch = u64::from_le_bytes(data[8..16].try_into().ok()?);
    let sr: [u8; 32] = data[16..48].try_into().ok()?;
    let tx_count = u32::from_le_bytes(data[48..52].try_into().ok()?) as usize;
    let hash = String::from_utf8(data[52..].to_vec()).ok()?;
    Some(FinalizedBlock {
        height,
        epoch,
        state_root: sr,
        tx_count,
        hash,
        gas_used: 0,
    })
}

// ── GossipBridge ──────────────────────────────────────────────────────────────

/// Bridges finalized block events from the block producer to the P2P network.
pub struct GossipBridge {
    node: Arc<P2PNode>,
}

impl GossipBridge {
    pub fn new(node: Arc<P2PNode>) -> Self {
        Self { node }
    }

    /// Broadcast a finalized block to all peers.
    pub fn broadcast_block(&self, fb: &FinalizedBlock) {
        let payload = encode_finalized_block(fb);
        self.node.broadcast(MessageType::Block, payload);
        debug!(
            "[GossipBridge] Broadcasted block {} to {} peers",
            fb.height,
            self.node.peer_count()
        );
    }

    /// Run a gossip relay loop driven by the block producer's broadcast channel.
    ///
    /// `rx` is the `tokio::sync::broadcast::Receiver<FinalizedBlock>` from
    /// `BlockProducer::new`. Call inside `tokio::spawn`.
    pub async fn run(self, mut rx: tokio::sync::broadcast::Receiver<FinalizedBlock>) {
        info!("[GossipBridge] Gossip relay started");
        loop {
            match rx.recv().await {
                Ok(fb) => {
                    self.broadcast_block(&fb);
                    info!(
                        "[GossipBridge] Block {} gossipped → {} peers",
                        fb.height,
                        self.node.peer_count()
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(
                        "[GossipBridge] Lagged {} blocks — some may not have been gossiped",
                        n
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    info!("[GossipBridge] Channel closed — stopping");
                    break;
                }
            }
        }
    }
}

// ── Encode / decode tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FinalizedBlock {
        FinalizedBlock {
            height: 42,
            epoch: 0,
            hash: "deadbeef".to_string(),
            tx_count: 7,
            state_root: [1u8; 32],
            gas_used: 0,
        }
    }

    #[test]
    fn roundtrip() {
        let fb = sample();
        let enc = encode_finalized_block(&fb);
        let dec = decode_finalized_block(&enc).expect("decode failed");
        assert_eq!(dec.height, fb.height);
        assert_eq!(dec.epoch, fb.epoch);
        assert_eq!(dec.hash, fb.hash);
        assert_eq!(dec.tx_count, fb.tx_count);
        assert_eq!(dec.state_root, fb.state_root);
    }

    #[test]
    fn too_short_returns_none() {
        assert!(decode_finalized_block(&[0u8; 10]).is_none());
    }
}
