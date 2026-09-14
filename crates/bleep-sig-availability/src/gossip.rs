//! Gossip interface for the Signature Availability Layer.
//!
//! ## Architecture
//!
//! This module defines two abstractions:
//!
//! * [`GossipBroadcaster`] — a trait implemented by `bleep-p2p`'s gossip mesh.
//!   `bleep-sig-availability` calls it to fan-out outbound messages without
//!   taking a hard dependency on the P2P crate's internals.
//!
//! * [`SigAvailabilityGossipHandler`] — the inbound side. `bleep-p2p` calls
//!   `handle_raw_message()` for every message that arrives on topic
//!   `TOPIC_SIG_AVAILABILITY = 0x07`. The handler decodes, validates the wire
//!   format, and forwards to the `SigAvailabilityLayer` via a bounded
//!   `tokio::sync::mpsc` channel.

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::types::SigAvailabilityMessage;
use crate::TOPIC_SIG_AVAILABILITY;

// ─────────────────────────────────────────────────────────────────────────────
// GossipError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by [`GossipBroadcaster::broadcast_message`].
#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    #[error("gossip mesh has no connected peers")]
    NoPeers,

    #[error("message exceeds maximum gossip size ({size} > {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("serialisation failed: {0}")]
    Serialisation(#[from] bincode::Error),

    #[error("broadcast channel closed")]
    ChannelClosed,

    #[error("transport error: {0}")]
    Transport(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// GossipBroadcaster trait
// ─────────────────────────────────────────────────────────────────────────────

/// Interface through which the SAL pushes outbound messages into the P2P mesh.
///
/// ## Implementation contract
///
/// Implementors MUST:
/// - Fan out to at least `min(fanout, connected_peer_count)` peers.
/// - Enforce the `MAX_GOSSIP_MSG_BYTES = 2 MiB` limit from `bleep-p2p`.
/// - Return `Err(GossipError::NoPeers)` when the local peer has zero connections.
///
/// Implementors MUST NOT block the calling task for more than ~1 ms. Use an
/// internal send queue if necessary.
pub trait GossipBroadcaster: Send + Sync {
    /// Broadcast `payload` tagged with `topic` to the gossip mesh.
    fn broadcast_message(&self, topic: u8, payload: &[u8]) -> Result<(), GossipError>;

    /// Number of currently connected peers (for availability metrics).
    fn peer_count(&self) -> usize;
}

// ─────────────────────────────────────────────────────────────────────────────
// Outbound helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum size of a single SAL gossip payload.
/// Derived from `MAX_GOSSIP_MSG_BYTES = 2 MiB` in `bleep-p2p`, with 1 KiB
/// reserved for framing overhead added by the transport layer.
pub const MAX_SAL_MSG_BYTES: usize = 2 * 1024 * 1024 - 1024;

/// Broadcast a typed `SigAvailabilityMessage` through `broadcaster`.
///
/// Returns `Ok(())` if the message was handed to the transport layer.
/// Does NOT guarantee delivery to any specific peer count.
pub fn broadcast_sal_message(
    broadcaster: &dyn GossipBroadcaster,
    msg: &SigAvailabilityMessage,
) -> Result<(), GossipError> {
    let payload = bincode::serialize(msg)?;

    if payload.len() > MAX_SAL_MSG_BYTES {
        return Err(GossipError::MessageTooLarge {
            size: payload.len(),
            max: MAX_SAL_MSG_BYTES,
        });
    }

    broadcaster.broadcast_message(TOPIC_SIG_AVAILABILITY, &payload)
}

// ─────────────────────────────────────────────────────────────────────────────
// SigAvailabilityGossipHandler — inbound
// ─────────────────────────────────────────────────────────────────────────────

/// Inbound message handler registered with `bleep-p2p` for topic `0x07`.
///
/// `bleep-p2p` calls [`handle_raw_message`] on every incoming frame.
/// The handler decodes the frame and forwards it to the
/// [`SigAvailabilityLayer`] task via a bounded channel.
///
/// The bounded channel has capacity [`INBOUND_CHANNEL_CAPACITY`]. If it is
/// full, new messages are silently dropped with a warning log. This prevents
/// a slow consumer from causing the P2P receive loop to stall.
pub struct SigAvailabilityGossipHandler {
    tx: mpsc::Sender<SigAvailabilityMessage>,
}

/// Maximum number of decoded SAL messages queued for the availability layer.
/// At ~200 bytes per attestation and 512 validators, a fully-loaded round
/// produces ~102,400 bytes of attestations — well within a 4096-entry queue.
pub const INBOUND_CHANNEL_CAPACITY: usize = 4_096;

impl SigAvailabilityGossipHandler {
    /// Create a handler and the corresponding receiver channel.
    ///
    /// The returned `mpsc::Receiver<SigAvailabilityMessage>` must be consumed
    /// by the [`SigAvailabilityLayer`] task.
    pub fn new() -> (Arc<Self>, mpsc::Receiver<SigAvailabilityMessage>) {
        let (tx, rx) = mpsc::channel(INBOUND_CHANNEL_CAPACITY);
        (Arc::new(Self { tx }), rx)
    }

    /// Entry point called by `bleep-p2p` for every frame on topic `0x07`.
    ///
    /// - Validates the topic byte (guards against misconfigured topic routing).
    /// - Decodes via bincode.
    /// - Forwards to the availability layer; drops on full queue.
    pub fn handle_raw_message(&self, topic: u8, payload: &[u8]) {
        if topic != TOPIC_SIG_AVAILABILITY {
            warn!(
                topic,
                expected = TOPIC_SIG_AVAILABILITY,
                "SigAvailabilityGossipHandler: wrong topic — routing error in bleep-p2p"
            );
            return;
        }

        if payload.len() > MAX_SAL_MSG_BYTES {
            warn!(
                size = payload.len(),
                max = MAX_SAL_MSG_BYTES,
                "SigAvailabilityGossipHandler: oversized message dropped"
            );
            return;
        }

        let msg = match bincode::deserialize::<SigAvailabilityMessage>(payload) {
            Ok(m) => m,
            Err(e) => {
                warn!(%e, "SigAvailabilityGossipHandler: deserialisation failure");
                return;
            }
        };

        // try_send is non-blocking; if the channel is full we log and drop.
        match self.tx.try_send(msg) {
            Ok(_) => debug!("SigAvailabilityGossipHandler: message forwarded"),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!("SigAvailabilityGossipHandler: inbound channel full — message dropped");
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                warn!("SigAvailabilityGossipHandler: availability layer task has stopped");
            }
        }
    }
}

impl Default for SigAvailabilityGossipHandler {
    fn default() -> Self {
        // Provide a no-op sender for testing contexts where the receiver is not needed.
        let (tx, _rx) = mpsc::channel(1);
        Self { tx }
    }
}
