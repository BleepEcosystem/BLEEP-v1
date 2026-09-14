use std::sync::Arc;

use bleep_sig_availability::{
    gossip::{GossipBroadcaster, GossipError, SigAvailabilityGossipHandler},
    TOPIC_SIG_AVAILABILITY,
};
use tracing::{debug, warn};

use crate::p2p_node::P2PNode;
use crate::types::{MessageType, SecureMessage};

/// Bridges SAL gossip frames onto the live P2P network and routes inbound
/// SAL payloads into the SAL gossip handler.
pub struct SigAvailabilityBridge {
    handler: Arc<SigAvailabilityGossipHandler>,
    node: Option<Arc<P2PNode>>,
}

impl SigAvailabilityBridge {
    pub fn new(handler: Arc<SigAvailabilityGossipHandler>, node: Option<Arc<P2PNode>>) -> Self {
        Self { handler, node }
    }

    pub fn handle_inbound_message(&self, msg: SecureMessage) {
        if msg.message_type != MessageType::SigAvailability {
            return;
        }

        let Some(topic) = msg.payload.first().copied() else {
            warn!("SIG-AVAIL: dropped message without topic byte");
            return;
        };

        if topic != TOPIC_SIG_AVAILABILITY {
            warn!(
                topic,
                expected = TOPIC_SIG_AVAILABILITY,
                "SIG-AVAIL: unexpected topic"
            );
            return;
        }

        self.handler.handle_raw_message(topic, &msg.payload[1..]);
        debug!("SIG-AVAIL: forwarded inbound SAL payload to handler");
    }
}

impl GossipBroadcaster for SigAvailabilityBridge {
    fn broadcast_message(&self, topic: u8, payload: &[u8]) -> Result<(), GossipError> {
        let Some(node) = self.node.as_ref() else {
            return Err(GossipError::NoPeers);
        };

        if node.peer_count() == 0 {
            return Err(GossipError::NoPeers);
        }

        let mut wire = Vec::with_capacity(payload.len() + 1);
        wire.push(topic);
        wire.extend_from_slice(payload);
        node.broadcast(MessageType::SigAvailability, wire);
        Ok(())
    }

    fn peer_count(&self) -> usize {
        self.node.as_ref().map(|n| n.peer_count()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NodeId;
    use bleep_sig_availability::{gossip::SigAvailabilityGossipHandler, TOPIC_SIG_AVAILABILITY};
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn bridge_forwards_sal_payload_to_handler() {
        let (handler, mut rx) = SigAvailabilityGossipHandler::new();
        let bridge = SigAvailabilityBridge::new(handler, None);

        let sal_message = bleep_sig_availability::types::SigAvailabilityMessage::Announcement(
            bleep_sig_availability::types::SigCommitmentAnnouncement {
                block_id: bleep_sig_availability::types::BlockId {
                    height: 0,
                    block_hash: [0u8; 32],
                },
                sig_commitment_root: [0u8; 32],
                sig_count: 0,
                sig_hashes: vec![],
                proposer_sig: vec![],
                proposer_pk: vec![],
            },
        );
        let payload = sal_message.encode().expect("SAL message should encode");
        let message = SecureMessage {
            version: 1,
            sender_id: NodeId::random(),
            message_type: MessageType::SigAvailability,
            payload: [TOPIC_SIG_AVAILABILITY as u8]
                .into_iter()
                .chain(payload.into_iter())
                .collect(),
            signature: vec![],
            hop_count: 0,
            nonce: [0u8; 16],
            timestamp: 0,
        };

        bridge.handle_inbound_message(message);

        let forwarded = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("SAL handler should receive the message")
            .expect("channel should contain a message");

        match forwarded {
            bleep_sig_availability::types::SigAvailabilityMessage::Announcement(ann) => {
                assert_eq!(ann.block_id.height, 0);
            }
            other => panic!("unexpected message type: {other:?}"),
        }
    }
}
