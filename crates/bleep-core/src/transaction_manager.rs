use crate::transaction::{
    DarkRouting, GossipProtocol, MultiHopRouting, P2PMessage, PeerManager, ZKTransaction,
};
use std::sync::Arc;

pub struct TransactionManager {
    peer_manager: Arc<PeerManager>,
    gossip_protocol: Arc<GossipProtocol>,
    multi_hop_routing: Arc<MultiHopRouting>,
    dark_routing: Arc<DarkRouting>,
}

impl TransactionManager {
    pub fn new(
        peer_manager: Arc<PeerManager>,
        gossip_protocol: Arc<GossipProtocol>,
        multi_hop_routing: Arc<MultiHopRouting>,
        dark_routing: Arc<DarkRouting>,
    ) -> Self {
        Self {
            peer_manager,
            gossip_protocol,
            multi_hop_routing,
            dark_routing,
        }
    }

    pub async fn broadcast_transaction(&self, transaction: ZKTransaction) {
        let message = P2PMessage::Transaction(transaction);
        let _ = self.gossip_protocol.broadcast_message(message).await;
    }

    pub async fn route_transaction(
        &self,
        sender: &str,
        receiver: &str,
        transaction: ZKTransaction,
    ) {
        let route = match self.multi_hop_routing.select_route(sender, receiver).await {
            Ok(r) => r,
            Err(_) => return,
        };
        let _ = self
            .multi_hop_routing
            .forward_message(route, P2PMessage::Transaction(transaction))
            .await;
    }

    pub async fn send_anonymous_transaction(&self, sender: &str, transaction: ZKTransaction) {
        let route = match self.dark_routing.select_anonymous_route(sender).await {
            Ok(r) => r,
            Err(_) => return,
        };
        let _ = self
            .dark_routing
            .forward_anonymous(route, P2PMessage::Transaction(transaction))
            .await;
    }

    pub async fn process_p2p_message(&self, message: P2PMessage) {
        if let P2PMessage::Transaction(tx) = message {
            if tx.verify() {
                let _ = self.peer_manager.add_transaction_to_pool(tx).await;
                log::info!("✅ Valid transaction received and added to mempool.");
            } else {
                log::warn!("❌ Invalid transaction rejected.");
            }
        }
    }
}
