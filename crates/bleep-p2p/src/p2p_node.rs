//! Top-level P2P node for the BLEEP network.
//!
//! Orchestrates all subsystems:
//! - PeerManager (admission, scoring, banning)
//! - KademliaDHT (peer discovery)
//! - MessageProtocol (encryption, signing, TCP transport)
//! - GossipProtocol (epidemic broadcast)
//! - OnionRouter (anonymous routing)
//!
//! Usage:
//! ```no_run
//! use bleep_p2p::p2p_node::{P2PNode, P2PNodeConfig};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = P2PNodeConfig::default();
//!     let (node, handle) = P2PNode::start(config).await.unwrap();
//!     // ... use node ...
//! }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::ai_security::PeerScoring;
use crate::error::P2PResult;
use crate::gossip_protocol::GossipProtocol;
use crate::message_protocol::MessageProtocol;
use crate::onion_routing::OnionRouter;
use crate::peer_manager::{PeerEvent, PeerManager, PeerManagerConfig};
use crate::quantum_crypto::NodeIdentity;
use crate::types::{MessageType, NodeId, PeerInfo, SecureMessage};

// ─────────────────────────────────────────────────────────────────────────────
// NODE CONFIG
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct P2PNodeConfig {
    /// Address to bind the TCP listener on.
    pub listen_addr: SocketAddr,
    /// Bootstrap peers (NodeId + addr + public keys).
    pub bootstrap_peers: Vec<BootstrapPeer>,
    /// Peer manager configuration.
    pub peer_manager_config: PeerManagerConfig,
}

#[derive(Debug, Clone)]
pub struct BootstrapPeer {
    pub addr: SocketAddr,
    pub ed25519_pubkey: Vec<u8>,
    pub sphincs_pubkey: Vec<u8>,
}

impl Default for P2PNodeConfig {
    fn default() -> Self {
        P2PNodeConfig {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 7700)),
            bootstrap_peers: vec![],
            peer_manager_config: PeerManagerConfig::default(),
        }
    }
}

impl P2PNodeConfig {
    pub fn from_env() -> Result<Self, String> {
        let mut config = Self::default();
        if let Ok(addr) = std::env::var("BLEEP_P2P_LISTEN_ADDR") {
            config.listen_addr = addr
                .parse()
                .map_err(|e| format!("invalid BLEEP_P2P_LISTEN_ADDR: {e}"))?;
        }
        if let Ok(seeds) = std::env::var("BLEEP_P2P_SEEDS") {
            for seed in seeds
                .split(',')
                .map(str::trim)
                .filter(|seed| !seed.is_empty())
            {
                config.bootstrap_peers.push(BootstrapPeer {
                    addr: seed
                        .parse()
                        .map_err(|e| format!("invalid BLEEP_P2P_SEEDS entry '{seed}': {e}"))?,
                    ed25519_pubkey: vec![],
                    sphincs_pubkey: vec![],
                });
            }
        }
        Ok(config)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P2P NODE
// ─────────────────────────────────────────────────────────────────────────────

pub struct P2PNode {
    pub node_id: NodeId,
    pub identity: Arc<NodeIdentity>,
    pub peer_manager: Arc<PeerManager>,
    pub message_protocol: Arc<MessageProtocol>,
    pub gossip: Arc<GossipProtocol>,
    pub onion_router: Arc<OnionRouter>,
    /// Inbound messages decoded and verified by MessageProtocol.
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<(NodeId, SecureMessage)>>,
}

impl P2PNode {
    /// Construct and start the node.  Returns the node and a handle to all
    /// background tasks that the caller should await / abort on shutdown.
    pub async fn start(config: P2PNodeConfig) -> P2PResult<(Arc<Self>, NodeHandle)> {
        // Generate node identity
        let identity = Arc::new(NodeIdentity::generate());
        let node_id = identity.node_id();

        info!(node_id = %node_id, listen = %config.listen_addr, "Starting BLEEP P2P node");

        // Peer manager
        let (peer_manager, mut event_rx) =
            PeerManager::new(node_id.clone(), config.peer_manager_config.clone());

        let (message_protocol, inbound_rx) = MessageProtocol::new(
            identity.ed_keypair.clone(),
            identity.sphincs_keypair.clone(),
            identity.kyber_keypair.clone(),
            peer_manager.clone(),
        );
        message_protocol.set_advertised_addr(config.listen_addr);

        // Gossip
        let gossip = GossipProtocol::new(peer_manager.clone(), message_protocol.clone());

        // Onion router
        let scoring = Arc::new(PeerScoring::new());
        let onion_router = Arc::new(OnionRouter::new(
            peer_manager.clone(),
            message_protocol.clone(),
            scoring,
        ));

        let node = Arc::new(P2PNode {
            node_id: node_id.clone(),
            identity: identity.clone(),
            peer_manager: peer_manager.clone(),
            message_protocol: message_protocol.clone(),
            gossip: gossip.clone(),
            onion_router,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
        });

        // ── Spawn background tasks ────────────────────────────────────────────

        // 1. TCP listener
        let mp_clone = message_protocol.clone();
        let listen_addr = config.listen_addr;
        let listen_handle = tokio::spawn(async move {
            if let Err(e) = mp_clone.listen(listen_addr).await {
                error!(error = %e, "MessageProtocol listener stopped");
            }
        });

        // 2. Gossip background loop
        let gossip_clone = gossip.clone();
        let gossip_handle = tokio::spawn(async move {
            gossip_clone.run().await;
        });

        // 3. Peer manager maintenance
        peer_manager.clone().spawn_maintenance();

        // 4. Kademlia DHT maintenance
        let dht_clone = peer_manager.dht();
        let dht_handle = tokio::spawn(async move {
            dht_clone.run_maintenance().await;
        });

        // 5. Peer event logger
        let event_handle = tokio::spawn(async move {
            while let Ok(event) = event_rx.recv().await {
                match &event {
                    PeerEvent::Added(id) => info!(peer = %id, "Peer added"),
                    PeerEvent::Removed(id) => info!(peer = %id, "Peer removed"),
                    PeerEvent::Banned(id) => warn!(peer = %id, "Peer banned"),
                    PeerEvent::StatusChanged(id, status) => {
                        info!(peer = %id, status = %status, "Peer status changed")
                    }
                }
            }
        });

        // Bootstrap
        let bootstrap_handle = if config.bootstrap_peers.is_empty() {
            None
        } else {
            let seeds = config.bootstrap_peers.clone();
            let protocol = message_protocol.clone();
            let peer_manager = peer_manager.clone();
            let dht = peer_manager.dht();
            Some(tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                loop {
                    for seed in &seeds {
                        match protocol.establish_outbound(seed.addr).await {
                            Ok(peer) => {
                                if let Some(peer_info) = peer_manager.get_peer(&peer) {
                                    dht.bootstrap(std::slice::from_ref(&peer_info)).await;
                                }
                                info!(addr = %seed.addr, peer = %peer, "Connected to bootstrap peer");
                            }
                            Err(error) => {
                                warn!(addr = %seed.addr, %error, "Bootstrap peer connection failed; will retry")
                            }
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }))
        };

        let handle = NodeHandle {
            tasks: vec![listen_handle, gossip_handle, dht_handle, event_handle]
                .into_iter()
                .chain(bootstrap_handle)
                .collect(),
        };

        Ok((node, handle))
    }

    // ── PUBLIC API ────────────────────────────────────────────────────────────

    /// Broadcast a message to all connected healthy peers via the gossip protocol.
    pub fn broadcast(&self, message_type: MessageType, payload: Vec<u8>) {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let msg = SecureMessage {
            version: 1,
            sender_id: self.node_id.clone(),
            message_type,
            payload,
            signature: Vec::new(), // signed per-peer by seal_message
            hop_count: 0,
            nonce,
            timestamp: crate::types::unix_now(),
        };
        self.gossip.enqueue(msg, None);
    }

    /// Receive the next verified inbound message (blocks until one arrives).
    pub async fn recv(&self) -> Option<(NodeId, SecureMessage)> {
        self.inbound_rx.lock().await.recv().await
    }

    /// Admit a peer after verifying their SPHINCS+ identity proof.
    pub async fn connect_peer(
        &self,
        addr: SocketAddr,
        ed25519_pubkey: Vec<u8>,
        sphincs_pubkey: Vec<u8>,
        challenge: &[u8],
        sphincs_signature: &[u8],
    ) -> P2PResult<NodeId> {
        let peer_id = NodeId::from_bytes(&ed25519_pubkey);
        self.peer_manager
            .add_peer(
                peer_id.clone(),
                addr,
                ed25519_pubkey,
                sphincs_pubkey,
                challenge,
                sphincs_signature,
            )
            .await?;
        Ok(peer_id)
    }

    /// Generate a SPHINCS+ proof-of-identity for use in the handshake.
    pub fn make_identity_proof(&self, challenge: &[u8]) -> P2PResult<Vec<u8>> {
        self.identity.sign_sphincs(challenge)
    }

    pub fn peer_count(&self) -> usize {
        self.peer_manager.peer_count()
    }

    pub fn healthy_peer_count(&self) -> usize {
        self.peer_manager.healthy_peers().len()
    }

    pub async fn find_closest(&self, target: &NodeId, k: usize) -> Vec<PeerInfo> {
        self.peer_manager.find_closest(target, k).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NODE HANDLE
// ─────────────────────────────────────────────────────────────────────────────

/// Holds the JoinHandles for all background tasks spawned by the node.
/// Drop this to cancel all tasks, or call `shutdown()`.
pub struct NodeHandle {
    tasks: Vec<JoinHandle<()>>,
}

impl NodeHandle {
    pub async fn shutdown(self) {
        for task in self.tasks {
            task.abort();
        }
        info!("BLEEP P2P node shut down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    async fn start_test_node(port: u16) -> (Arc<P2PNode>, NodeHandle) {
        let config = P2PNodeConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            bootstrap_peers: vec![],
            peer_manager_config: PeerManagerConfig::default(),
        };
        P2PNode::start(config).await.unwrap()
    }

    #[tokio::test]
    async fn test_node_starts_and_has_node_id() {
        let (node, handle) = start_test_node(17700).await;
        assert_eq!(node.node_id.as_bytes().len(), 32);
        assert_eq!(node.peer_count(), 0);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_make_and_verify_identity_proof() {
        let (node, handle) = start_test_node(17701).await;
        let challenge = b"test-handshake-nonce-12345";
        let proof = node.make_identity_proof(challenge).unwrap();
        assert!(!proof.is_empty());

        // Verify it
        let sphincs_pk = &node.identity.sphincs_keypair.public_key.0;
        crate::quantum_crypto::sphincs_verify(challenge, &proof, sphincs_pk).unwrap();
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_connect_peer_adds_to_manager() {
        let (node_a, handle_a) = start_test_node(17702).await;
        let (node_b, handle_b) = start_test_node(17703).await;

        let b_ed_pk = node_b.identity.ed_keypair.public_key_bytes();
        let b_sphincs_pk = node_b.identity.sphincs_keypair.public_key.0.clone();
        let challenge = b"handshake-test-challenge";
        let sig = node_b.make_identity_proof(challenge).unwrap();

        let peer_id = node_a
            .connect_peer(
                "127.0.0.1:17703".parse().unwrap(),
                b_ed_pk,
                b_sphincs_pk,
                challenge,
                &sig,
            )
            .await
            .unwrap();

        assert_eq!(node_a.peer_count(), 1);
        handle_a.shutdown().await;
        handle_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_bootstrap_peer_is_dialed_and_admitted() {
        let (node_b, handle_b) = start_test_node(17706).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let config = P2PNodeConfig {
            listen_addr: "127.0.0.1:17707".parse().unwrap(),
            bootstrap_peers: vec![BootstrapPeer {
                addr: "127.0.0.1:17706".parse().unwrap(),
                ed25519_pubkey: vec![],
                sphincs_pubkey: vec![],
            }],
            peer_manager_config: PeerManagerConfig::default(),
        };
        let (node_a, handle_a) = P2PNode::start(config).await.unwrap();

        timeout(Duration::from_secs(30), async {
            loop {
                if node_a.peer_count() == 1 && node_b.peer_count() == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("bootstrap peer should be admitted through the outbound handshake");

        timeout(Duration::from_secs(5), async {
            loop {
                if node_b.peer_count() == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("bootstrap peer should be admitted on the accepting node");

        assert_eq!(node_b.peer_count(), 1);
        let closest = node_a.peer_manager.find_closest(&node_b.node_id, 1).await;
        assert_eq!(closest.first().map(|peer| &peer.id), Some(&node_b.node_id));

        handle_a.shutdown().await;
        handle_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_broadcast_enqueues_in_gossip() {
        let (node, handle) = start_test_node(17704).await;
        node.broadcast(MessageType::Transaction, b"tx_data".to_vec());
        // pending queue should have 1 item
        assert_eq!(node.gossip.pending.lock().len(), 1);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_accepts_tcp_connections() {
        let (node, handle) = start_test_node(17705).await;
        // Just verify the port is bound
        let result = timeout(
            Duration::from_millis(200),
            tokio::net::TcpStream::connect("127.0.0.1:17705"),
        )
        .await;
        assert!(result.is_ok(), "TCP connect should succeed");
        handle.shutdown().await;
    }
}
