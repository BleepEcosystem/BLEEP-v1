//! Production peer manager for bleep-p2p.
//!
//! Responsibilities:
//! - Lifecycle management (add, remove, ban, prune)
//! - Quantum-secure identity verification on admission
//! - Continuous AI-driven trust scoring
//! - Sybil detection via subnet clustering
//! - Kademlia DHT integration for distributed peer discovery
//! - Mesh broadcast of peer events

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::broadcast;
use tokio::time::interval;
use tracing::{info, warn};

use crate::ai_security::{
    AnomalyDetector, PeerScoring, SybilDetector, TRUST_HEALTHY_THRESHOLD,
    TRUST_SUSPICIOUS_THRESHOLD,
};
use crate::error::{P2PError, P2PResult};
use crate::kademlia_dht::KademliaDht;
use crate::quantum_crypto::sphincs_verify;
use crate::types::{unix_now, NodeId, PeerInfo, PeerStatus};

// ─────────────────────────────────────────────────────────────────────────────
// PEER EVENTS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum PeerEvent {
    Added(NodeId),
    Removed(NodeId),
    StatusChanged(NodeId, PeerStatus),
    Banned(NodeId),
}

// ─────────────────────────────────────────────────────────────────────────────
// PEER MANAGER CONFIG
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PeerManagerConfig {
    /// Maximum total peers maintained.
    pub max_peers: usize,
    /// How often to run the maintenance sweep (prune, re-score).
    pub maintenance_interval: Duration,
    /// Minimum trust score to remain in the peer table.
    pub min_trust_score: f64,
    /// Age in seconds after which a peer not seen is evicted.
    pub peer_eviction_age_secs: u64,
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        PeerManagerConfig {
            max_peers: 250,
            maintenance_interval: Duration::from_secs(30),
            min_trust_score: 20.0,
            peer_eviction_age_secs: 3600,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PEER MANAGER
// ─────────────────────────────────────────────────────────────────────────────

pub struct PeerManager {
    config: PeerManagerConfig,
    /// The live peer table — NodeId → PeerInfo.
    peers: DashMap<NodeId, PeerInfo>,
    /// Explicitly banned peers (persist across restarts conceptually).
    banned: DashMap<NodeId, u64>,
    dht: Arc<KademliaDht>,
    scoring: Arc<PeerScoring>,
    sybil: Arc<SybilDetector>,
    anomaly: Arc<AnomalyDetector>,
    event_tx: broadcast::Sender<PeerEvent>,
}

impl PeerManager {
    /// Construct a new PeerManager.
    pub fn new(
        local_id: NodeId,
        config: PeerManagerConfig,
    ) -> (Arc<Self>, broadcast::Receiver<PeerEvent>) {
        let (tx, rx) = broadcast::channel(1024);
        let dht = Arc::new(KademliaDht::new(local_id));
        let pm = Arc::new(PeerManager {
            config,
            peers: DashMap::new(),
            banned: DashMap::new(),
            dht,
            scoring: Arc::new(PeerScoring::new()),
            sybil: Arc::new(SybilDetector::new()),
            anomaly: Arc::new(AnomalyDetector::new()),
            event_tx: tx,
        });
        (pm, rx)
    }

    // ── ADMISSION ─────────────────────────────────────────────────────────────

    /// Admit a new peer after full verification.
    ///
    /// Steps:
    /// 1. Check the peer is not banned.
    /// 2. Sybil detection on the remote address.
    /// 3. Verify the SPHINCS+ proof-of-identity.
    /// 4. Compute initial trust score.
    /// 5. Insert into peer table and DHT.
    pub async fn add_peer(
        &self,
        id: NodeId,
        addr: SocketAddr,
        ed25519_pubkey: Vec<u8>,
        sphincs_pubkey: Vec<u8>,
        identity_proof_challenge: &[u8],
        identity_proof_signature: &[u8],
    ) -> P2PResult<()> {
        // 1. Banned check
        if self.banned.contains_key(&id) {
            return Err(P2PError::PeerBanned {
                peer_id: id.to_string(),
            });
        }

        // 2. Max peers guard
        if self.peers.len() >= self.config.max_peers {
            // Evict the lowest-scoring non-banned peer to make room
            self.evict_lowest_scored_peer().await;
        }

        // 3. Sybil check
        if self.sybil.register(&id, &addr) {
            return Err(P2PError::SybilDetected {
                peer_id: id.to_string(),
            });
        }

        // 4. SPHINCS+ identity proof
        sphincs_verify(
            identity_proof_challenge,
            identity_proof_signature,
            &sphincs_pubkey,
        )
        .map_err(|_| P2PError::QuantumIdentityFailed {
            peer_id: id.to_string(),
        })?;

        // 5. Build PeerInfo and score
        let mut peer = PeerInfo::new(id.clone(), addr, ed25519_pubkey, sphincs_pubkey);
        let score = self.scoring.calculate_score(&id);
        peer.trust_score = score;
        peer.status = if score >= TRUST_HEALTHY_THRESHOLD {
            PeerStatus::Healthy
        } else if score >= TRUST_SUSPICIOUS_THRESHOLD {
            PeerStatus::Suspicious
        } else {
            PeerStatus::Malicious
        };

        // 6. Insert
        self.peers.insert(id.clone(), peer.clone());
        self.dht.add_peer(peer.clone()).await;
        self.dht.store_peer_addr(&id, &addr);

        let _ = self.event_tx.send(PeerEvent::Added(id.clone()));
        info!(peer_id = %id, addr = %addr, score = %score, "Peer admitted");
        Ok(())
    }

    // ── REMOVAL / BANNING ─────────────────────────────────────────────────────

    pub async fn remove_peer(&self, id: &NodeId) {
        if let Some((_, peer)) = self.peers.remove(id) {
            self.sybil.deregister(id, &peer.addr);
            self.dht.remove_peer(id).await;
            let _ = self.event_tx.send(PeerEvent::Removed(id.clone()));
            info!(peer_id = %id, "Peer removed");
        }
    }

    pub async fn ban_peer(&self, id: &NodeId) {
        self.remove_peer(id).await;
        self.banned.insert(id.clone(), unix_now());
        self.scoring.remove(id);
        let _ = self.event_tx.send(PeerEvent::Banned(id.clone()));
        warn!(peer_id = %id, "Peer banned");
    }

    pub fn is_banned(&self, id: &NodeId) -> bool {
        self.banned.contains_key(id)
    }

    // ── INTERACTION RECORDING ─────────────────────────────────────────────────

    pub fn record_success(&self, id: &NodeId) {
        self.scoring.record_success(id);
        if let Some(mut peer) = self.peers.get_mut(id) {
            peer.record_success();
            peer.trust_score = self.scoring.calculate_score(id);
        }
    }

    pub fn record_failure(&self, id: &NodeId) {
        self.scoring.record_failure(id);
        if let Some(mut peer) = self.peers.get_mut(id) {
            peer.record_failure();
            peer.trust_score = self.scoring.calculate_score(id);
        }
    }

    pub fn record_message(&self, id: &NodeId) {
        self.scoring.record_message(id);
    }

    pub fn record_latency(&self, id: &NodeId, latency_ms: u32) {
        self.scoring.record_latency(id, latency_ms);
    }

    pub fn check_message_anomaly(
        &self,
        _id: &NodeId,
        payload: &[u8],
        hop_count: u8,
    ) -> Option<String> {
        self.anomaly.check_message(payload, hop_count)
    }

    pub fn touch(&self, id: &NodeId) {
        if let Some(mut peer) = self.peers.get_mut(id) {
            peer.touch();
        }
    }

    // ── QUERIES ───────────────────────────────────────────────────────────────

    pub fn get_peer(&self, id: &NodeId) -> Option<PeerInfo> {
        self.peers.get(id).map(|p| p.clone())
    }

    pub fn get_peer_addr(&self, id: &NodeId) -> Option<SocketAddr> {
        self.peers.get(id).map(|p| p.addr)
    }

    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers.iter().map(|e| e.value().clone()).collect()
    }

    pub fn healthy_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .filter(|e| e.value().status == PeerStatus::Healthy)
            .map(|e| e.value().clone())
            .collect()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn peer_ids(&self) -> Vec<NodeId> {
        self.peers.iter().map(|e| e.key().clone()).collect()
    }

    /// Find k-closest peers to `target` via the Kademlia routing table.
    pub async fn find_closest(&self, target: &NodeId, k: usize) -> Vec<PeerInfo> {
        self.dht.find_closest_peers(target, k).await
    }

    pub fn dht(&self) -> Arc<KademliaDht> {
        self.dht.clone()
    }

    // ── MAINTENANCE ───────────────────────────────────────────────────────────

    /// Prune banned/malicious/stale peers and re-score suspicious peers.
    pub async fn maintenance_sweep(&self) {
        let now = unix_now();
        let mut to_ban: Vec<NodeId> = Vec::new();
        let mut to_remove: Vec<NodeId> = Vec::new();

        for entry in self.peers.iter() {
            let id = entry.key().clone();
            let peer = entry.value();

            // Evict very stale peers
            if now.saturating_sub(peer.last_seen) > self.config.peer_eviction_age_secs {
                to_remove.push(id.clone());
                continue;
            }

            // Re-score and update status
            let score = self.scoring.calculate_score(&id);
            drop(entry); // Release read lock before mutating

            if let Some(mut p) = self.peers.get_mut(&id) {
                let old_status = p.status.clone();
                p.trust_score = score;
                p.status = if score >= TRUST_HEALTHY_THRESHOLD {
                    PeerStatus::Healthy
                } else if score >= TRUST_SUSPICIOUS_THRESHOLD {
                    PeerStatus::Suspicious
                } else {
                    PeerStatus::Malicious
                };
                if p.status != old_status {
                    let _ = self
                        .event_tx
                        .send(PeerEvent::StatusChanged(id.clone(), p.status.clone()));
                }
                if score < self.config.min_trust_score {
                    to_ban.push(id);
                }
            }
        }

        for id in to_remove {
            self.remove_peer(&id).await;
        }
        for id in to_ban {
            self.ban_peer(&id).await;
        }
    }

    async fn evict_lowest_scored_peer(&self) {
        let mut lowest_score = f64::MAX;
        let mut lowest_id: Option<NodeId> = None;

        for entry in self.peers.iter() {
            let score = self.scoring.calculate_score(entry.key());
            if score < lowest_score {
                lowest_score = score;
                lowest_id = Some(entry.key().clone());
            }
        }
        if let Some(id) = lowest_id {
            self.remove_peer(&id).await;
        }
    }

    /// Spawn the periodic maintenance background task.
    pub fn spawn_maintenance(self: Arc<Self>) {
        let interval_dur = self.config.maintenance_interval;
        tokio::spawn(async move {
            let mut ticker = interval(interval_dur);
            loop {
                ticker.tick().await;
                self.maintenance_sweep().await;
            }
        });
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<PeerEvent> {
        self.event_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum_crypto::{sphincs_sign, Ed25519Keypair, SphincsKeypair};

    fn make_test_pm() -> (Arc<PeerManager>, broadcast::Receiver<PeerEvent>) {
        let local_id = NodeId::random();
        PeerManager::new(local_id, PeerManagerConfig::default())
    }

    async fn add_test_peer(pm: &PeerManager, seed: u8) -> NodeId {
        let ed_kp = Ed25519Keypair::generate();
        let sphincs_kp = SphincsKeypair::generate();
        let id = NodeId::from_bytes(&ed_kp.public_key_bytes());
        let addr: SocketAddr = format!("10.0.0.{}:9000", seed).parse().unwrap();
        let challenge = b"test-handshake-context";
        let sig = sphincs_sign(challenge, &sphincs_kp.secret_key.0).unwrap();
        pm.add_peer(
            id.clone(),
            addr,
            ed_kp.public_key_bytes(),
            sphincs_kp.public_key.0.clone(),
            challenge,
            &sig,
        )
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn test_add_and_get_peer() {
        let (pm, _rx) = make_test_pm();
        let id = add_test_peer(&pm, 1).await;
        let peer = pm.get_peer(&id).unwrap();
        assert_eq!(peer.id, id);
    }

    #[tokio::test]
    async fn test_remove_peer() {
        let (pm, _rx) = make_test_pm();
        let id = add_test_peer(&pm, 2).await;
        assert_eq!(pm.peer_count(), 1);
        pm.remove_peer(&id).await;
        assert_eq!(pm.peer_count(), 0);
    }

    #[tokio::test]
    async fn test_ban_prevents_readmission() {
        let (pm, _rx) = make_test_pm();
        let id = add_test_peer(&pm, 3).await;
        pm.ban_peer(&id).await;
        assert!(pm.is_banned(&id));

        let ed_kp = Ed25519Keypair::generate();
        let sphincs_kp = SphincsKeypair::generate();
        let addr: SocketAddr = "10.0.0.3:9001".parse().unwrap();
        let challenge = b"re-admit-context";
        let sig = sphincs_sign(challenge, &sphincs_kp.secret_key.0).unwrap();
        let result = pm
            .add_peer(
                id.clone(),
                addr,
                ed_kp.public_key_bytes(),
                sphincs_kp.public_key.0.clone(),
                challenge,
                &sig,
            )
            .await;
        assert!(matches!(result, Err(P2PError::PeerBanned { .. })));
    }

    #[tokio::test]
    async fn test_invalid_identity_proof_rejected() {
        let (pm, _rx) = make_test_pm();
        let ed_kp = Ed25519Keypair::generate();
        let sphincs_kp = SphincsKeypair::generate();
        let id = NodeId::from_bytes(&ed_kp.public_key_bytes());
        let addr: SocketAddr = "10.0.0.99:9000".parse().unwrap();
        let challenge = b"some-context";
        let bad_sig = vec![0u8; 64]; // invalid signature
        let result = pm
            .add_peer(
                id,
                addr,
                ed_kp.public_key_bytes(),
                sphincs_kp.public_key.0,
                challenge,
                &bad_sig,
            )
            .await;
        assert!(matches!(
            result,
            Err(P2PError::QuantumIdentityFailed { .. })
        ));
    }

    #[tokio::test]
    async fn test_record_success_and_failure() {
        let (pm, _rx) = make_test_pm();
        let id = add_test_peer(&pm, 5).await;
        pm.record_success(&id);
        pm.record_success(&id);
        pm.record_failure(&id);
        let peer = pm.get_peer(&id).unwrap();
        assert!(peer.trust_score >= 0.0);
    }

    #[tokio::test]
    async fn test_all_peers_and_healthy_peers() {
        let (pm, _rx) = make_test_pm();
        for i in 10..15u8 {
            add_test_peer(&pm, i).await;
        }
        assert_eq!(pm.all_peers().len(), 5);
        // All new peers start at Candidate/Suspicious; healthy_peers may be empty
        let healthy = pm.healthy_peers();
        assert!(healthy.len() <= 5);
    }

    #[tokio::test]
    async fn test_maintenance_sweep_evicts_stale() {
        let (pm, _rx) = PeerManager::new(
            NodeId::random(),
            PeerManagerConfig {
                peer_eviction_age_secs: 0, // instant eviction
                ..Default::default()
            },
        );
        let id = add_test_peer(&pm, 20).await;
        assert_eq!(pm.peer_count(), 1);
        // Mark as very old
        if let Some(mut p) = pm.peers.get_mut(&id) {
            p.last_seen = 0;
        }
        pm.maintenance_sweep().await;
        assert_eq!(pm.peer_count(), 0);
    }

    #[tokio::test]
    async fn test_event_broadcast_on_add() {
        let (pm, mut rx) = make_test_pm();
        let id = add_test_peer(&pm, 30).await;
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, PeerEvent::Added(_)));
    }
}
