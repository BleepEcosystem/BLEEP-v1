//! Production onion routing (dark routing) for bleep-p2p.
//!
//! Each hop encrypts under the relay's Kyber-derived session key (AES-256-GCM).
//! The final destination peels all layers to recover the original plaintext.
//! Route selection uses AI trust scoring to avoid low-reputation relays.

use std::sync::Arc;

use rand::seq::SliceRandom;
use tracing::info;

use crate::ai_security::PeerScoring;
use crate::error::{P2PError, P2PResult};
use crate::message_protocol::MessageProtocol;
use crate::peer_manager::PeerManager;
use crate::quantum_crypto::{aes_gcm_decrypt, aes_gcm_encrypt, derive_key};
use crate::types::{MessageType, NodeId, RoutePath};

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum hops in an onion circuit.
const MAX_HOPS: usize = 6;
/// Minimum trust score for a node to be used as a relay.
const MIN_RELAY_TRUST: f64 = 55.0;

// ─────────────────────────────────────────────────────────────────────────────
// PER-HOP ENCRYPTION KEY DERIVATION
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a per-hop symmetric key from a Kyber session shared-secret and the
/// relay's NodeId.  Each hop gets a *different* key even if they somehow shared
/// the same underlying KEM material.
fn hop_key(session_shared_secret: &[u8], relay_id: &NodeId, hop_index: u8) -> [u8; 32] {
    let mut salt = relay_id.as_bytes().to_vec();
    salt.push(hop_index);
    derive_key(session_shared_secret, &salt, b"bleep-onion-hop-v1")
}

// ─────────────────────────────────────────────────────────────────────────────
// ONION LAYER
// ─────────────────────────────────────────────────────────────────────────────

/// A single layer of the onion: encrypted payload + routing hint (next hop).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OnionLayer {
    /// AES-256-GCM encrypted payload (nonce prepended).
    pub encrypted_payload: Vec<u8>,
    /// The NodeId of the next hop (empty for final destination).
    pub next_hop: Option<NodeId>,
    /// Hop index (0 = outermost layer).
    pub hop_index: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// ONION CIRCUIT
// ─────────────────────────────────────────────────────────────────────────────

/// A constructed onion circuit: ordered outer-to-inner layers ready to send.
pub struct OnionCircuit {
    pub layers: Vec<OnionLayer>,
    pub route: RoutePath,
}

// ─────────────────────────────────────────────────────────────────────────────
// ONION ROUTER
// ─────────────────────────────────────────────────────────────────────────────

pub struct OnionRouter {
    peer_manager: Arc<PeerManager>,
    message_protocol: Arc<MessageProtocol>,
    #[allow(dead_code)]
    scoring: Arc<PeerScoring>,
}

impl OnionRouter {
    pub fn new(
        peer_manager: Arc<PeerManager>,
        message_protocol: Arc<MessageProtocol>,
        scoring: Arc<PeerScoring>,
    ) -> Self {
        OnionRouter {
            peer_manager,
            message_protocol,
            scoring,
        }
    }

    // ── ROUTE SELECTION ───────────────────────────────────────────────────────

    /// Select a route of up to `max_hops` relay nodes for `sender_id`.
    ///
    /// - Excludes the sender.
    /// - Filters to nodes above MIN_RELAY_TRUST.
    /// - Shuffles the remainder for unlinkability.
    pub fn select_route(&self, sender_id: &NodeId, max_hops: usize) -> P2PResult<RoutePath> {
        let max_hops = max_hops.min(MAX_HOPS);
        let all = self.peer_manager.healthy_peers();

        let mut candidates: Vec<NodeId> = all
            .into_iter()
            .filter(|p| &p.id != sender_id && p.trust_score >= MIN_RELAY_TRUST)
            .map(|p| p.id)
            .collect();

        if candidates.is_empty() {
            return Err(P2PError::NoRoute {
                sender: sender_id.to_string(),
            });
        }

        // Shuffle for unlinkability, then truncate
        candidates.shuffle(&mut rand::thread_rng());
        candidates.truncate(max_hops);

        Ok(RoutePath { hops: candidates })
    }

    // ── CIRCUIT CONSTRUCTION ─────────────────────────────────────────────────

    /// Wrap `plaintext` in onion layers for each relay in `route`.
    ///
    /// Layers are constructed inner-to-outer so that the outermost layer is the
    /// one to be sent first.  Each relay decrypts its own layer and forwards
    /// the inner payload.
    ///
    /// The `hop_shared_secrets[i]` must be the Kyber shared secret that has been
    /// established with route.hops[i].
    pub fn wrap(
        &self,
        plaintext: &[u8],
        route: &RoutePath,
        hop_shared_secrets: &[Vec<u8>],
    ) -> P2PResult<OnionCircuit> {
        if hop_shared_secrets.len() != route.hops.len() {
            return Err(P2PError::Crypto(
                "hop_shared_secrets length must match route length".into(),
            ));
        }

        // Start from the innermost payload (actual data for the final destination)
        let mut current_payload = plaintext.to_vec();
        let n = route.hops.len();
        let mut layers = Vec::with_capacity(n);

        // Encrypt innermost → outermost (reverse order)
        for i in (0..n).rev() {
            let relay_id = &route.hops[i];
            let key = hop_key(&hop_shared_secrets[i], relay_id, i as u8);
            let encrypted_payload = aes_gcm_encrypt(&key, &current_payload)?;

            let next_hop = if i + 1 < n {
                Some(route.hops[i + 1].clone())
            } else {
                None // Final destination
            };

            let layer = OnionLayer {
                encrypted_payload: encrypted_payload.clone(),
                next_hop,
                hop_index: i as u8,
            };
            layers.push(layer);

            // The payload for the next (outer) layer includes this encrypted layer
            let last_layer = layers.last().expect("just pushed a layer, cannot be empty");
            current_payload = bincode::serialize(last_layer)
                .map_err(|e| P2PError::Serialization(e.to_string()))?;
        }

        // Layers are currently innermost-first; reverse so [0] is the outermost
        layers.reverse();

        Ok(OnionCircuit {
            layers,
            route: route.clone(),
        })
    }

    // ── LAYER PEELING ────────────────────────────────────────────────────────

    /// Peel one layer of the onion given our shared secret with the sender of
    /// this layer.
    pub fn peel(
        &self,
        layer: &OnionLayer,
        local_id: &NodeId,
        shared_secret: &[u8],
    ) -> P2PResult<(Vec<u8>, Option<NodeId>)> {
        let key = hop_key(shared_secret, local_id, layer.hop_index);
        let inner = aes_gcm_decrypt(&key, &layer.encrypted_payload)?;
        Ok((inner, layer.next_hop.clone()))
    }

    // ── SEND ─────────────────────────────────────────────────────────────────

    /// Build and send an anonymised message.
    /// Returns immediately after enqueuing the first hop.
    pub async fn send_anonymous(
        &self,
        sender_id: &NodeId,
        plaintext: &[u8],
        _message_type: MessageType,
        hop_shared_secrets: &[Vec<u8>],
    ) -> P2PResult<()> {
        let route = self.select_route(sender_id, MAX_HOPS)?;

        if hop_shared_secrets.len() < route.hops.len() {
            return Err(P2PError::Crypto(
                "Insufficient shared secrets for route".into(),
            ));
        }

        let circuit = self.wrap(plaintext, &route, &hop_shared_secrets[..route.hops.len()])?;

        // Send the outermost layer to the first relay
        let first_hop_id = &route.hops[0];
        let addr = self
            .peer_manager
            .get_peer_addr(first_hop_id)
            .ok_or_else(|| P2PError::PeerNotFound {
                peer_id: first_hop_id.to_string(),
            })?;

        let outer_bytes = bincode::serialize(&circuit.layers[0])
            .map_err(|e| P2PError::Serialization(e.to_string()))?;

        if !self.message_protocol.has_session(first_hop_id) {
            return Err(P2PError::PeerNotFound {
                peer_id: first_hop_id.to_string(),
            });
        }

        let sealed = self.message_protocol.seal_message(
            first_hop_id,
            MessageType::OnionRelay,
            &outer_bytes,
        )?;

        self.message_protocol.send_message(addr, &sealed).await?;

        info!(
            first_hop = %first_hop_id,
            hops = route.hops.len(),
            "Onion message dispatched"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::{PeerManager, PeerManagerConfig};
    use crate::quantum_crypto::{derive_key, Ed25519Keypair, KyberKeypair};

    fn make_router() -> (OnionRouter, Arc<PeerManager>) {
        let local = NodeId::random();
        let (pm, _) = PeerManager::new(local.clone(), PeerManagerConfig::default());
        let ed = Ed25519Keypair::generate();
        let kyber = KyberKeypair::generate();
        let (mp, _) = MessageProtocol::new(ed, kyber, pm.clone());
        let scoring = Arc::new(PeerScoring::new());
        (OnionRouter::new(pm.clone(), mp, scoring), pm)
    }

    fn fake_secret(seed: u8) -> Vec<u8> {
        let mut s = vec![seed; 32];
        s
    }

    #[test]
    fn test_hop_key_is_deterministic() {
        let id = NodeId::random();
        let secret = fake_secret(42);
        let k1 = hop_key(&secret, &id, 0);
        let k2 = hop_key(&secret, &id, 0);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_hop_key_differs_per_hop_index() {
        let id = NodeId::random();
        let secret = fake_secret(42);
        let k0 = hop_key(&secret, &id, 0);
        let k1 = hop_key(&secret, &id, 1);
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_wrap_and_peel_roundtrip() {
        let (router, _) = make_router();
        let local = NodeId::random();

        let relay1 = NodeId::random();
        let relay2 = NodeId::random();
        let route = RoutePath {
            hops: vec![relay1.clone(), relay2.clone()],
        };
        let secrets = vec![fake_secret(1), fake_secret(2)];

        let plaintext = b"super secret payload";
        let circuit = router.wrap(plaintext, &route, &secrets).unwrap();
        assert_eq!(circuit.layers.len(), 2);

        // Peel outer layer (relay1 peels it)
        let key1 = hop_key(&secrets[0], &relay1, 0);
        let outer = &circuit.layers[0];
        let decrypted_outer = aes_gcm_decrypt(&key1, &outer.encrypted_payload).unwrap();

        // The decrypted outer contains the inner OnionLayer serialised
        let inner_layer: OnionLayer = bincode::deserialize(&decrypted_outer).unwrap();

        // Peel inner layer (relay2 peels it)
        let key2 = hop_key(&secrets[1], &relay2, 1);
        let recovered = aes_gcm_decrypt(&key2, &inner_layer.encrypted_payload).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_wrap_mismatched_secrets_fails() {
        let (router, _) = make_router();
        let route = RoutePath {
            hops: vec![NodeId::random(), NodeId::random()],
        };
        let secrets = vec![fake_secret(1)]; // only 1 secret for 2 hops
        assert!(router.wrap(b"data", &route, &secrets).is_err());
    }

    #[tokio::test]
    async fn test_select_route_no_peers_fails() {
        let (router, _) = make_router();
        let sender = NodeId::random();
        assert!(matches!(
            router.select_route(&sender, 3),
            Err(P2PError::NoRoute { .. })
        ));
    }
}
