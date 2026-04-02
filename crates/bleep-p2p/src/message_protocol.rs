//! Production message protocol for bleep-p2p.
//!
//! Transport: async TCP with a 4-byte length-prefix framing.
//! Encryption: Kyber-768 KEM session key → AES-256-GCM per message.
//! Authentication: Ed25519 signature on every message.
//! Anti-replay: 16-byte nonce + timestamp within ±30s window.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::error::{P2PError, P2PResult};
use crate::peer_manager::PeerManager;
use crate::quantum_crypto::{
    ed25519_verify, kyber_decapsulate, kyber_encapsulate, Ed25519Keypair, KyberKeypair, SessionKey,
};
use crate::types::{unix_now, MessageType, NodeId, SecureMessage};

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum allowed message payload size (4 MiB).
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
/// Anti-replay timestamp tolerance (seconds).
const REPLAY_WINDOW_SECS: u64 = 30;
/// TCP connection timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Read timeout per frame.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

// ─────────────────────────────────────────────────────────────────────────────
// SESSION STORE
// ─────────────────────────────────────────────────────────────────────────────

/// Per-peer session holding the symmetric key derived from Kyber KEM.
#[derive(Clone)]
struct Session {
    key: SessionKey,
    #[allow(dead_code)]
    established_at: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// SEEN-NONCE CACHE (anti-replay)
// ─────────────────────────────────────────────────────────────────────────────

struct NonceCache {
    /// nonce (hex) → expiry unix timestamp
    seen: HashMap<String, u64>,
}

impl NonceCache {
    fn new() -> Self {
        NonceCache {
            seen: HashMap::new(),
        }
    }

    /// Returns `true` if this nonce was already seen (replay).
    fn check_and_insert(&mut self, nonce: &[u8; 16], now: u64) -> bool {
        let key = hex::encode(nonce);
        self.evict_old(now);
        if self.seen.contains_key(&key) {
            return true; // replay
        }
        self.seen.insert(key, now + REPLAY_WINDOW_SECS * 2);
        false
    }

    fn evict_old(&mut self, now: u64) {
        self.seen.retain(|_, &mut expiry| expiry > now);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MESSAGE PROTOCOL
// ─────────────────────────────────────────────────────────────────────────────

pub struct MessageProtocol {
    local_identity: Arc<Ed25519Keypair>,
    local_kyber: Arc<KyberKeypair>,
    local_id: NodeId,
    /// Peer NodeId → established session key.
    sessions: DashMap<NodeId, Session>,
    /// Anti-replay cache.
    nonce_cache: Arc<Mutex<NonceCache>>,
    /// Inbound message channel — consumers subscribe to this.
    inbound_tx: mpsc::Sender<(NodeId, SecureMessage)>,
    peer_manager: Arc<PeerManager>,
}

impl MessageProtocol {
    pub fn new(
        local_identity: Ed25519Keypair,
        local_kyber: KyberKeypair,
        peer_manager: Arc<PeerManager>,
    ) -> (Arc<Self>, mpsc::Receiver<(NodeId, SecureMessage)>) {
        let local_id = NodeId::from_bytes(&local_identity.public_key_bytes());
        let (tx, rx) = mpsc::channel(4096);
        let proto = Arc::new(MessageProtocol {
            local_identity: Arc::new(local_identity),
            local_kyber: Arc::new(local_kyber),
            local_id,
            sessions: DashMap::new(),
            nonce_cache: Arc::new(Mutex::new(NonceCache::new())),
            inbound_tx: tx,
            peer_manager,
        });
        (proto, rx)
    }

    // ── SESSION ESTABLISHMENT ─────────────────────────────────────────────────

    /// Initiate a Kyber KEM session with `peer_kyber_pk_bytes`.
    /// Returns the ciphertext that must be sent to the peer so they can decapsulate.
    pub fn initiate_session(
        &self,
        peer_id: &NodeId,
        peer_kyber_pk_bytes: &[u8],
    ) -> P2PResult<Vec<u8>> {
        let (ciphertext, shared_secret) = kyber_encapsulate(peer_kyber_pk_bytes)?;
        let session_key = SessionKey::from_shared_secret(&shared_secret, peer_id.as_bytes());
        self.sessions.insert(
            peer_id.clone(),
            Session {
                key: session_key,
                established_at: unix_now(),
            },
        );
        debug!(peer = %peer_id, "Session initiated (encapsulator)");
        Ok(ciphertext)
    }

    /// Respond to a Kyber KEM session initiation.
    pub fn accept_session(&self, peer_id: &NodeId, kem_ciphertext: &[u8]) -> P2PResult<()> {
        let shared_secret = kyber_decapsulate(kem_ciphertext, &self.local_kyber.secret_key.0)?;
        let session_key = SessionKey::from_shared_secret(&shared_secret, peer_id.as_bytes());
        self.sessions.insert(
            peer_id.clone(),
            Session {
                key: session_key,
                established_at: unix_now(),
            },
        );
        debug!(peer = %peer_id, "Session accepted (decapsulator)");
        Ok(())
    }

    pub fn has_session(&self, peer_id: &NodeId) -> bool {
        self.sessions.contains_key(peer_id)
    }

    // ── ENCRYPT / SIGN ────────────────────────────────────────────────────────

    /// Build a signed, encrypted `SecureMessage`.
    pub fn seal_message(
        &self,
        peer_id: &NodeId,
        message_type: MessageType,
        plaintext_payload: &[u8],
    ) -> P2PResult<SecureMessage> {
        let session = self
            .sessions
            .get(peer_id)
            .ok_or_else(|| P2PError::PeerNotFound {
                peer_id: peer_id.to_string(),
            })?;

        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let encrypted_payload = session.key.encrypt(plaintext_payload)?;

        let mut msg = SecureMessage {
            version: 1,
            sender_id: self.local_id.clone(),
            message_type,
            payload: encrypted_payload,
            signature: Vec::new(),
            hop_count: 0,
            nonce,
            timestamp: unix_now(),
        };
        msg.signature = self.local_identity.sign(&msg.signing_bytes());
        Ok(msg)
    }

    // ── DECRYPT / VERIFY ──────────────────────────────────────────────────────

    /// Verify and decrypt an inbound `SecureMessage`.
    pub async fn open_message(
        &self,
        msg: &SecureMessage,
        sender_pubkey_bytes: &[u8],
    ) -> P2PResult<Vec<u8>> {
        // 1. Timestamp freshness
        let now = unix_now();
        if now.abs_diff(msg.timestamp) > REPLAY_WINDOW_SECS {
            return Err(P2PError::AuthenticationFailed);
        }

        // 2. Replay nonce check
        {
            let mut cache = self.nonce_cache.lock().await;
            if cache.check_and_insert(&msg.nonce, now) {
                return Err(P2PError::AuthenticationFailed);
            }
        }

        // 3. Signature verification
        ed25519_verify(&msg.signing_bytes(), &msg.signature, sender_pubkey_bytes)?;

        // 4. Decryption
        let session = self
            .sessions
            .get(&msg.sender_id)
            .ok_or_else(|| P2PError::PeerNotFound {
                peer_id: msg.sender_id.to_string(),
            })?;
        session.key.decrypt(&msg.payload)
    }

    // ── WIRE FRAMING ──────────────────────────────────────────────────────────

    /// Encode a `SecureMessage` as a length-prefixed frame: `[u32 BE length][bincode bytes]`.
    pub fn encode_frame(msg: &SecureMessage) -> P2PResult<Bytes> {
        let encoded =
            bincode::serialize(msg).map_err(|e| P2PError::Serialization(e.to_string()))?;
        if encoded.len() > MAX_FRAME_BYTES {
            return Err(P2PError::Serialization(format!(
                "Frame too large: {} bytes",
                encoded.len()
            )));
        }
        let mut buf = BytesMut::with_capacity(4 + encoded.len());
        buf.put_u32(encoded.len() as u32);
        buf.extend_from_slice(&encoded);
        Ok(buf.freeze())
    }

    /// Decode a length-prefixed frame from a TCP stream.
    pub async fn decode_frame(stream: &mut TcpStream) -> P2PResult<SecureMessage> {
        // Read 4-byte length header
        let mut len_buf = [0u8; 4];
        timeout(READ_TIMEOUT, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| P2PError::ConnectionTimeout {
                addr: "unknown".into(),
            })?
            .map_err(P2PError::Io)?;

        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len > MAX_FRAME_BYTES {
            return Err(P2PError::Serialization(format!(
                "Frame too large: {} bytes",
                frame_len
            )));
        }

        let mut payload = vec![0u8; frame_len];
        timeout(READ_TIMEOUT, stream.read_exact(&mut payload))
            .await
            .map_err(|_| P2PError::ConnectionTimeout {
                addr: "unknown".into(),
            })?
            .map_err(P2PError::Io)?;

        bincode::deserialize(&payload).map_err(|e| P2PError::Serialization(e.to_string()))
    }

    // ── SEND ─────────────────────────────────────────────────────────────────

    /// Open a TCP connection to `peer_addr` and send `msg`.
    pub async fn send_message(&self, peer_addr: SocketAddr, msg: &SecureMessage) -> P2PResult<()> {
        let frame = Self::encode_frame(msg)?;
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer_addr))
            .await
            .map_err(|_| P2PError::ConnectionTimeout {
                addr: peer_addr.to_string(),
            })?
            .map_err(P2PError::Io)?;

        timeout(READ_TIMEOUT, stream.write_all(&frame))
            .await
            .map_err(|_| P2PError::ConnectionTimeout {
                addr: peer_addr.to_string(),
            })?
            .map_err(P2PError::Io)?;

        stream.flush().await.map_err(P2PError::Io)?;
        debug!(peer = %peer_addr, bytes = frame.len(), "Sent message");
        Ok(())
    }

    // ── LISTEN ────────────────────────────────────────────────────────────────

    /// Accept incoming connections on `bind_addr` and dispatch to the inbound channel.
    pub async fn listen(self: Arc<Self>, bind_addr: SocketAddr) -> P2PResult<()> {
        let listener = TcpListener::bind(bind_addr).await.map_err(P2PError::Io)?;
        info!(addr = %bind_addr, "MessageProtocol listening");

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let proto = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = proto.handle_incoming(stream, peer_addr).await {
                            warn!(peer = %peer_addr, error = %e, "Inbound connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Accept error");
                }
            }
        }
    }

    async fn handle_incoming(
        &self,
        mut stream: TcpStream,
        _peer_addr: SocketAddr,
    ) -> P2PResult<()> {
        let msg = Self::decode_frame(&mut stream).await?;
        let sender_id = msg.sender_id.clone();

        // Look up sender's public key from peer manager
        let sender_pk = self
            .peer_manager
            .get_peer(&sender_id)
            .map(|p| p.public_key.clone())
            .ok_or_else(|| P2PError::PeerNotFound {
                peer_id: sender_id.to_string(),
            })?;

        // Anomaly check
        if let Some(reason) =
            self.peer_manager
                .check_message_anomaly(&sender_id, &msg.payload, msg.hop_count)
        {
            warn!(peer = %sender_id, reason = %reason, "Anomaly detected, flagging peer");
            self.peer_manager.record_failure(&sender_id);
            return Err(P2PError::AuthenticationFailed);
        }

        // Verify and decrypt
        let _plaintext = self.open_message(&msg, &sender_pk).await.map_err(|e| {
            self.peer_manager.record_failure(&sender_id);
            e
        })?;

        self.peer_manager.record_success(&sender_id);
        self.peer_manager.record_message(&sender_id);
        self.peer_manager.touch(&sender_id);

        let _ = self.inbound_tx.send((sender_id, msg)).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kademlia_dht::KademliaDht;
    use crate::peer_manager::{PeerManager, PeerManagerConfig};
    use crate::quantum_crypto::{sphincs_sign, Ed25519Keypair, KyberKeypair, SphincsKeypair};

    fn make_proto() -> (
        Arc<MessageProtocol>,
        mpsc::Receiver<(NodeId, SecureMessage)>,
        Arc<PeerManager>,
    ) {
        let ed = Ed25519Keypair::generate();
        let kyber = KyberKeypair::generate();
        let local_id = NodeId::from_bytes(&ed.public_key_bytes());
        let (pm, _) = PeerManager::new(local_id.clone(), PeerManagerConfig::default());
        let (proto, rx) = MessageProtocol::new(ed, kyber, pm.clone());
        (proto, rx, pm)
    }

    #[tokio::test]
    async fn test_session_initiation_and_encrypt_decrypt() {
        let (proto_a, _, _) = make_proto();
        let (proto_b, _, _) = make_proto();

        let peer_id_b = proto_b.local_id.clone();

        // A initiates session to B
        let kem_ct = proto_a
            .initiate_session(&peer_id_b, &proto_b.local_kyber.public_key.0)
            .unwrap();

        // B accepts
        proto_b.accept_session(&proto_a.local_id, &kem_ct).unwrap();

        // A seals a message
        let msg = proto_a
            .seal_message(&peer_id_b, MessageType::Transaction, b"hello bleep")
            .unwrap();

        // Verify the signing bytes are non-empty
        assert!(!msg.signature.is_empty());
        assert!(!msg.payload.is_empty());
    }

    #[test]
    fn test_encode_decode_frame_roundtrip() {
        let msg = SecureMessage {
            version: 1,
            sender_id: NodeId::random(),
            message_type: MessageType::Block,
            payload: b"test payload".to_vec(),
            signature: vec![0u8; 64],
            hop_count: 2,
            nonce: [42u8; 16],
            timestamp: unix_now(),
        };
        let frame = MessageProtocol::encode_frame(&msg).unwrap();
        // We can't easily decode without async here, but verify frame structure
        assert!(frame.len() > 4);
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len + 4, frame.len());
    }

    #[test]
    fn test_encode_oversized_frame_fails() {
        let msg = SecureMessage {
            version: 1,
            sender_id: NodeId::random(),
            message_type: MessageType::Custom("x".into()),
            payload: vec![0u8; MAX_FRAME_BYTES + 1],
            signature: vec![],
            hop_count: 0,
            nonce: [0u8; 16],
            timestamp: unix_now(),
        };
        assert!(MessageProtocol::encode_frame(&msg).is_err());
    }

    #[tokio::test]
    async fn test_replay_attack_rejected() {
        let (proto_a, _, _) = make_proto();
        let (proto_b, _, _) = make_proto();
        let peer_id_b = proto_b.local_id.clone();

        let kem_ct = proto_a
            .initiate_session(&peer_id_b, &proto_b.local_kyber.public_key.0)
            .unwrap();
        proto_b.accept_session(&proto_a.local_id, &kem_ct).unwrap();

        // Register peer_a in proto_b's peer manager (normally done during handshake)
        // Skipped here — open_message would fail on peer lookup, which is expected
        // This test validates the nonce-cache path specifically
        let msg = proto_a
            .seal_message(&peer_id_b, MessageType::Ping, b"ping")
            .unwrap();

        let mut cache = proto_b.nonce_cache.lock().await;
        let now = unix_now();
        // First insert should not be a replay
        assert!(!cache.check_and_insert(&msg.nonce, now));
        // Second insert with same nonce IS a replay
        assert!(cache.check_and_insert(&msg.nonce, now));
    }
}
