use bleep_crypto::quantum_secure::QuantumSecure;
use bleep_state::state_manager::StateManager;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;

// Re-export these from bleep_p2p once available
pub struct PeerManager;
pub struct GossipProtocol;
pub struct MultiHopRouting;
pub struct DarkRouting;

/// Error type for P2P operations not yet implemented
#[derive(Debug)]
pub struct P2PNotImplementedError;

impl std::fmt::Display for P2PNotImplementedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "P2P networking not yet integrated (Phase 0: Crypto only)"
        )
    }
}

impl std::error::Error for P2PNotImplementedError {}

impl PeerManager {
    /// Add transaction to pool
    /// Currently unimplemented - P2P integration pending
    pub async fn add_transaction_to_pool(
        &self,
        _tx: ZKTransaction,
    ) -> Result<(), P2PNotImplementedError> {
        Err(P2PNotImplementedError)
    }
}

impl GossipProtocol {
    /// Broadcast message to network
    /// Currently unimplemented - P2P integration pending
    pub async fn broadcast_message(
        &self,
        _message: P2PMessage,
    ) -> Result<(), P2PNotImplementedError> {
        Err(P2PNotImplementedError)
    }
}

impl MultiHopRouting {
    /// Select a route for message
    /// Currently unimplemented - P2P integration pending
    pub async fn select_route(
        &self,
        _sender: &str,
        _receiver: &str,
    ) -> Result<Vec<String>, P2PNotImplementedError> {
        Err(P2PNotImplementedError)
    }

    /// Forward message along route
    /// Currently unimplemented - P2P integration pending
    pub async fn forward_message(
        &self,
        _route: Vec<String>,
        _message: P2PMessage,
    ) -> Result<(), P2PNotImplementedError> {
        Err(P2PNotImplementedError)
    }
}

impl DarkRouting {
    /// Select anonymous route
    /// Currently unimplemented - P2P integration pending
    pub async fn select_anonymous_route(
        &self,
        _sender: &str,
    ) -> Result<Vec<String>, P2PNotImplementedError> {
        Err(P2PNotImplementedError)
    }

    /// Forward message anonymously
    /// Currently unimplemented - P2P integration pending
    pub async fn forward_anonymous(
        &self,
        _route: Vec<String>,
        _message: P2PMessage,
    ) -> Result<(), P2PNotImplementedError> {
        Err(P2PNotImplementedError)
    }
}

/// Peer-to-peer message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    Transaction(ZKTransaction),
    Block(Box<Block>),
    Consensus(ConsensusMessage),
}

/// Represents a Zero-Knowledge Proof (ZKP)-based transaction
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZKTransaction {
    #[serde(default = "legacy_transaction_version")]
    pub version: u16,
    pub chain_id: String,
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    #[serde(default)]
    pub fee: u64,
    pub timestamp: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

fn legacy_transaction_version() -> u16 {
    1
}

pub const MAX_PENDING_NONCE_GAP: u64 = 64;
pub const MAX_PENDING_PER_SENDER: usize = 64;
pub const MAX_POOL_BYTES: usize = 256 * 1024 * 1024;
pub const MIN_TRANSACTION_FEE: u64 = 1;

pub fn pending_admission_allowed(
    state: &StateManager,
    pending: &[ZKTransaction],
    candidate: &ZKTransaction,
) -> bool {
    let committed_nonce = state.get_nonce(&candidate.sender);
    let pending_nonces: BTreeSet<u64> = pending
        .iter()
        .filter(|tx| tx.sender == candidate.sender)
        .map(|tx| tx.nonce)
        .collect();
    let mut next_nonce = committed_nonce;
    while pending_nonces.contains(&next_nonce) {
        let Some(next) = next_nonce.checked_add(1) else {
            return false;
        };
        next_nonce = next;
    }

    if candidate.nonce == u64::MAX
        || candidate.nonce != next_nonce
        || candidate.nonce > committed_nonce.saturating_add(MAX_PENDING_NONCE_GAP)
        || pending
            .iter()
            .filter(|tx| tx.sender == candidate.sender)
            .count()
            >= MAX_PENDING_PER_SENDER
    {
        return false;
    }

    let reserved = pending
        .iter()
        .filter(|tx| tx.sender == candidate.sender)
        .try_fold(0u128, |total, tx| {
            total.checked_add(tx.amount as u128 + tx.fee as u128)
        });
    let Some(reserved) = reserved else {
        return false;
    };
    let Some(required) = reserved.checked_add(candidate.amount as u128 + candidate.fee as u128)
    else {
        return false;
    };
    required <= state.get_balance(&candidate.sender)
}

pub fn transaction_size(transaction: &ZKTransaction) -> usize {
    transaction
        .chain_id
        .len()
        .saturating_add(transaction.sender.len())
        .saturating_add(transaction.receiver.len())
        .saturating_add(transaction.signature.len())
        .saturating_add(std::mem::size_of::<u16>())
        .saturating_add(4 * std::mem::size_of::<u64>())
}

pub fn compare_fee_priority(left: &ZKTransaction, right: &ZKTransaction) -> std::cmp::Ordering {
    let left_size = transaction_size(left).max(1) as u128;
    let right_size = transaction_size(right).max(1) as u128;
    (left.fee as u128 * right_size)
        .cmp(&(right.fee as u128 * left_size))
        .then_with(|| left.get_hash().cmp(&right.get_hash()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorStakeAction {
    pub label: String,
    pub kyber_public_key: Vec<u8>,
    pub vrf_public_key: Vec<u8>,
}

const VALIDATOR_STAKE_RECEIVER_PREFIX: &str = "bleep:validator-stake:v1:";

pub fn parse_validator_stake_receiver(
    receiver: &str,
) -> Result<Option<ValidatorStakeAction>, String> {
    let Some(encoded) = receiver.strip_prefix(VALIDATOR_STAKE_RECEIVER_PREFIX) else {
        return Ok(None);
    };
    let mut fields = encoded.split(':');
    let label = fields
        .next()
        .and_then(|value| hex::decode(value).ok())
        .and_then(|value| String::from_utf8(value).ok())
        .filter(|value| {
            !value.trim().is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        .ok_or_else(|| "invalid validator stake label".to_string())?;
    let kyber_public_key = fields
        .next()
        .and_then(|value| hex::decode(value).ok())
        .filter(|value| value.len() == 1568)
        .ok_or_else(|| "invalid validator stake Kyber key".to_string())?;
    let vrf_public_key = fields
        .next()
        .and_then(|value| hex::decode(value).ok())
        .ok_or_else(|| "invalid validator stake VRF key encoding".to_string())?;
    if fields.next().is_some() || vrf_public_key.len() != 32 {
        return Err("invalid validator stake receiver encoding".into());
    }

    let canonical = bleep_crypto::tx_signer::validator_stake_receiver(
        &label,
        &kyber_public_key,
        &vrf_public_key,
    );
    if canonical != receiver {
        return Err("non-canonical validator stake receiver".into());
    }

    Ok(Some(ValidatorStakeAction {
        label,
        kyber_public_key,
        vrf_public_key,
    }))
}

pub fn validator_bond_account(label: &str, timestamp: u64) -> String {
    format!("bleep:validator-bond:val-{label}-{timestamp}")
}

pub fn validator_id(label: &str, timestamp: u64) -> String {
    format!("val-{label}-{timestamp}")
}

pub fn transaction_execution_receiver(
    sender: &str,
    receiver: &str,
    timestamp: u64,
) -> Result<String, String> {
    match parse_validator_stake_receiver(receiver)? {
        Some(action) => Ok(validator_bond_account(&action.label, timestamp)),
        None => {
            if sender == receiver {
                return Err(format!("Self-transfer rejected for {sender}"));
            }
            Ok(receiver.to_string())
        }
    }
}

impl ZKTransaction {
    /// Creates a new ZKP transaction and signs it with quantum-safe signature (SPHINCS+)
    pub fn new(sender: &str, receiver: &str, amount: u64, quantum_secure: &QuantumSecure) -> Self {
        let timestamp = Utc::now().timestamp() as u64;
        let data = format!("{}{}{}{}", sender, receiver, amount, timestamp);
        let signature = quantum_secure.sign(data.as_bytes());
        Self {
            version: 1,
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            amount,
            fee: 0,
            timestamp,
            nonce: 0,
            signature,
        }
    }

    /// Verifies transaction validity using quantum-safe signatures (SPHINCS+)
    pub fn verify(&self, quantum_secure: &QuantumSecure) -> bool {
        let data = format!(
            "{}{}{}{}",
            self.sender, self.receiver, self.amount, self.timestamp
        );
        quantum_secure.verify(data.as_bytes(), &self.signature)
    }

    /// Verify the versioned transaction signature and bind its key to `sender`.
    pub fn verify_account_authorization(&self) -> bool {
        const SPHINCS_PK_LEN: usize = 64;
        if self.chain_id.is_empty() || self.signature.len() <= SPHINCS_PK_LEN {
            return false;
        }
        let (pk_bytes, sig_bytes) = self.signature.split_at(SPHINCS_PK_LEN);
        if !bleep_crypto::account_address_matches_public_key(&self.sender, pk_bytes) {
            return false;
        }
        let payload = match self.version {
            1 if self.fee == 0 => match parse_validator_stake_receiver(&self.receiver) {
                Ok(Some(action)) => bleep_crypto::tx_signer::validator_stake_payload(
                    &self.chain_id,
                    &self.sender,
                    bleep_crypto::tx_signer::ValidatorKeyBindings {
                        label: &action.label,
                        kyber_public_key: &action.kyber_public_key,
                        vrf_public_key: &action.vrf_public_key,
                    },
                    self.amount,
                    self.timestamp,
                    self.nonce,
                ),
                Ok(None) => bleep_crypto::tx_signer::tx_payload(
                    &self.chain_id,
                    &self.sender,
                    &self.receiver,
                    self.amount,
                    self.timestamp,
                    self.nonce,
                ),
                Err(_) => return false,
            },
            2 if self.fee > 0 => match parse_validator_stake_receiver(&self.receiver) {
                Ok(Some(action)) => bleep_crypto::tx_signer::validator_stake_payload_v2(
                    &self.chain_id,
                    &self.sender,
                    bleep_crypto::tx_signer::ValidatorKeyBindings {
                        label: &action.label,
                        kyber_public_key: &action.kyber_public_key,
                        vrf_public_key: &action.vrf_public_key,
                    },
                    self.amount,
                    self.fee,
                    self.timestamp,
                    self.nonce,
                ),
                Ok(None) => bleep_crypto::tx_signer::tx_payload_v2(
                    &self.chain_id,
                    &self.sender,
                    &self.receiver,
                    self.amount,
                    self.fee,
                    self.timestamp,
                    self.nonce,
                ),
                Err(_) => return false,
            },
            _ => return false,
        };
        bleep_crypto::verify_tx_signature_for_address(&payload, sig_bytes, pk_bytes, &self.sender)
    }
}

/// Consensus message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    Propose,
    Vote,
    Commit,
}

use crate::block::Block;

/// Manages transaction lifecycle and validation
pub struct TransactionManager {
    quantum_secure: Arc<QuantumSecure>,
    pub(crate) peer_manager: Arc<PeerManager>,
    pub(crate) gossip_protocol: Arc<GossipProtocol>,
    pub(crate) multi_hop_routing: Arc<MultiHopRouting>,
    pub(crate) dark_routing: Arc<DarkRouting>,
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new(
            Arc::new(PeerManager),
            Arc::new(GossipProtocol),
            Arc::new(MultiHopRouting),
            Arc::new(DarkRouting),
        )
    }
}

impl TransactionManager {
    /// Creates a new TransactionManager with quantum-secure cryptography
    pub fn new(
        peer_manager: Arc<PeerManager>,
        gossip_protocol: Arc<GossipProtocol>,
        multi_hop_routing: Arc<MultiHopRouting>,
        dark_routing: Arc<DarkRouting>,
    ) -> Self {
        Self {
            quantum_secure: Arc::new(QuantumSecure::keygen()),
            peer_manager,
            gossip_protocol,
            multi_hop_routing,
            dark_routing,
        }
    }

    /// Broadcasts a transaction to all peers using GossipProtocol
    pub async fn broadcast_transaction(&self, transaction: ZKTransaction) {
        let message = P2PMessage::Transaction(transaction);
        let _ = self.gossip_protocol.broadcast_message(message).await;
    }

    /// Routes a transaction securely over multiple hops
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

    /// Sends a fully anonymous transaction using DarkRouting
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

    /// Processes incoming P2P transaction messages
    pub async fn process_p2p_message(&self, message: P2PMessage) {
        if let P2PMessage::Transaction(tx) = message {
            if tx.verify(&self.quantum_secure) {
                let _ = self.peer_manager.add_transaction_to_pool(tx).await;
                println!("✅ Valid transaction received and added to mempool.");
            } else {
                println!("❌ Invalid transaction rejected.");
            }
        }
    }
}
