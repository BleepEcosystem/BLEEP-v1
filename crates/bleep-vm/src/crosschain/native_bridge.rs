//! # Layer 7 — Cross-Chain Native Bridge
//!
//! BLEEP VM supports cross-chain calls **natively** — contracts don't
//! need to manually call a bridge. The VM handles routing automatically
//! through BLEEP Connect.
//!
//! The bridge layer:
//! 1. Validates the destination chain is supported
//! 2. Encodes the call in the destination chain's ABI format
//! 3. Routes through BLEEP Connect's 4-layer security stack
//! 4. Returns the result (or a receipt if async)
//!
//! Security: cross-chain calls go through BLEEP Connect which provides:
//! - Kyber-768 KEM encrypted transport
//! - SPHINCS+ signed messages
//! - ZK proof of source execution (optional)
//! - Relayer stake slashing on fraud

use crate::error::{VmError, VmResult};
use crate::execution::state_transition::StateDiff;
use crate::intent::CrossChainIntent;
use crate::runtime::gas_model::GasModel;
use crate::types::ChainId;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, instrument};

// ─────────────────────────────────────────────────────────────────────────────
// CHAIN ABI ENCODING
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes calldata in the target chain's native format.
pub fn encode_for_chain(chain: &ChainId, calldata: &[u8]) -> VmResult<Vec<u8>> {
    match chain {
        ChainId::Ethereum | ChainId::EthereumL2(_) => Ok(calldata.to_vec()),

        ChainId::Solana => {
            let mut encoded = Vec::with_capacity(4 + calldata.len());
            encoded.extend_from_slice(&(calldata.len() as u32).to_le_bytes());
            encoded.extend_from_slice(calldata);
            Ok(encoded)
        }

        ChainId::CosmosHub => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(calldata);
            let json = serde_json::json!({
                "type": "wasm/execute",
                "value": { "msg": b64 }
            });
            Ok(serde_json::to_vec(&json).unwrap_or_default())
        }

        ChainId::Polkadot => {
            let len = calldata.len();
            let mut encoded = Vec::with_capacity(2 + len);
            if len < 64 {
                encoded.push((len as u8) << 2);
            } else if len < 16_384 {
                let compact = ((len as u16) << 2) | 0x01;
                encoded.extend_from_slice(&compact.to_le_bytes());
            } else {
                encoded.push(0x02);
                encoded.extend_from_slice(&(len as u32).to_le_bytes());
            }
            encoded.extend_from_slice(calldata);
            Ok(encoded)
        }

        ChainId::Near => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(calldata);
            let json = serde_json::json!({ "args_base64": b64 });
            Ok(serde_json::to_vec(&json).unwrap_or_default())
        }

        ChainId::Sui | ChainId::Aptos => {
            let len = calldata.len();
            let mut encoded = Vec::with_capacity(4 + len);
            let mut l = len;
            loop {
                let byte = (l & 0x7F) as u8;
                l >>= 7;
                if l == 0 {
                    encoded.push(byte);
                    break;
                } else {
                    encoded.push(byte | 0x80);
                }
            }
            encoded.extend_from_slice(calldata);
            Ok(encoded)
        }

        ChainId::Bleep => Ok(calldata.to_vec()),

        ChainId::Bitcoin => {
            if calldata.len() > 80 {
                return Err(VmError::ValidationError(
                    "Bitcoin OP_RETURN limited to 80 bytes".into(),
                ));
            }
            let mut script = Vec::with_capacity(2 + calldata.len());
            script.push(0x6a); // OP_RETURN
            script.push(calldata.len() as u8);
            script.extend_from_slice(calldata);
            Ok(script)
        }

        ChainId::Custom(_) => Ok(calldata.to_vec()),
    }
}

/// Decodes a response from a remote chain back to BLEEP-native format.
pub fn decode_from_chain(chain: &ChainId, response: &[u8]) -> VmResult<Vec<u8>> {
    match chain {
        ChainId::Ethereum | ChainId::EthereumL2(_) | ChainId::Bleep => Ok(response.to_vec()),
        ChainId::Solana => {
            if response.len() < 4 {
                return Ok(response.to_vec());
            }
            let len =
                u32::from_le_bytes([response[0], response[1], response[2], response[3]]) as usize;
            if response.len() >= 4 + len {
                Ok(response[4..4 + len].to_vec())
            } else {
                Ok(response.to_vec())
            }
        }
        ChainId::CosmosHub | ChainId::Near => {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(response) {
                if let Some(result) = json.get("result") {
                    if let Some(s) = result.as_str() {
                        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(s) {
                            return Ok(decoded);
                        }
                    }
                }
            }
            Ok(response.to_vec())
        }
        _ => Ok(response.to_vec()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CROSS-CHAIN MESSAGE
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,
    Delivered,
    Confirmed,
    Failed(String),
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMessage {
    pub id: [u8; 32],
    pub source_chain: ChainId,
    pub destination_chain: ChainId,
    pub sender: Vec<u8>,
    pub contract: Vec<u8>,
    pub encoded_calldata: Vec<u8>,
    pub source_gas_limit: u64,
    pub dest_gas_limit: u64,
    pub bridge_value: u128,
    pub relay_fee: u128,
    pub require_zk_proof: bool,
    pub status: MessageStatus,
    pub created_at: u64,
    pub timeout_at: u64,
    pub source_proof: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
}

impl CrossChainMessage {
    pub fn new(
        source_chain: ChainId,
        destination_chain: ChainId,
        sender: Vec<u8>,
        contract: Vec<u8>,
        encoded_calldata: Vec<u8>,
        dest_gas_limit: u64,
        bridge_value: u128,
        relay_fee: u128,
        require_zk_proof: bool,
    ) -> Self {
        let now = unix_now();
        let id = Self::compute_id(
            &source_chain,
            &destination_chain,
            &sender,
            &contract,
            &encoded_calldata,
            now,
        );
        CrossChainMessage {
            id,
            source_chain,
            destination_chain,
            sender,
            contract,
            encoded_calldata,
            source_gas_limit: 0,
            dest_gas_limit,
            bridge_value,
            relay_fee,
            require_zk_proof,
            status: MessageStatus::Pending,
            created_at: now,
            timeout_at: now + 3600,
            source_proof: None,
            response: None,
        }
    }

    pub fn compute_id(
        src: &ChainId,
        dst: &ChainId,
        sender: &[u8],
        contract: &[u8],
        calldata: &[u8],
        ts: u64,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(src.to_string().as_bytes());
        h.update(dst.to_string().as_bytes());
        h.update(sender);
        h.update(contract);
        h.update(calldata);
        h.update(&ts.to_le_bytes());
        h.finalize().into()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CONNECT BRIDGE
// ─────────────────────────────────────────────────────────────────────────────

pub struct ConnectBridge {
    gas_model: GasModel,
    supported_chains: HashMap<String, ChainConfig>,
    pending: parking_lot::RwLock<HashMap<[u8; 32], CrossChainMessage>>,
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: ChainId,
    pub relayer_url: String,
    pub confirmation_blocks: u32,
    pub max_message_size: usize,
}

impl ConnectBridge {
    pub fn new() -> Self {
        let mut supported_chains = HashMap::new();

        let chains: Vec<(&str, ChainId, &str, u32, usize)> = vec![
            (
                "ethereum",
                ChainId::Ethereum,
                "https://relay.bleep.network/eth",
                12,
                128_000,
            ),
            (
                "solana",
                ChainId::Solana,
                "https://relay.bleep.network/sol",
                1,
                1_232,
            ),
            (
                "cosmos",
                ChainId::CosmosHub,
                "https://relay.bleep.network/cosmos",
                6,
                256_000,
            ),
            (
                "polkadot",
                ChainId::Polkadot,
                "https://relay.bleep.network/dot",
                2,
                262_144,
            ),
            (
                "near",
                ChainId::Near,
                "https://relay.bleep.network/near",
                1,
                1_048_576,
            ),
            (
                "sui",
                ChainId::Sui,
                "https://relay.bleep.network/sui",
                1,
                131_072,
            ),
            (
                "aptos",
                ChainId::Aptos,
                "https://relay.bleep.network/aptos",
                1,
                131_072,
            ),
        ];

        for (key, chain_id, url, confirmations, max_size) in chains {
            supported_chains.insert(
                key.to_string(),
                ChainConfig {
                    chain_id,
                    relayer_url: url.to_string(),
                    confirmation_blocks: confirmations,
                    max_message_size: max_size,
                },
            );
        }

        ConnectBridge {
            gas_model: GasModel::default(),
            supported_chains,
            pending: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    #[instrument(skip(self, intent, sender), fields(dst = %intent.destination_chain))]
    pub async fn submit(
        &self,
        intent: &CrossChainIntent,
        sender: &[u8; 32],
    ) -> VmResult<([u8; 32], StateDiff)> {
        let chain_key = chain_key(&intent.destination_chain);

        let config = self.supported_chains.get(chain_key).ok_or_else(|| {
            VmError::ValidationError(format!(
                "Unsupported destination chain: {}",
                intent.destination_chain
            ))
        })?;

        if intent.calldata.len() > config.max_message_size {
            return Err(VmError::ValidationError(format!(
                "Calldata too large for {}: {} > {}",
                intent.destination_chain,
                intent.calldata.len(),
                config.max_message_size,
            )));
        }

        let encoded = encode_for_chain(&intent.destination_chain, &intent.calldata)?;

        info!(
            dst     = %intent.destination_chain,
            payload = encoded.len(),
            value   = intent.bridge_value,
            "Submitting cross-chain message"
        );

        let msg = CrossChainMessage::new(
            ChainId::Bleep,
            intent.destination_chain.clone(),
            sender.to_vec(),
            intent.contract.clone(),
            encoded,
            intent.dest_gas_limit,
            intent.bridge_value,
            intent.relay_fee,
            intent.require_zk_proof,
        );
        let msg_id = msg.id;

        {
            let mut pending = self.pending.write();
            pending.insert(msg_id, msg);
        }

        let mut diff = StateDiff::empty();
        diff.add_balance_update(*sender, -(intent.relay_fee as i128));
        diff.gas_charged = self.gas_model.cross_chain_base() + (intent.calldata.len() as u64 * 10);

        // Emit bridge event (BLEEP Connect contract address = [0xBB; 32])
        let contract_bytes = [0xBBu8; 32];
        let mut topic_chain = [0u8; 32];
        let dst_str = intent.destination_chain.to_string();
        let copy_len = dst_str.len().min(32);
        topic_chain[..copy_len].copy_from_slice(&dst_str.as_bytes()[..copy_len]);

        diff.emit_event(
            contract_bytes,
            vec![msg_id, topic_chain],
            intent.calldata.clone(),
        );

        Ok((msg_id, diff))
    }

    pub fn status(&self, msg_id: &[u8; 32]) -> Option<MessageStatus> {
        self.pending.read().get(msg_id).map(|m| m.status.clone())
    }

    pub fn pending_for_chain(&self, chain: &ChainId) -> Vec<[u8; 32]> {
        self.pending
            .read()
            .iter()
            .filter(|(_, m)| &m.destination_chain == chain && m.status == MessageStatus::Pending)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn is_supported(&self, chain: &ChainId) -> bool {
        self.supported_chains.contains_key(chain_key(chain))
    }

    pub fn supported_chains(&self) -> Vec<&ChainId> {
        self.supported_chains
            .values()
            .map(|c| &c.chain_id)
            .collect()
    }
}

impl Default for ConnectBridge {
    fn default() -> Self {
        Self::new()
    }
}

fn chain_key(chain: &ChainId) -> &'static str {
    match chain {
        ChainId::Ethereum | ChainId::EthereumL2(_) => "ethereum",
        ChainId::Solana => "solana",
        ChainId::CosmosHub => "cosmos",
        ChainId::Polkadot => "polkadot",
        ChainId::Near => "near",
        ChainId::Sui => "sui",
        ChainId::Aptos => "aptos",
        ChainId::Bleep => "bleep",
        _ => "unknown",
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_for_evm_passthrough() {
        let data = vec![0x12u8, 0x34, 0x56];
        let encoded = encode_for_chain(&ChainId::Ethereum, &data).unwrap();
        assert_eq!(encoded, data);
    }

    #[test]
    fn test_encode_for_solana_length_prefix() {
        let data = vec![0xAAu8, 0xBB, 0xCC];
        let encoded = encode_for_chain(&ChainId::Solana, &data).unwrap();
        assert_eq!(&encoded[0..4], &[3u8, 0, 0, 0]);
        assert_eq!(&encoded[4..], &data);
    }

    #[test]
    fn test_decode_solana_roundtrip() {
        let data = vec![0x01u8, 0x02, 0x03, 0x04];
        let encoded = encode_for_chain(&ChainId::Solana, &data).unwrap();
        let decoded = decode_from_chain(&ChainId::Solana, &encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_bitcoin_size_limit() {
        let ok_data = vec![0u8; 80];
        assert!(encode_for_chain(&ChainId::Bitcoin, &ok_data).is_ok());
        let too_big = vec![0u8; 81];
        assert!(encode_for_chain(&ChainId::Bitcoin, &too_big).is_err());
    }

    #[test]
    fn test_sui_bcs_encoding() {
        let data = vec![0xAAu8; 5];
        let encoded = encode_for_chain(&ChainId::Sui, &data).unwrap();
        assert_eq!(encoded[0], 5u8);
        assert_eq!(&encoded[1..], &data);
    }

    #[test]
    fn test_cosmos_json_encoding() {
        let data = vec![0x01u8, 0x02];
        let encoded = encode_for_chain(&ChainId::CosmosHub, &data).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(json["type"], "wasm/execute");
    }

    #[test]
    fn test_bridge_supported_chains() {
        let bridge = ConnectBridge::new();
        assert!(bridge.is_supported(&ChainId::Ethereum));
        assert!(bridge.is_supported(&ChainId::Solana));
        assert!(bridge.is_supported(&ChainId::CosmosHub));
        assert!(!bridge.is_supported(&ChainId::Bitcoin));
    }

    #[tokio::test]
    async fn test_submit_cross_chain_intent() {
        let bridge = ConnectBridge::new();
        let sender = [0x01u8; 32];
        let intent = CrossChainIntent {
            destination_chain: ChainId::Ethereum,
            contract: vec![0xABu8; 20],
            calldata: vec![0x12, 0x34, 0x56],
            source_gas_limit: 100_000,
            dest_gas_limit: 200_000,
            bridge_value: 0,
            relay_fee: 1_000,
            require_zk_proof: false,
        };
        let (msg_id, diff) = bridge.submit(&intent, &sender).await.unwrap();
        assert_ne!(msg_id, [0u8; 32]);
        assert_eq!(diff.balances[&sender].delta, -1_000);
        assert!(!diff.events.is_empty());
    }

    #[tokio::test]
    async fn test_submit_to_unsupported_chain_fails() {
        let bridge = ConnectBridge::new();
        let sender = [0u8; 32];
        let intent = CrossChainIntent {
            destination_chain: ChainId::Bitcoin,
            contract: vec![],
            calldata: vec![],
            source_gas_limit: 100_000,
            dest_gas_limit: 100_000,
            bridge_value: 0,
            relay_fee: 0,
            require_zk_proof: false,
        };
        assert!(bridge.submit(&intent, &sender).await.is_err());
    }

    #[tokio::test]
    async fn test_message_status_after_submit() {
        let bridge = ConnectBridge::new();
        let sender = [0u8; 32];
        let intent = CrossChainIntent {
            destination_chain: ChainId::Solana,
            contract: vec![0u8; 32],
            calldata: vec![1, 2, 3],
            source_gas_limit: 100_000,
            dest_gas_limit: 100_000,
            bridge_value: 0,
            relay_fee: 500,
            require_zk_proof: false,
        };
        let (msg_id, _) = bridge.submit(&intent, &sender).await.unwrap();
        assert_eq!(bridge.status(&msg_id), Some(MessageStatus::Pending));
    }

    #[test]
    fn test_message_id_determinism() {
        let now = unix_now();
        let id1 = CrossChainMessage::compute_id(
            &ChainId::Bleep,
            &ChainId::Ethereum,
            &[1u8; 32],
            &[2u8; 20],
            &[3, 4],
            now,
        );
        let id2 = CrossChainMessage::compute_id(
            &ChainId::Bleep,
            &ChainId::Ethereum,
            &[1u8; 32],
            &[2u8; 20],
            &[3, 4],
            now,
        );
        assert_eq!(id1, id2);
    }
}
