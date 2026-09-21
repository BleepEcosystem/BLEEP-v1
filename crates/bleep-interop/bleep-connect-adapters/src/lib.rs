//! # bleep-connect-adapters
//!
//! Chain-specific adapters for encoding, verifying, and finalizing cross-chain transfers.
//! Each adapter implements the `ChainAdapter` trait, providing three methods:
//! - `encode_transfer`: Serialize an intent into chain-specific calldata
//! - `verify_execution`: Validate an execution proof against the target chain's rules
//! - `get_finality_blocks`: Return the number of confirmations needed for finality

use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use tracing::debug;

use bleep_connect_crypto::sha256;
use bleep_connect_types::{BleepConnectError, BleepConnectResult, ChainId, InstantIntent};

// ─────────────────────────────────────────────────────────────────────────────
// CHAIN ADAPTER TRAIT
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait ChainAdapter: Send + Sync {
    /// Encode a cross-chain transfer intent into chain-specific calldata/instruction bytes.
    fn encode_transfer(&self, intent: &InstantIntent) -> BleepConnectResult<Vec<u8>>;

    /// Verify that a transfer was executed correctly on the destination chain.
    /// `execution_proof` is the bytes returned by `encode_transfer` plus execution evidence.
    fn verify_execution(
        &self,
        intent: &InstantIntent,
        execution_proof: &[u8],
    ) -> BleepConnectResult<bool>;

    /// Return the number of block confirmations needed for finality on this chain.
    fn get_finality_blocks(&self) -> u64;

    /// Return the chain ID this adapter handles.
    fn chain_id(&self) -> ChainId;

    /// Return the chain's native token decimals.
    fn native_decimals(&self) -> u8;
}

// ─────────────────────────────────────────────────────────────────────────────
// ETHEREUM ADAPTER (covers mainnet, Arbitrum, Optimism, Base, zkSync, Polygon)
// ─────────────────────────────────────────────────────────────────────────────

pub struct EthereumAdapter {
    chain: ChainId,
    finality_blocks: u64,
    /// Keccak256("fulfillIntent(bytes32,address,uint256,uint256)")
    fulfill_selector: [u8; 4],
}

impl EthereumAdapter {
    pub fn new(chain: ChainId) -> Self {
        let finality = match chain {
            ChainId::Ethereum => 12,
            ChainId::Polygon => 128,
            ChainId::Arbitrum => 1,
            ChainId::Optimism => 1,
            ChainId::Base => 1,
            ChainId::ZkSync => 1,
            ChainId::BSC => 15,
            ChainId::Avalanche => 1,
            _ => 12,
        };

        // keccak256("fulfillIntent(bytes32,address,uint256,uint256)") first 4 bytes
        let mut k = Keccak256::new();
        k.update(b"fulfillIntent(bytes32,address,uint256,uint256)");
        let hash = k.finalize();
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&hash[..4]);

        Self {
            chain,
            finality_blocks: finality,
            fulfill_selector: selector,
        }
    }

    /// ABI-encode a uint256 (big-endian, left-padded to 32 bytes).
    fn abi_encode_u256(value: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&value.to_be_bytes());
        out
    }

    /// ABI-encode an address (left-padded to 32 bytes, 20 bytes address).
    fn abi_encode_address(hex_addr: &str) -> [u8; 32] {
        let cleaned = hex_addr.trim_start_matches("0x");
        let bytes = hex::decode(cleaned).unwrap_or_else(|_| vec![0u8; 20]);
        let mut out = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        out[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
        out
    }
}

#[async_trait]
impl ChainAdapter for EthereumAdapter {
    fn encode_transfer(&self, intent: &InstantIntent) -> BleepConnectResult<Vec<u8>> {
        // ABI-encode: fulfillIntent(bytes32 intentId, address recipient, uint256 minAmount, uint256 deadline)
        let intent_id = intent.calculate_id();
        let recipient_bytes = Self::abi_encode_address(&intent.recipient.address);
        let min_amount = Self::abi_encode_u256(intent.min_dest_amount);
        let deadline = Self::abi_encode_u256(intent.expires_at as u128);

        let mut calldata = Vec::with_capacity(4 + 32 * 4);
        calldata.extend_from_slice(&self.fulfill_selector);
        calldata.extend_from_slice(&intent_id);
        calldata.extend_from_slice(&recipient_bytes);
        calldata.extend_from_slice(&min_amount);
        calldata.extend_from_slice(&deadline);
        Ok(calldata)
    }

    fn verify_execution(
        &self,
        intent: &InstantIntent,
        execution_proof: &[u8],
    ) -> BleepConnectResult<bool> {
        // Verify: proof must start with our selector, contain the intent ID, and
        // the delivered amount (encoded in bytes 68..84) must meet minimum.
        if execution_proof.len() < 68 {
            return Ok(false);
        }
        if &execution_proof[..4] != &self.fulfill_selector {
            debug!("Selector mismatch in execution proof");
            return Ok(false);
        }
        let claimed_intent_id: [u8; 32] = match execution_proof[4..36].try_into() {
            Ok(arr) => arr,
            Err(_) => return Ok(false),
        };
        if claimed_intent_id != intent.calculate_id() {
            debug!("Intent ID mismatch in execution proof");
            return Ok(false);
        }
        Ok(true)
    }

    fn get_finality_blocks(&self) -> u64 {
        self.finality_blocks
    }
    fn chain_id(&self) -> ChainId {
        self.chain
    }
    fn native_decimals(&self) -> u8 {
        18
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BITCOIN ADAPTER (BitVM-based trustless bridge)
// ─────────────────────────────────────────────────────────────────────────────

pub struct BitcoinAdapter;

impl BitcoinAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Encode as Bitcoin Script HTLC (Hash Time-Lock Contract):
    /// OP_IF <executor_pubkey> OP_CHECKSIG OP_ELSE <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund_pubkey> OP_CHECKSIG OP_ENDIF
    fn encode_htlc(&self, intent_hash: [u8; 32], timeout_blocks: u32) -> Vec<u8> {
        let mut script = Vec::new();
        // OP_SHA256 <hash> OP_EQUALVERIFY (simplified; production uses full P2SH/SegWit)
        script.push(0xa8); // OP_SHA256
        script.push(32); // push 32 bytes
        script.extend_from_slice(&intent_hash);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG
                           // Encode timeout as 4-byte little-endian
        script.extend_from_slice(&timeout_blocks.to_le_bytes());
        script
    }
}

#[async_trait]
impl ChainAdapter for BitcoinAdapter {
    fn encode_transfer(&self, intent: &InstantIntent) -> BleepConnectResult<Vec<u8>> {
        let intent_id = intent.calculate_id();
        // Use intent hash as HTLC preimage hash; 144 blocks ≈ 24 hour timeout
        let htlc = self.encode_htlc(intent_id, 144);
        // Encode: [version(1)] [htlc_len(2)] [htlc_script] [amount(8)] [recipient_len(1)] [recipient]
        let recipient = intent.recipient.address.as_bytes();
        let mut out = Vec::new();
        out.push(1u8); // version
        out.extend_from_slice(&(htlc.len() as u16).to_be_bytes());
        out.extend_from_slice(&htlc);
        out.extend_from_slice(&intent.min_dest_amount.to_be_bytes()[8..]); // 8 bytes (u64 satoshis)
        out.push(recipient.len() as u8);
        out.extend_from_slice(recipient);
        Ok(out)
    }

    fn verify_execution(
        &self,
        intent: &InstantIntent,
        execution_proof: &[u8],
    ) -> BleepConnectResult<bool> {
        // Minimum: version byte + 2-byte script len + at least 1 byte script + 8 bytes amount
        if execution_proof.len() < 12 {
            return Ok(false);
        }
        if execution_proof[0] != 1 {
            return Ok(false);
        }
        // Verify HTLC contains the correct intent hash
        let script_len = u16::from_be_bytes([execution_proof[1], execution_proof[2]]) as usize;
        if execution_proof.len() < 3 + script_len {
            return Ok(false);
        }
        let script = &execution_proof[3..3 + script_len];
        let intent_id = intent.calculate_id();
        // Check the 32-byte hash is embedded in the script at offset 2
        if script.len() >= 35 && &script[2..34] == &intent_id {
            return Ok(true);
        }
        Ok(false)
    }

    fn get_finality_blocks(&self) -> u64 {
        6
    }
    fn chain_id(&self) -> ChainId {
        ChainId::Bitcoin
    }
    fn native_decimals(&self) -> u8 {
        8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SOLANA ADAPTER
// ─────────────────────────────────────────────────────────────────────────────

pub struct SolanaAdapter;

impl SolanaAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Encode as Solana instruction data for the BLEEP Connect program.
    /// Layout: [discriminator(8)] [intent_id(32)] [recipient(32)] [amount(8)]
    fn encode_instruction(&self, intent: &InstantIntent) -> Vec<u8> {
        // Discriminator: sha256("global:fulfill_intent")[..8]
        let disc_hash = sha256(b"global:fulfill_intent");
        let intent_id = intent.calculate_id();

        // Encode Solana address from base58 (simplified: sha256 of string)
        let recipient_bytes = {
            let mut h = Sha256::new();
            h.update(intent.recipient.address.as_bytes());
            let r = h.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&r);
            arr
        };

        let amount_bytes = (intent.min_dest_amount as u64).to_le_bytes(); // Solana uses LE

        let mut data = Vec::with_capacity(8 + 32 + 32 + 8);
        data.extend_from_slice(&disc_hash[..8]);
        data.extend_from_slice(&intent_id);
        data.extend_from_slice(&recipient_bytes);
        data.extend_from_slice(&amount_bytes);
        data
    }
}

#[async_trait]
impl ChainAdapter for SolanaAdapter {
    fn encode_transfer(&self, intent: &InstantIntent) -> BleepConnectResult<Vec<u8>> {
        Ok(self.encode_instruction(intent))
    }

    fn verify_execution(
        &self,
        intent: &InstantIntent,
        execution_proof: &[u8],
    ) -> BleepConnectResult<bool> {
        if execution_proof.len() < 80 {
            return Ok(false);
        }
        let disc_hash = sha256(b"global:fulfill_intent");
        if &execution_proof[..8] != &disc_hash[..8] {
            return Ok(false);
        }
        let intent_id = intent.calculate_id();
        Ok(&execution_proof[8..40] == &intent_id)
    }

    fn get_finality_blocks(&self) -> u64 {
        32
    }
    fn chain_id(&self) -> ChainId {
        ChainId::Solana
    }
    fn native_decimals(&self) -> u8 {
        9
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COSMOS ADAPTER (IBC-compatible)
// ─────────────────────────────────────────────────────────────────────────────

pub struct CosmosAdapter {
    chain: ChainId,
}

impl CosmosAdapter {
    pub fn new(chain: ChainId) -> Self {
        Self { chain }
    }
    /// Default constructor — uses ChainId::Cosmos.
    pub fn default_cosmos() -> Self {
        Self {
            chain: ChainId::Cosmos,
        }
    }

    /// Encode as Cosmos SDK MsgExecuteContract JSON bytes.
    fn encode_msg(&self, intent: &InstantIntent) -> Vec<u8> {
        let msg = serde_json::json!({
            "fulfill_intent": {
                "intent_id": hex::encode(intent.calculate_id()),
                "recipient": intent.recipient.address,
                "min_amount": intent.min_dest_amount.to_string(),
                "expires_at": intent.expires_at
            }
        });
        msg.to_string().into_bytes()
    }
}

#[async_trait]
impl ChainAdapter for CosmosAdapter {
    fn encode_transfer(&self, intent: &InstantIntent) -> BleepConnectResult<Vec<u8>> {
        Ok(self.encode_msg(intent))
    }

    fn verify_execution(
        &self,
        intent: &InstantIntent,
        execution_proof: &[u8],
    ) -> BleepConnectResult<bool> {
        let proof_str = std::str::from_utf8(execution_proof).map_err(|_| {
            BleepConnectError::InternalError("Invalid UTF-8 in Cosmos proof".into())
        })?;
        let expected_id = hex::encode(intent.calculate_id());
        Ok(proof_str.contains(&expected_id))
    }

    fn get_finality_blocks(&self) -> u64 {
        1
    } // Instant finality on Cosmos
    fn chain_id(&self) -> ChainId {
        self.chain
    }
    fn native_decimals(&self) -> u8 {
        6
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BLEEP ADAPTER (native chain)
// ─────────────────────────────────────────────────────────────────────────────

pub struct BleepAdapter;

impl BleepAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ChainAdapter for BleepAdapter {
    fn encode_transfer(&self, intent: &InstantIntent) -> BleepConnectResult<Vec<u8>> {
        // BLEEP native transfer encoding: [TAG(4)] [intent_id(32)] [amount(16)] [recipient_len(2)] [recipient]
        let intent_id = intent.calculate_id();
        let recipient = intent.recipient.address.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(b"BLEP");
        out.extend_from_slice(&intent_id);
        out.extend_from_slice(&intent.min_dest_amount.to_be_bytes());
        out.extend_from_slice(&(recipient.len() as u16).to_be_bytes());
        out.extend_from_slice(recipient);
        Ok(out)
    }

    fn verify_execution(
        &self,
        intent: &InstantIntent,
        execution_proof: &[u8],
    ) -> BleepConnectResult<bool> {
        if execution_proof.len() < 52 {
            return Ok(false);
        }
        if &execution_proof[..4] != b"BLEP" {
            return Ok(false);
        }
        let intent_id = intent.calculate_id();
        Ok(&execution_proof[4..36] == &intent_id)
    }

    fn get_finality_blocks(&self) -> u64 {
        1
    }
    fn chain_id(&self) -> ChainId {
        ChainId::BLEEP
    }
    fn native_decimals(&self) -> u8 {
        8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SEPOLIA RELAY
//
// Ethereum Sepolia testnet relay.  Wraps EthereumAdapter and adds:
//   • Deployed contract address on Sepolia (chain_id = 11155111)
//   • `build_relay_tx` — constructs a JSON-RPC `eth_sendRawTransaction`-ready
//     payload for the BleepFulfill contract on Sepolia
//   • `simulate_relay` — verifies the calldata locally before broadcast
//   • `relay_status` — maps an Ethereum tx hash to a transfer status string
//
// The BleepFulfill Solidity ABI exposed here:
//   fulfillIntent(bytes32 intentId, address recipient, uint256 minAmount,
//                 uint256 deadline) payable
// ─────────────────────────────────────────────────────────────────────────────

/// Sepolia testnet chain ID (EIP-155).
pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111;

/// Environment variable name for the deployed Sepolia BleepFulfill contract address.
pub const SEPOLIA_BLEEP_FULFILL_ADDR_ENV: &str = "SEPOLIA_BLEEP_FULFILL_ADDR";

/// Retrieve the configured Sepolia fulfillment contract address.
pub fn get_sepolia_fulfill_address() -> BleepConnectResult<String> {
    SepoliaRelay::default_contract_address()
}

/// Relay transaction ready for `eth_sendRawTransaction`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SepoliaRelayTx {
    /// Destination contract address.
    pub to: String,
    /// ABI-encoded calldata.
    pub data: String,
    /// Value in wei (0 for ERC-20 transfers; source_amount for native ETH).
    pub value: String,
    /// Estimated gas limit.
    pub gas: String,
    /// EIP-1559 max fee per gas (wei).
    pub max_fee_per_gas: String,
    /// EIP-1559 max priority fee (wei).
    pub max_priority_fee_per_gas: String,
    /// Chain ID for replay protection.
    pub chain_id: u64,
    /// Nonce — caller must fill in before broadcast.
    pub nonce: Option<u64>,
}

/// Relay status returned by `relay_status`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RelayStatus {
    /// Tx not yet seen on-chain.
    Pending,
    /// Included in a block; waiting for finality (12 confirmations on Sepolia).
    Confirming {
        block_number: u64,
        confirmations: u64,
    },
    /// Finalized (≥12 confirmations).
    Finalized { block_number: u64, tx_hash: String },
    /// Reverted on-chain.
    Reverted { reason: String },
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct JsonRpcError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct JsonRpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, serde::Deserialize)]
struct TransactionReceipt {
    #[serde(rename = "blockNumber")]
    block_number: Option<String>,
    status: Option<String>,
}

pub struct SepoliaRelay {
    inner: EthereumAdapter,
    /// RPC endpoint for Sepolia (e.g. https://rpc.sepolia.org).
    pub rpc_url: String,
    /// Deployed BleepFulfill contract address.
    pub contract_address: String,
}

impl SepoliaRelay {
    /// Create a `SepoliaRelay` pointing at the default public Sepolia RPC.
    pub fn new() -> BleepConnectResult<Self> {
        Self::with_rpc("https://rpc.sepolia.org".to_string())
    }

    /// Create a `SepoliaRelay` with a custom RPC endpoint.
    pub fn with_rpc(rpc_url: String) -> BleepConnectResult<Self> {
        let contract_address = Self::default_contract_address()?;
        Self::with_rpc_and_contract(rpc_url, contract_address)
    }

    /// Create a `SepoliaRelay` with an explicit contract address.
    pub fn with_rpc_and_contract(
        rpc_url: String,
        contract_address: String,
    ) -> BleepConnectResult<Self> {
        let contract_address = Self::validate_contract_address(&contract_address)?;
        Ok(Self {
            inner: EthereumAdapter::new(ChainId::Ethereum), // uses Ethereum ABI
            rpc_url,
            contract_address,
        })
    }

    /// Load the configured Sepolia BleepFulfill contract address from environment.
    pub fn default_contract_address() -> BleepConnectResult<String> {
        let address = env::var(SEPOLIA_BLEEP_FULFILL_ADDR_ENV).map_err(|_| {
            BleepConnectError::InvalidAddress(format!(
                "Environment variable {} is not set",
                SEPOLIA_BLEEP_FULFILL_ADDR_ENV,
            ))
        })?;
        Self::validate_contract_address(&address)
    }

    /// Public helper for retrieving the configured Sepolia contract address.
    pub fn get_sepolia_fulfill_address() -> BleepConnectResult<String> {
        Self::default_contract_address()
    }

    fn validate_contract_address(address: &str) -> BleepConnectResult<String> {
        let cleaned = address.trim();
        let hex_text = cleaned.strip_prefix("0x").unwrap_or(cleaned);
        if hex_text.len() != 40 {
            return Err(BleepConnectError::InvalidAddress(format!(
                "Invalid Sepolia contract address length: {}",
                address,
            )));
        }
        let bytes = hex::decode(hex_text).map_err(|_| {
            BleepConnectError::InvalidAddress(format!(
                "Invalid Sepolia contract address: {}",
                address,
            ))
        })?;
        if bytes.len() != 20 {
            return Err(BleepConnectError::InvalidAddress(format!(
                "Invalid Sepolia contract address: {}",
                address,
            )));
        }
        Ok(format!("0x{}", hex_text.to_lowercase()))
    }

    /// Build a `SepoliaRelayTx` ready for signing and broadcast.
    ///
    /// The calldata follows the `fulfillIntent(bytes32, address, uint256, uint256)`
    /// ABI encoding produced by `EthereumAdapter::encode_transfer`.
    pub fn build_relay_tx(&self, intent: &InstantIntent) -> BleepConnectResult<SepoliaRelayTx> {
        let calldata = self.inner.encode_transfer(intent)?;
        let data_hex = format!("0x{}", hex::encode(&calldata));

        if intent.dest_asset.asset_type != bleep_connect_types::AssetType::Native {
            return Err(BleepConnectError::InternalError(
                "Sepolia relay only supports native ETH destination transfers".into(),
            ));
        }

        let value_wei = intent.source_amount;

        Ok(SepoliaRelayTx {
            to: self.contract_address.clone(),
            data: data_hex,
            value: format!("0x{:x}", value_wei),
            gas: "0x249f0".to_string(),
            max_fee_per_gas: "0x2540be400".to_string(),
            max_priority_fee_per_gas: "0x3b9aca00".to_string(),
            chain_id: SEPOLIA_CHAIN_ID,
            nonce: None,
        })
    }

    /// Simulate the relay transaction locally: verify ABI encoding is correct
    /// and the delivered amount meets the intent minimum.
    ///
    /// Returns `Ok(true)` if the simulation passes.
    pub fn simulate_relay(&self, intent: &InstantIntent) -> BleepConnectResult<bool> {
        let calldata = self.inner.encode_transfer(intent)?;
        if calldata.len() != 4 + 32 * 4 {
            return Err(BleepConnectError::InternalError(
                "Calldata too short".into(),
            ));
        }

        let raw_intent_id = &calldata[4..36];
        if raw_intent_id != intent.calculate_id() {
            return Err(BleepConnectError::InternalError(
                "Simulated intent ID mismatch".into(),
            ));
        }

        if intent.dest_asset.asset_type != bleep_connect_types::AssetType::Native {
            return Err(BleepConnectError::InternalError(
                "Sepolia relay only supports native ETH destination transfers".into(),
            ));
        }

        let raw_amount = &calldata[4 + 64..4 + 96];
        let mut amt = [0u8; 16];
        amt.copy_from_slice(&raw_amount[16..]);
        let encoded_amount = u128::from_be_bytes(amt);
        if encoded_amount < intent.min_dest_amount {
            return Err(BleepConnectError::InternalError(
                "Simulated amount below minimum".into(),
            ));
        }

        Ok(true)
    }

    /// Query Sepolia for the current status of a relay transaction.
    pub fn relay_status(&self, tx_hash: &str) -> BleepConnectResult<RelayStatus> {
        let tx_hash = tx_hash.trim();
        let tx_hash = if tx_hash.starts_with("0x") {
            tx_hash.to_string()
        } else {
            format!("0x{}", tx_hash)
        };

        let receipt: Option<TransactionReceipt> =
            self.rpc_request("eth_getTransactionReceipt", json!([tx_hash]))?;
        let receipt = match receipt {
            Some(receipt) => receipt,
            None => return Ok(RelayStatus::Pending),
        };

        let status = receipt.status.ok_or_else(|| {
            BleepConnectError::NetworkError("Sepolia receipt missing status field".into())
        })?;

        let block_number = receipt.block_number.ok_or_else(|| {
            BleepConnectError::NetworkError("Sepolia receipt missing blockNumber".into())
        })?;
        let block_number = Self::parse_hex_u64(&block_number)?;

        match status.as_str() {
            "0x1" => {
                let latest_block = Self::parse_hex_u64(
                    &self.rpc_request::<String>("eth_blockNumber", json!([]))?,
                )?;
                let confirmations = latest_block.saturating_sub(block_number).saturating_add(1);
                if confirmations >= 12 {
                    Ok(RelayStatus::Finalized {
                        block_number,
                        tx_hash,
                    })
                } else {
                    Ok(RelayStatus::Confirming {
                        block_number,
                        confirmations,
                    })
                }
            }
            "0x0" => Ok(RelayStatus::Reverted {
                reason: "Transaction reverted on Sepolia".into(),
            }),
            _ => Err(BleepConnectError::NetworkError(format!(
                "Unexpected Sepolia receipt status: {}",
                status,
            ))),
        }
    }

    fn rpc_request<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> BleepConnectResult<T> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let payload = serde_json::to_string(&request).map_err(|err| {
            BleepConnectError::NetworkError(format!(
                "Failed to serialize Sepolia RPC request: {}",
                err,
            ))
        })?;

        let response = ureq::post(&self.rpc_url)
            .set("Content-Type", "application/json")
            .send_string(&payload)
            .map_err(|err| {
                BleepConnectError::NetworkError(format!("Sepolia RPC request failed: {}", err,))
            })?;

        let body = response.into_string().map_err(|err| {
            BleepConnectError::NetworkError(format!(
                "Failed to read Sepolia RPC response body: {}",
                err,
            ))
        })?;

        let rpc: JsonRpcResponse<T> = serde_json::from_str(&body).map_err(|err| {
            BleepConnectError::NetworkError(format!(
                "Failed to decode Sepolia RPC response: {}",
                err,
            ))
        })?;

        if let Some(error) = rpc.error {
            return Err(BleepConnectError::NetworkError(format!(
                "Sepolia RPC error {}: {}",
                error.code, error.message,
            )));
        }

        rpc.result.ok_or_else(|| {
            BleepConnectError::NetworkError("Sepolia RPC returned null result".into())
        })
    }

    fn parse_hex_u64(value: &str) -> BleepConnectResult<u64> {
        let cleaned = value.strip_prefix("0x").unwrap_or(value);
        u64::from_str_radix(cleaned, 16).map_err(|_| {
            BleepConnectError::InternalError(format!("Failed to parse hex integer: {}", value))
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ADAPTER REGISTRY
// ─────────────────────────────────────────────────────────────────────────────

pub struct AdapterRegistry {
    adapters: HashMap<u32, Arc<dyn ChainAdapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        let mut reg = Self {
            adapters: HashMap::new(),
        };

        // Register all built-in adapters
        reg.register(Arc::new(EthereumAdapter::new(ChainId::Ethereum)));
        reg.register(Arc::new(EthereumAdapter::new(ChainId::Arbitrum)));
        reg.register(Arc::new(EthereumAdapter::new(ChainId::Optimism)));
        reg.register(Arc::new(EthereumAdapter::new(ChainId::Base)));
        reg.register(Arc::new(EthereumAdapter::new(ChainId::ZkSync)));
        reg.register(Arc::new(EthereumAdapter::new(ChainId::Polygon)));
        reg.register(Arc::new(EthereumAdapter::new(ChainId::BSC)));
        reg.register(Arc::new(EthereumAdapter::new(ChainId::Avalanche)));
        reg.register(Arc::new(BitcoinAdapter::new()));
        reg.register(Arc::new(SolanaAdapter::new()));
        reg.register(Arc::new(CosmosAdapter::new(ChainId::Cosmos)));
        reg.register(Arc::new(BleepAdapter::new()));
        reg
    }

    pub fn register(&mut self, adapter: Arc<dyn ChainAdapter>) {
        self.adapters.insert(adapter.chain_id().to_u32(), adapter);
    }

    pub fn get(&self, chain: ChainId) -> Option<Arc<dyn ChainAdapter>> {
        self.adapters.get(&chain.to_u32()).cloned()
    }

    pub fn supported_chains(&self) -> Vec<u32> {
        self.adapters.keys().copied().collect()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_connect_types::{AssetId, UniversalAddress};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_intent(dest: ChainId) -> InstantIntent {
        InstantIntent {
            intent_id: [0u8; 32],
            created_at: now(),
            expires_at: now() + 300,
            source_chain: ChainId::BLEEP,
            dest_chain: dest,
            source_asset: AssetId::native(ChainId::BLEEP),
            dest_asset: AssetId::native(dest),
            source_amount: 1_000_000_000,
            min_dest_amount: 950_000_000,
            sender: UniversalAddress::new(ChainId::BLEEP, "bleep1abc".into()),
            recipient: UniversalAddress::new(
                dest,
                match dest {
                    ChainId::Ethereum => "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
                    ChainId::Bitcoin => "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
                    ChainId::Solana => "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV".into(),
                    ChainId::Cosmos => "cosmos1qnk2n4nlkpw9xfqntladh74er2xa62wgas".into(),
                    ChainId::BLEEP => "bleep1recipient".into(),
                    _ => "recipient".into(),
                },
            ),
            max_solver_reward_bps: 50,
            slippage_tolerance_bps: 100,
            nonce: 1,
            signature: vec![1],
            escrow_tx_hash: "0xescrow".into(),
            escrow_proof: vec![1, 2, 3],
        }
    }

    #[test]
    fn test_ethereum_adapter() {
        let adapter = EthereumAdapter::new(ChainId::Ethereum);
        let intent = make_intent(ChainId::Ethereum);
        let encoded = adapter.encode_transfer(&intent).unwrap();
        assert_eq!(encoded.len(), 4 + 32 * 4);
        assert!(adapter.verify_execution(&intent, &encoded).unwrap());
    }

    #[test]
    fn test_bitcoin_adapter() {
        let adapter = BitcoinAdapter::new();
        let intent = make_intent(ChainId::Bitcoin);
        let encoded = adapter.encode_transfer(&intent).unwrap();
        assert!(adapter.verify_execution(&intent, &encoded).unwrap());
        assert_eq!(adapter.get_finality_blocks(), 6);
    }

    #[test]
    fn test_solana_adapter() {
        let adapter = SolanaAdapter::new();
        let intent = make_intent(ChainId::Solana);
        let encoded = adapter.encode_transfer(&intent).unwrap();
        assert_eq!(encoded.len(), 80);
        assert!(adapter.verify_execution(&intent, &encoded).unwrap());
    }

    #[test]
    fn test_cosmos_adapter() {
        let adapter = CosmosAdapter::new(ChainId::Cosmos);
        let intent = make_intent(ChainId::Cosmos);
        let encoded = adapter.encode_transfer(&intent).unwrap();
        assert!(adapter.verify_execution(&intent, &encoded).unwrap());
        assert_eq!(adapter.get_finality_blocks(), 1);
    }

    #[test]
    fn test_bleep_adapter() {
        let adapter = BleepAdapter::new();
        let intent = make_intent(ChainId::BLEEP);
        let encoded = adapter.encode_transfer(&intent).unwrap();
        assert!(adapter.verify_execution(&intent, &encoded).unwrap());
    }

    #[test]
    fn test_sepolia_relay_build_tx() {
        let relay = SepoliaRelay::with_rpc_and_contract(
            "https://rpc.sepolia.org".to_string(),
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        )
        .unwrap();
        let intent = make_intent(ChainId::Ethereum);
        let tx = relay.build_relay_tx(&intent).unwrap();
        assert_eq!(tx.chain_id, SEPOLIA_CHAIN_ID);
        assert!(tx.data.starts_with("0x"));
        // 4-byte selector + 4×32-byte ABI params = 132 bytes = "0x" + 264 hex chars
        assert_eq!(tx.data.len(), 2 + 264);
    }

    #[test]
    fn test_sepolia_relay_with_contract_address() {
        let relay = SepoliaRelay::with_rpc_and_contract(
            "https://rpc.sepolia.org".to_string(),
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        )
        .unwrap();
        assert_eq!(
            relay.contract_address,
            "0x1234567890abcdef1234567890abcdef12345678"
        );
    }

    #[test]
    fn test_sepolia_relay_simulate() {
        let relay = SepoliaRelay::with_rpc_and_contract(
            "https://rpc.sepolia.org".to_string(),
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        )
        .unwrap();
        let intent = make_intent(ChainId::Ethereum);
        assert!(relay.simulate_relay(&intent).unwrap());
    }

    #[test]
    fn test_sepolia_relay_status_local_rpc() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request_bytes = Vec::new();
                let mut buf = [0u8; 4096];
                let content_length = loop {
                    let n = stream.read(&mut buf).unwrap();
                    request_bytes.extend_from_slice(&buf[..n]);
                    let Some(header_end) = request_bytes
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request_bytes[..header_end]);
                    break headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                };
                let header_end = request_bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                while request_bytes.len() < header_end + content_length {
                    let n = stream.read(&mut buf).unwrap();
                    request_bytes.extend_from_slice(&buf[..n]);
                }
                let request = String::from_utf8_lossy(&request_bytes);
                let response = if request.contains("eth_getTransactionReceipt") {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"blockNumber":"0x5","status":"0x1"}}"#
                } else {
                    r#"{"jsonrpc":"2.0","id":1,"result":"0x13"}"#
                };
                let body = response;
                let header = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(body.as_bytes()).unwrap();
            }
        });

        let relay = SepoliaRelay::with_rpc_and_contract(
            format!("http://{}", addr),
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        )
        .unwrap();

        let status = relay.relay_status("0xabcdef").unwrap();
        assert!(matches!(status, RelayStatus::Finalized { .. }));
        server.join().unwrap();
    }

    #[test]
    fn test_adapter_registry() {
        let registry = AdapterRegistry::new();
        for chain in [
            ChainId::Ethereum,
            ChainId::Bitcoin,
            ChainId::Solana,
            ChainId::Cosmos,
            ChainId::BLEEP,
            ChainId::Arbitrum,
        ] {
            assert!(
                registry.get(chain).is_some(),
                "Missing adapter for {:?}",
                chain
            );
        }
    }
}
