//! Cross-chain ABI bridge for bleep-vm.
//!
//! Every major blockchain uses a different encoding for contract calls:
//!
//! | Chain         | Encoding             | Entry point convention            |
//! |---------------|----------------------|-----------------------------------|
//! | Ethereum/EVM  | ABI (4-byte selector + Solidity ABI) | `call(bytes)` → `bytes` |
//! | Solana        | Borsh                | discriminator[8] + Borsh args     |
//! | Cosmos        | Protobuf / JSON      | `MsgExecuteContract` JSON         |
//! | Polkadot      | SCALE                | ink! message selector[4] + SCALE  |
//! | Sui / Aptos   | BCS                  | module::function + BCS args       |
//! | Near          | JSON                 | function name + JSON args         |
//!
//! This module provides:
//!   - `ChainAbi` trait: `encode_call` / `decode_return`
//!   - Concrete implementations for each chain
//!   - `AbiRouter`: dispatches to the right implementation by `ChainId`
//!   - Normalised `CallEnvelope` / `ReturnEnvelope` that the WASM runtime reads

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::error::{VmError, VmResult};
use crate::types::ChainId;

// ─────────────────────────────────────────────────────────────────────────────
// NORMALISED ENVELOPES
// ─────────────────────────────────────────────────────────────────────────────

/// The normalised call that bleep-vm's WASM entry point receives.
/// Written into linear memory at offset 0 before execution begins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEnvelope {
    /// 4-byte function selector (chain-native — 0-padded for chains that don't use it).
    pub selector: [u8; 4],
    /// ABI-encoded arguments in the chain's native format.
    pub args: Vec<u8>,
    /// Caller address bytes (variable length; 20 for EVM, 32 for Solana/Cosmos, etc.)
    pub caller: Vec<u8>,
    /// Value transferred (in chain's base units).
    pub value: u128,
    /// Gas stipend passed to this call.
    pub gas: u64,
    /// Chain that originated this call.
    pub chain_id: ChainId,
}

impl CallEnvelope {
    /// Serialise into a flat byte buffer suitable for writing into WASM memory.
    /// Layout: [selector(4)] [chain_id_len(4 LE)] [chain_id_bytes]
    ///         [caller_len(4 LE)] [caller_bytes]
    ///         [value(16 LE)] [gas(8 LE)]
    ///         [args_len(4 LE)] [args_bytes]
    pub fn to_memory_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.args.len() + self.caller.len());
        buf.extend_from_slice(&self.selector);
        let chain_str = self.chain_id.to_string();
        let chain_bytes = chain_str.as_bytes();
        buf.extend_from_slice(&(chain_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(chain_bytes);
        buf.extend_from_slice(&(self.caller.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.caller);
        buf.extend_from_slice(&self.value.to_le_bytes());
        buf.extend_from_slice(&self.gas.to_le_bytes());
        buf.extend_from_slice(&(self.args.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.args);
        buf
    }

    pub fn encoded_len(&self) -> usize {
        4 + 4
            + self.chain_id.to_string().len()
            + 4
            + self.caller.len()
            + 16
            + 8
            + 4
            + self.args.len()
    }
}

/// The normalised return value from a contract execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnEnvelope {
    /// 0 = success, non-zero = revert code.
    pub status: i32,
    /// ABI-encoded return data in the chain's native format.
    pub data: Vec<u8>,
    /// Revert reason string (if status != 0).
    pub reason: Option<String>,
}

impl ReturnEnvelope {
    pub fn success(data: Vec<u8>) -> Self {
        ReturnEnvelope {
            status: 0,
            data,
            reason: None,
        }
    }

    pub fn revert(code: i32, reason: impl Into<String>) -> Self {
        ReturnEnvelope {
            status: code,
            data: vec![],
            reason: Some(reason.into()),
        }
    }

    pub fn is_success(&self) -> bool {
        self.status == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CHAIN ABI TRAIT
// ─────────────────────────────────────────────────────────────────────────────

pub trait ChainAbi: Send + Sync {
    /// Translate a raw on-chain call into a normalised `CallEnvelope`.
    fn decode_call(&self, raw: &[u8]) -> VmResult<CallEnvelope>;

    /// Translate WASM return bytes back into the chain's native return encoding.
    fn encode_return(&self, envelope: &ReturnEnvelope) -> VmResult<Vec<u8>>;

    /// The chain this implementation handles.
    fn chain_id(&self) -> ChainId;
}

// ─────────────────────────────────────────────────────────────────────────────
// EVM ABI  (Ethereum, Arbitrum, Optimism, Base, Polygon, BSC…)
// ─────────────────────────────────────────────────────────────────────────────

/// EVM calldata layout:
///   bytes[0..4]  — Keccak-256(function signature)[0..4]
///   bytes[4..]   — ABI-encoded arguments (32-byte aligned slots)
pub struct EvmAbi {
    chain: ChainId,
}

impl EvmAbi {
    pub fn ethereum() -> Self {
        EvmAbi {
            chain: ChainId::Ethereum,
        }
    }
    pub fn l2(name: impl Into<String>) -> Self {
        EvmAbi {
            chain: ChainId::EthereumL2(name.into()),
        }
    }

    /// Compute a 4-byte EVM function selector from a human-readable signature,
    /// e.g. `"transfer(address,uint256)"`.
    pub fn selector(sig: &str) -> [u8; 4] {
        let hash = Keccak256::digest(sig.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// Decode a raw ABI `uint256` slot (32 bytes big-endian) as u128.
    pub fn decode_uint256_as_u128(slot: &[u8]) -> VmResult<u128> {
        if slot.len() < 32 {
            return Err(VmError::AbiDecodeFailed {
                chain: "ethereum".into(),
                reason: "slot too short for uint256".into(),
            });
        }
        // Take the low 16 bytes (u128 range)
        let lo: [u8; 16] = slot[16..32].try_into().unwrap();
        Ok(u128::from_be_bytes(lo))
    }

    /// Decode a 20-byte Ethereum address from a 32-byte ABI slot.
    pub fn decode_address(slot: &[u8]) -> VmResult<[u8; 20]> {
        if slot.len() < 32 {
            return Err(VmError::AbiDecodeFailed {
                chain: "ethereum".into(),
                reason: "slot too short for address".into(),
            });
        }
        // Address is right-aligned: bytes[12..32]
        slot[12..32]
            .try_into()
            .map_err(|_| VmError::AbiDecodeFailed {
                chain: "ethereum".into(),
                reason: "address slice error".into(),
            })
    }

    /// Encode a `bool` as a 32-byte ABI slot.
    pub fn encode_bool(v: bool) -> [u8; 32] {
        let mut slot = [0u8; 32];
        slot[31] = if v { 1 } else { 0 };
        slot
    }

    /// Encode a `uint256` (as u128) as a 32-byte ABI slot.
    pub fn encode_uint256(v: u128) -> [u8; 32] {
        let mut slot = [0u8; 32];
        slot[16..32].copy_from_slice(&v.to_be_bytes());
        slot
    }

    /// Encode `bytes` as an ABI dynamic type (offset + length + data, 32-byte padded).
    pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // For a single dynamic arg at position 0: offset = 32
        out.extend_from_slice(&Self::encode_uint256(32));
        out.extend_from_slice(&Self::encode_uint256(data.len() as u128));
        out.extend_from_slice(data);
        // Pad to 32-byte boundary
        let pad = (32 - (data.len() % 32)) % 32;
        out.extend(std::iter::repeat(0u8).take(pad));
        out
    }
}

impl ChainAbi for EvmAbi {
    fn chain_id(&self) -> ChainId {
        self.chain.clone()
    }

    fn decode_call(&self, raw: &[u8]) -> VmResult<CallEnvelope> {
        if raw.len() < 4 {
            return Err(VmError::AbiDecodeFailed {
                chain: self.chain.to_string(),
                reason: format!("calldata too short: {} bytes", raw.len()),
            });
        }
        let selector: [u8; 4] = raw[..4].try_into().unwrap();
        let args = raw[4..].to_vec();
        Ok(CallEnvelope {
            selector,
            args,
            caller: vec![0u8; 20], // filled by VM from tx context
            value: 0,
            gas: 0,
            chain_id: self.chain.clone(),
        })
    }

    fn encode_return(&self, envelope: &ReturnEnvelope) -> VmResult<Vec<u8>> {
        if envelope.is_success() {
            Ok(envelope.data.clone())
        } else {
            // Encode as Solidity `Error(string)` revert
            let reason = envelope.reason.clone().unwrap_or_default();
            let mut out = Vec::new();
            // selector: keccak256("Error(string)")[0..4]
            out.extend_from_slice(&[0x08, 0xc3, 0x79, 0xa0]);
            out.extend_from_slice(&EvmAbi::encode_bytes(reason.as_bytes()));
            Ok(out)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SOLANA BORSH ABI
// ─────────────────────────────────────────────────────────────────────────────

/// Solana calldata layout:
///   bytes[0..8]  — 8-byte discriminator (anchor: SHA256("global:<fn_name>")[..8])
///   bytes[8..]   — Borsh-serialised arguments
pub struct SolanaAbi;

impl SolanaAbi {
    /// Compute anchor discriminator for a given instruction name.
    pub fn discriminator(name: &str) -> [u8; 8] {
        use sha2::{Digest, Sha256};
        let preimage = format!("global:{name}");
        let hash = Sha256::digest(preimage.as_bytes());
        [
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]
    }

    /// Read a little-endian u64 from `data[offset..]`.
    pub fn read_u64_le(data: &[u8], offset: usize) -> VmResult<u64> {
        if data.len() < offset + 8 {
            return Err(VmError::AbiDecodeFailed {
                chain: "solana".into(),
                reason: format!(
                    "need 8 bytes at offset {offset}, got {}",
                    data.len().saturating_sub(offset)
                ),
            });
        }
        Ok(u64::from_le_bytes(
            data[offset..offset + 8].try_into().unwrap(),
        ))
    }
}

impl ChainAbi for SolanaAbi {
    fn chain_id(&self) -> ChainId {
        ChainId::Solana
    }

    fn decode_call(&self, raw: &[u8]) -> VmResult<CallEnvelope> {
        if raw.len() < 8 {
            return Err(VmError::AbiDecodeFailed {
                chain: "solana".into(),
                reason: format!("instruction too short: {} bytes", raw.len()),
            });
        }
        let disc: [u8; 8] = raw[..8].try_into().unwrap();
        // Map 8-byte discriminator into a 4-byte selector for normalisation
        let selector: [u8; 4] = [disc[0], disc[1], disc[2], disc[3]];
        let args = raw[8..].to_vec();
        Ok(CallEnvelope {
            selector,
            args,
            caller: vec![0u8; 32],
            value: 0,
            gas: 0,
            chain_id: ChainId::Solana,
        })
    }

    fn encode_return(&self, envelope: &ReturnEnvelope) -> VmResult<Vec<u8>> {
        if envelope.is_success() {
            // Borsh success: status byte(0) + data
            let mut out = vec![0u8];
            out.extend_from_slice(&envelope.data);
            Ok(out)
        } else {
            // Borsh error: status byte(1) + little-endian error code + message
            let reason = envelope.reason.clone().unwrap_or_default();
            let mut out = vec![1u8];
            out.extend_from_slice(&(envelope.status as u32).to_le_bytes());
            let reason_bytes = reason.as_bytes();
            out.extend_from_slice(&(reason_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(reason_bytes);
            Ok(out)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COSMOS / COSMWASM JSON ABI
// ─────────────────────────────────────────────────────────────────────────────

pub struct CosmosAbi;

impl ChainAbi for CosmosAbi {
    fn chain_id(&self) -> ChainId {
        ChainId::CosmosHub
    }

    fn decode_call(&self, raw: &[u8]) -> VmResult<CallEnvelope> {
        // CosmWasm: JSON `{"method_name": {...args}}`
        let json: serde_json::Value =
            serde_json::from_slice(raw).map_err(|e| VmError::AbiDecodeFailed {
                chain: "cosmos".into(),
                reason: e.to_string(),
            })?;
        let obj = json.as_object().ok_or_else(|| VmError::AbiDecodeFailed {
            chain: "cosmos".into(),
            reason: "expected JSON object".into(),
        })?;
        // Extract first key as method name → selector
        let method = obj.keys().next().cloned().unwrap_or_default();
        let selector = {
            let h = Keccak256::digest(method.as_bytes());
            [h[0], h[1], h[2], h[3]]
        };
        let args = raw.to_vec(); // pass full JSON as args
        Ok(CallEnvelope {
            selector,
            args,
            caller: vec![],
            value: 0,
            gas: 0,
            chain_id: ChainId::CosmosHub,
        })
    }

    fn encode_return(&self, envelope: &ReturnEnvelope) -> VmResult<Vec<u8>> {
        let resp = if envelope.is_success() {
            serde_json::json!({ "ok": hex::encode(&envelope.data) })
        } else {
            serde_json::json!({ "error": envelope.reason })
        };
        serde_json::to_vec(&resp).map_err(|e| VmError::Serialization(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POLKADOT / SUBSTRATE SCALE ABI
// ─────────────────────────────────────────────────────────────────────────────

/// ink! calldata: [selector(4)] [SCALE-encoded args]
pub struct SubstrateAbi;

impl SubstrateAbi {
    /// Compute ink! message selector: first 4 bytes of Blake2b-256(fn_name).
    pub fn selector(fn_name: &str) -> [u8; 4] {
        use blake2::{Blake2b512, Digest};
        let hash = Blake2b512::digest(fn_name.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// Decode a SCALE compact integer from `data[offset..]`.
    /// Returns (value, bytes_consumed).
    pub fn decode_compact_u64(data: &[u8], offset: usize) -> VmResult<(u64, usize)> {
        if data.is_empty() || offset >= data.len() {
            return Err(VmError::AbiDecodeFailed {
                chain: "polkadot".into(),
                reason: "empty data for compact decode".into(),
            });
        }
        let first = data[offset];
        match first & 0b11 {
            0b00 => Ok(((first >> 2) as u64, 1)),
            0b01 => {
                if offset + 1 >= data.len() {
                    return Err(VmError::AbiDecodeFailed {
                        chain: "polkadot".into(),
                        reason: "compact u64: need 2 bytes".into(),
                    });
                }
                let v = u16::from_le_bytes([first, data[offset + 1]]) >> 2;
                Ok((v as u64, 2))
            }
            0b10 => {
                if offset + 3 >= data.len() {
                    return Err(VmError::AbiDecodeFailed {
                        chain: "polkadot".into(),
                        reason: "compact u64: need 4 bytes".into(),
                    });
                }
                let v = u32::from_le_bytes([
                    first,
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) >> 2;
                Ok((v as u64, 4))
            }
            _ => Err(VmError::AbiDecodeFailed {
                chain: "polkadot".into(),
                reason: "big-integer SCALE mode not supported".into(),
            }),
        }
    }
}

impl ChainAbi for SubstrateAbi {
    fn chain_id(&self) -> ChainId {
        ChainId::Polkadot
    }

    fn decode_call(&self, raw: &[u8]) -> VmResult<CallEnvelope> {
        if raw.len() < 4 {
            return Err(VmError::AbiDecodeFailed {
                chain: "polkadot".into(),
                reason: format!("ink! calldata too short: {} bytes", raw.len()),
            });
        }
        let selector: [u8; 4] = raw[..4].try_into().unwrap();
        let args = raw[4..].to_vec();
        Ok(CallEnvelope {
            selector,
            args,
            caller: vec![0u8; 32],
            value: 0,
            gas: 0,
            chain_id: ChainId::Polkadot,
        })
    }

    fn encode_return(&self, envelope: &ReturnEnvelope) -> VmResult<Vec<u8>> {
        // SCALE Result<T, E>: 0x00 = Ok, 0x01 = Err
        let mut out = Vec::new();
        if envelope.is_success() {
            out.push(0x00);
            out.extend_from_slice(&envelope.data);
        } else {
            out.push(0x01);
            let reason = envelope.reason.clone().unwrap_or_default();
            let bytes = reason.as_bytes();
            // SCALE compact length prefix
            if bytes.len() < 64 {
                out.push((bytes.len() as u8) << 2);
            } else {
                out.extend_from_slice(&((bytes.len() as u32) << 2 | 0b10).to_le_bytes());
            }
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NEAR JSON ABI
// ─────────────────────────────────────────────────────────────────────────────

pub struct NearAbi;

impl ChainAbi for NearAbi {
    fn chain_id(&self) -> ChainId {
        ChainId::Near
    }

    fn decode_call(&self, raw: &[u8]) -> VmResult<CallEnvelope> {
        // Near: `{"function": "name", "args": <JSON>}`
        let json: serde_json::Value =
            serde_json::from_slice(raw).map_err(|e| VmError::AbiDecodeFailed {
                chain: "near".into(),
                reason: e.to_string(),
            })?;
        let fn_name = json["function"].as_str().unwrap_or("").to_string();
        let selector = {
            let h = Keccak256::digest(fn_name.as_bytes());
            [h[0], h[1], h[2], h[3]]
        };
        let args =
            serde_json::to_vec(&json["args"]).map_err(|e| VmError::Serialization(e.to_string()))?;
        Ok(CallEnvelope {
            selector,
            args,
            caller: vec![],
            value: 0,
            gas: 0,
            chain_id: ChainId::Near,
        })
    }

    fn encode_return(&self, envelope: &ReturnEnvelope) -> VmResult<Vec<u8>> {
        let resp = if envelope.is_success() {
            serde_json::json!({ "result": hex::encode(&envelope.data) })
        } else {
            serde_json::json!({ "error": envelope.reason })
        };
        serde_json::to_vec(&resp).map_err(|e| VmError::Serialization(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SUI / APTOS BCS ABI
// ─────────────────────────────────────────────────────────────────────────────

/// Move/BCS calldata: [module_len(u8)] [module] [fn_len(u8)] [fn_name] [args_len(u32 LE)] [args]
pub struct MoveAbi {
    chain: ChainId,
}

impl MoveAbi {
    pub fn sui() -> Self {
        MoveAbi {
            chain: ChainId::Sui,
        }
    }
    pub fn aptos() -> Self {
        MoveAbi {
            chain: ChainId::Aptos,
        }
    }
}

impl ChainAbi for MoveAbi {
    fn chain_id(&self) -> ChainId {
        self.chain.clone()
    }

    fn decode_call(&self, raw: &[u8]) -> VmResult<CallEnvelope> {
        if raw.is_empty() {
            return Err(VmError::AbiDecodeFailed {
                chain: self.chain.to_string(),
                reason: "empty calldata".into(),
            });
        }
        let mut cursor = 0usize;

        // module name
        let mod_len = raw[cursor] as usize;
        cursor += 1;
        if cursor + mod_len > raw.len() {
            return Err(VmError::AbiDecodeFailed {
                chain: self.chain.to_string(),
                reason: "module name overflows calldata".into(),
            });
        }
        let module = std::str::from_utf8(&raw[cursor..cursor + mod_len]).map_err(|e| {
            VmError::AbiDecodeFailed {
                chain: self.chain.to_string(),
                reason: e.to_string(),
            }
        })?;
        cursor += mod_len;

        // function name
        if cursor >= raw.len() {
            return Err(VmError::AbiDecodeFailed {
                chain: self.chain.to_string(),
                reason: "missing function name length".into(),
            });
        }
        let fn_len = raw[cursor] as usize;
        cursor += 1;
        if cursor + fn_len > raw.len() {
            return Err(VmError::AbiDecodeFailed {
                chain: self.chain.to_string(),
                reason: "function name overflows calldata".into(),
            });
        }
        let function = std::str::from_utf8(&raw[cursor..cursor + fn_len]).map_err(|e| {
            VmError::AbiDecodeFailed {
                chain: self.chain.to_string(),
                reason: e.to_string(),
            }
        })?;
        cursor += fn_len;

        // selector = keccak4("module::function")
        let sig = format!("{module}::{function}");
        let h = Keccak256::digest(sig.as_bytes());
        let selector: [u8; 4] = [h[0], h[1], h[2], h[3]];

        // remaining = BCS args
        let args = raw[cursor..].to_vec();

        Ok(CallEnvelope {
            selector,
            args,
            caller: vec![0u8; 32],
            value: 0,
            gas: 0,
            chain_id: self.chain.clone(),
        })
    }

    fn encode_return(&self, envelope: &ReturnEnvelope) -> VmResult<Vec<u8>> {
        // BCS result: success_flag(1) + data
        let mut out = Vec::new();
        out.push(if envelope.is_success() { 0u8 } else { 1u8 });
        out.extend_from_slice(&envelope.data);
        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ABI ROUTER
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatches ABI encode/decode operations to the correct chain implementation.
pub struct AbiRouter {
    handlers: HashMap<String, Box<dyn ChainAbi>>,
}

impl AbiRouter {
    /// Construct a router pre-loaded with all supported chains.
    pub fn new() -> Self {
        let mut handlers: HashMap<String, Box<dyn ChainAbi>> = HashMap::new();
        let insert = |m: &mut HashMap<String, Box<dyn ChainAbi>>, abi: Box<dyn ChainAbi>| {
            m.insert(abi.chain_id().to_string(), abi);
        };
        insert(&mut handlers, Box::new(EvmAbi::ethereum()));
        insert(&mut handlers, Box::new(EvmAbi::l2("arbitrum")));
        insert(&mut handlers, Box::new(EvmAbi::l2("optimism")));
        insert(&mut handlers, Box::new(EvmAbi::l2("base")));
        insert(&mut handlers, Box::new(EvmAbi::l2("polygon")));
        insert(&mut handlers, Box::new(SolanaAbi));
        insert(&mut handlers, Box::new(CosmosAbi));
        insert(&mut handlers, Box::new(SubstrateAbi));
        insert(&mut handlers, Box::new(NearAbi));
        insert(&mut handlers, Box::new(MoveAbi::sui()));
        insert(&mut handlers, Box::new(MoveAbi::aptos()));
        AbiRouter { handlers }
    }

    pub fn decode_call(&self, chain: &ChainId, raw: &[u8]) -> VmResult<CallEnvelope> {
        let key = chain.to_string();
        self.handlers
            .get(&key)
            .ok_or_else(|| VmError::UnsupportedChain(chain.to_string()))?
            .decode_call(raw)
    }

    pub fn encode_return(&self, chain: &ChainId, ret: &ReturnEnvelope) -> VmResult<Vec<u8>> {
        let key = chain.to_string();
        self.handlers
            .get(&key)
            .ok_or_else(|| VmError::UnsupportedChain(chain.to_string()))?
            .encode_return(ret)
    }

    pub fn supported_chains(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.handlers.keys().cloned().collect();
        keys.sort();
        keys
    }
}

impl Default for AbiRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EVM ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_evm_selector() {
        let sel = EvmAbi::selector("transfer(address,uint256)");
        assert_eq!(sel, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_evm_decode_call() {
        let abi = EvmAbi::ethereum();
        let raw = [0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x01, 0x02, 0x03];
        let env = abi.decode_call(&raw).unwrap();
        assert_eq!(env.selector, [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(env.args, [0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_evm_decode_call_too_short() {
        let abi = EvmAbi::ethereum();
        assert!(abi.decode_call(&[0x00, 0x01, 0x02]).is_err());
    }

    #[test]
    fn test_evm_encode_return_success() {
        let abi = EvmAbi::ethereum();
        let ret = ReturnEnvelope::success(vec![0x01]);
        let encoded = abi.encode_return(&ret).unwrap();
        assert_eq!(encoded, vec![0x01]);
    }

    #[test]
    fn test_evm_encode_return_revert() {
        let abi = EvmAbi::ethereum();
        let ret = ReturnEnvelope::revert(1, "insufficient balance");
        let encoded = abi.encode_return(&ret).unwrap();
        // starts with Error(string) selector
        assert_eq!(&encoded[..4], &[0x08, 0xc3, 0x79, 0xa0]);
    }

    #[test]
    fn test_evm_uint256_encode_decode() {
        let slot = EvmAbi::encode_uint256(12345u128);
        let val = EvmAbi::decode_uint256_as_u128(&slot).unwrap();
        assert_eq!(val, 12345u128);
    }

    #[test]
    fn test_evm_encode_bytes() {
        let data = b"hello";
        let encoded = EvmAbi::encode_bytes(data);
        // offset(32) + length(32) + padded_data(32)
        assert_eq!(encoded.len(), 96);
    }

    // ── Solana ────────────────────────────────────────────────────────────────

    #[test]
    fn test_solana_discriminator_length() {
        let disc = SolanaAbi::discriminator("initialize");
        assert_eq!(disc.len(), 8);
    }

    #[test]
    fn test_solana_decode_call() {
        let abi = SolanaAbi;
        let mut raw = SolanaAbi::discriminator("transfer").to_vec();
        raw.extend_from_slice(&100u64.to_le_bytes());
        let env = abi.decode_call(&raw).unwrap();
        assert_eq!(env.args.len(), 8);
    }

    #[test]
    fn test_solana_encode_return_success() {
        let abi = SolanaAbi;
        let ret = ReturnEnvelope::success(vec![42]);
        let enc = abi.encode_return(&ret).unwrap();
        assert_eq!(enc[0], 0u8);
        assert_eq!(enc[1], 42u8);
    }

    // ── Substrate ─────────────────────────────────────────────────────────────

    #[test]
    fn test_substrate_scale_compact_single_byte() {
        let data = [0x04u8]; // compact 1
        let (v, n) = SubstrateAbi::decode_compact_u64(&data, 0).unwrap();
        assert_eq!(v, 1);
        assert_eq!(n, 1);
    }

    #[test]
    fn test_substrate_scale_compact_two_byte() {
        // 69 encoded as 2-byte SCALE compact: 69 << 2 | 0b01
        let v: u16 = (69 << 2) | 0b01;
        let data = v.to_le_bytes();
        let (decoded, n) = SubstrateAbi::decode_compact_u64(&data, 0).unwrap();
        assert_eq!(decoded, 69);
        assert_eq!(n, 2);
    }

    #[test]
    fn test_substrate_decode_call() {
        let abi = SubstrateAbi;
        let mut raw = SubstrateAbi::selector("transfer").to_vec();
        raw.extend_from_slice(&[0x01, 0x02, 0x03]);
        let env = abi.decode_call(&raw).unwrap();
        assert_eq!(env.selector, SubstrateAbi::selector("transfer"));
    }

    // ── Move / BCS ────────────────────────────────────────────────────────────

    #[test]
    fn test_move_abi_decode_call() {
        let abi = MoveAbi::sui();
        let module = b"coin";
        let function = b"transfer";
        let args = b"\x01\x02\x03";
        let mut raw = vec![module.len() as u8];
        raw.extend_from_slice(module);
        raw.push(function.len() as u8);
        raw.extend_from_slice(function);
        raw.extend_from_slice(args);
        let env = abi.decode_call(&raw).unwrap();
        assert_eq!(env.args, args);
    }

    #[test]
    fn test_move_abi_short_calldata_rejected() {
        let abi = MoveAbi::aptos();
        assert!(abi.decode_call(&[]).is_err());
    }

    // ── ABI Router ────────────────────────────────────────────────────────────

    #[test]
    fn test_router_supports_all_chains() {
        let router = AbiRouter::new();
        let chains = router.supported_chains();
        assert!(chains.contains(&"ethereum".to_string()));
        assert!(chains.contains(&"solana".to_string()));
        assert!(chains.contains(&"cosmos".to_string()));
        assert!(chains.contains(&"polkadot".to_string()));
        assert!(chains.contains(&"near".to_string()));
        assert!(chains.contains(&"sui".to_string()));
        assert!(chains.contains(&"aptos".to_string()));
    }

    #[test]
    fn test_router_unsupported_chain_error() {
        let router = AbiRouter::new();
        let result = router.decode_call(&ChainId::Bitcoin, &[0u8; 4]);
        assert!(matches!(result, Err(VmError::UnsupportedChain(_))));
    }

    #[test]
    fn test_call_envelope_to_memory_bytes_roundtrip_len() {
        let env = CallEnvelope {
            selector: [0xAA, 0xBB, 0xCC, 0xDD],
            args: vec![1, 2, 3],
            caller: vec![0u8; 20],
            value: 1_000_000,
            gas: 21_000,
            chain_id: ChainId::Ethereum,
        };
        let bytes = env.to_memory_bytes();
        assert_eq!(bytes.len(), env.encoded_len());
    }

    #[test]
    fn test_return_envelope_success_flag() {
        let r = ReturnEnvelope::success(vec![0xFF]);
        assert!(r.is_success());
        let r2 = ReturnEnvelope::revert(-1, "bad");
        assert!(!r2.is_success());
    }
}
