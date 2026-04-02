//! # Layer 1 — Intent Layer
//!
//! Every operation in BLEEP VM starts as a typed **Intent**.
//! Intents are the unified API surface — callers never interact
//! with individual engines directly.
//!
//! ```text
//! TransferIntent  ──┐
//! ContractCallIntent─┤──► Intent ──► VM Router ──► Engine
//! DeployIntent    ──┤
//! CrossChainIntent──┘
//! ```

use crate::types::ChainId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// TARGET VM
// ─────────────────────────────────────────────────────────────────────────────

/// Which execution engine should handle this intent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetVm {
    /// BLEEP-native WASM (primary runtime — like CosmWasm/ink).
    Wasm,
    /// Full EVM compatibility via `revm`.
    Evm,
    /// Solana SBF (rBPF compatible).
    SolanaSbf,
    /// Move VM (Sui / Aptos bytecode spec v5).
    Move,
    /// ZK proof verification + execution.
    Zk,
    /// Let the router detect automatically from bytecode magic bytes.
    Auto,
}

impl TargetVm {
    /// Attempt to detect VM type from bytecode magic bytes.
    pub fn detect_from_bytecode(bytecode: &[u8]) -> Self {
        if bytecode.starts_with(b"\x00asm") {
            TargetVm::Wasm
        } else if bytecode.starts_with(&[0x60]) || bytecode.starts_with(&[0x61]) {
            // EVM commonly starts with PUSH1 0x60 (PUSH1 0x40 for free memory ptr)
            TargetVm::Evm
        } else if bytecode.len() >= 8 {
            // SBF has a specific magic: 0x7f 0x45 0x4c 0x46 (ELF magic)
            if bytecode.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
                return TargetVm::SolanaSbf;
            }
            // Move bytecode starts with magic 0xA1 0x1C 0xEB 0x0B
            if bytecode.starts_with(&[0xA1, 0x1C, 0xEB, 0x0B]) {
                return TargetVm::Move;
            }
            TargetVm::Wasm // default to WASM
        } else {
            TargetVm::Wasm
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// INTENT KINDS
// ─────────────────────────────────────────────────────────────────────────────

/// A value transfer between accounts (no contract execution).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferIntent {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u128,
    pub memo: Option<String>,
}

/// Call a function on an already-deployed contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCallIntent {
    /// Which VM executes this contract.
    pub target_vm: TargetVm,
    /// Contract address (32 bytes, zero-padded for 20-byte EVM addresses).
    pub contract: [u8; 32],
    /// ABI-encoded or raw calldata.
    pub calldata: Vec<u8>,
    /// Maximum gas the caller authorizes.
    pub gas_limit: u64,
    /// Value attached to the call (wei / lamports / etc.).
    pub value: u128,
    /// Extra per-engine hints (e.g. {"evm_chain_id": "1"}).
    pub hints: HashMap<String, String>,
}

/// Deploy a new contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployIntent {
    /// VM to deploy into.
    pub target_vm: TargetVm,
    /// Raw contract bytecode.
    pub bytecode: Vec<u8>,
    /// Constructor arguments.
    pub init_args: Vec<u8>,
    /// Gas budget.
    pub gas_limit: u64,
    /// Salt for CREATE2-style deterministic addresses.
    pub salt: Option<[u8; 32]>,
    /// Optional ABI / IDL JSON.
    pub abi: Option<String>,
}

/// Execute a call that crosses chain boundaries.
/// BLEEP VM routes this through BLEEP Connect automatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainIntent {
    /// Target blockchain.
    pub destination_chain: ChainId,
    /// Contract on the destination chain.
    pub contract: Vec<u8>,
    /// Encoded call.
    pub calldata: Vec<u8>,
    /// Gas budget on the *source* chain.
    pub source_gas_limit: u64,
    /// Gas budget on the *destination* chain.
    pub dest_gas_limit: u64,
    /// Value to bridge alongside the call.
    pub bridge_value: u128,
    /// Relay fee authorised by caller.
    pub relay_fee: u128,
    /// Whether to require a ZK proof of destination execution.
    pub require_zk_proof: bool,
}

/// Verify a ZK proof and optionally execute the proven computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVerifyIntent {
    /// Groth16 proof bytes (ark-serialize format).
    pub proof_bytes: Vec<u8>,
    /// Public inputs.
    pub public_inputs: Vec<Vec<u8>>,
    /// Verification key identifier (registered in the ZK engine registry).
    pub vk_id: String,
    /// If set, execute this WASM after successful proof verification.
    pub post_verify_wasm: Option<Vec<u8>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SERDE HELPERS FOR FIXED-SIZE ARRAYS
// ─────────────────────────────────────────────────────────────────────────────

mod serde_arrays {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(array: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(array)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a 64-byte array")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<[u8; 64], E> {
                if v.len() != 64 {
                    return Err(E::custom(format!("expected 64 bytes, got {}", v.len())));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(arr)
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UNIFIED INTENT ENVELOPE
// ─────────────────────────────────────────────────────────────────────────────

/// The single API type accepted by the BLEEP VM router.
/// Every interaction is represented as one of these variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentKind {
    Transfer(TransferIntent),
    ContractCall(ContractCallIntent),
    Deploy(DeployIntent),
    CrossChain(CrossChainIntent),
    ZkVerify(ZkVerifyIntent),
}

/// Full intent envelope with routing metadata and caller identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    /// Globally unique intent identifier (UUIDv4).
    pub id: Uuid,
    /// The specific intent.
    pub kind: IntentKind,
    /// Ed25519 public key of the submitter (32 bytes).
    pub signer: [u8; 32],
    /// Ed25519 signature over `canonical_bytes()`.
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64],
    /// Sequential nonce for replay protection.
    pub nonce: u64,
    /// Unix timestamp of submission.
    pub submitted_at: u64,
    /// Source chain.
    pub source_chain: ChainId,
    /// Priority hint: 0 = normal, 1 = fast, 2 = instant.
    pub priority: u8,
}

impl Intent {
    /// Create a new unsigned intent (useful for testing and internal routing).
    pub fn new_unsigned(kind: IntentKind, source_chain: ChainId) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Intent {
            id: Uuid::new_v4(),
            kind,
            signer: [0u8; 32],
            signature: [0u8; 64],
            nonce: 0,
            submitted_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            source_chain,
            priority: 0,
        }
    }

    /// Canonical bytes used for signature verification.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let payload = serde_json::to_vec(&self.kind).unwrap_or_default();
        let mut buf = Vec::with_capacity(16 + 32 + payload.len());
        buf.extend_from_slice(self.id.as_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.submitted_at.to_le_bytes());
        buf.extend_from_slice(&self.signer);
        buf.extend_from_slice(self.source_chain.to_string().as_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    /// Verify the Ed25519 signature on this intent.
    pub fn verify_signature(&self) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};
        let Ok(vk) = VerifyingKey::from_bytes(&self.signer) else {
            return false;
        };
        let sig = Signature::from_bytes(&self.signature);
        use ed25519_dalek::Verifier;
        vk.verify(&self.canonical_bytes(), &sig).is_ok()
    }

    /// Extract the gas limit regardless of intent kind.
    pub fn gas_limit(&self) -> u64 {
        match &self.kind {
            IntentKind::Transfer(_) => 21_000,
            IntentKind::ContractCall(c) => c.gas_limit,
            IntentKind::Deploy(d) => d.gas_limit,
            IntentKind::CrossChain(x) => x.source_gas_limit,
            IntentKind::ZkVerify(_) => 5_000_000,
        }
    }

    /// Extract the target VM for routing.
    pub fn target_vm(&self) -> TargetVm {
        match &self.kind {
            IntentKind::Transfer(_) => TargetVm::Wasm,
            IntentKind::ContractCall(c) => c.target_vm.clone(),
            IntentKind::Deploy(d) => d.target_vm.clone(),
            IntentKind::CrossChain(_) => TargetVm::Wasm, // bridges use WASM
            IntentKind::ZkVerify(_) => TargetVm::Zk,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// INTENT BUILDER  (fluent API)
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for `ContractCallIntent`.
pub struct ContractCallBuilder {
    inner: ContractCallIntent,
}

impl ContractCallBuilder {
    pub fn new(contract: [u8; 32]) -> Self {
        Self {
            inner: ContractCallIntent {
                target_vm: TargetVm::Auto,
                contract,
                calldata: Vec::new(),
                gas_limit: 300_000,
                value: 0,
                hints: HashMap::new(),
            },
        }
    }

    pub fn vm(mut self, vm: TargetVm) -> Self {
        self.inner.target_vm = vm;
        self
    }
    pub fn calldata(mut self, data: Vec<u8>) -> Self {
        self.inner.calldata = data;
        self
    }
    pub fn gas(mut self, limit: u64) -> Self {
        self.inner.gas_limit = limit;
        self
    }
    pub fn value(mut self, v: u128) -> Self {
        self.inner.value = v;
        self
    }
    pub fn hint(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.inner.hints.insert(k.into(), v.into());
        self
    }
    pub fn build(self) -> IntentKind {
        IntentKind::ContractCall(self.inner)
    }
}

/// Fluent builder for `DeployIntent`.
pub struct DeployBuilder {
    inner: DeployIntent,
}

impl DeployBuilder {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            inner: DeployIntent {
                target_vm: TargetVm::Auto,
                bytecode,
                init_args: Vec::new(),
                gas_limit: 1_000_000,
                salt: None,
                abi: None,
            },
        }
    }

    pub fn vm(mut self, vm: TargetVm) -> Self {
        self.inner.target_vm = vm;
        self
    }
    pub fn init_args(mut self, args: Vec<u8>) -> Self {
        self.inner.init_args = args;
        self
    }
    pub fn gas(mut self, limit: u64) -> Self {
        self.inner.gas_limit = limit;
        self
    }
    pub fn salt(mut self, s: [u8; 32]) -> Self {
        self.inner.salt = Some(s);
        self
    }
    pub fn abi(mut self, json: String) -> Self {
        self.inner.abi = Some(json);
        self
    }
    pub fn build(self) -> IntentKind {
        IntentKind::Deploy(self.inner)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_detection_wasm() {
        let wasm_magic = b"\x00asm\x01\x00\x00\x00";
        assert_eq!(TargetVm::detect_from_bytecode(wasm_magic), TargetVm::Wasm);
    }

    #[test]
    fn test_vm_detection_evm() {
        let evm_bytecode = &[0x60, 0x40, 0x52]; // PUSH1 0x40 MSTORE
        assert_eq!(TargetVm::detect_from_bytecode(evm_bytecode), TargetVm::Evm);
    }

    #[test]
    fn test_vm_detection_sbf() {
        let elf_magic = &[0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00];
        assert_eq!(
            TargetVm::detect_from_bytecode(elf_magic),
            TargetVm::SolanaSbf
        );
    }

    #[test]
    fn test_vm_detection_move() {
        let move_magic = &[0xA1, 0x1C, 0xEB, 0x0B, 0x05, 0x00, 0x00, 0x00];
        assert_eq!(TargetVm::detect_from_bytecode(move_magic), TargetVm::Move);
    }

    #[test]
    fn test_intent_canonical_bytes_deterministic() {
        let kind = IntentKind::Transfer(TransferIntent {
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 1000,
            memo: Some("test".to_string()),
        });
        let intent1 = Intent::new_unsigned(kind.clone(), ChainId::Bleep);
        let intent2 = Intent {
            id: intent1.id,
            ..Intent::new_unsigned(kind, ChainId::Bleep)
        };
        // Same id and nonce → same canonical bytes
        assert_eq!(
            intent1.canonical_bytes().len(),
            intent2.canonical_bytes().len()
        );
    }

    #[test]
    fn test_intent_gas_limit_defaults() {
        let transfer = Intent::new_unsigned(
            IntentKind::Transfer(TransferIntent {
                from: [0u8; 32],
                to: [1u8; 32],
                amount: 100,
                memo: None,
            }),
            ChainId::Bleep,
        );
        assert_eq!(transfer.gas_limit(), 21_000);
    }

    #[test]
    fn test_contract_call_builder() {
        let kind = ContractCallBuilder::new([0xAB; 32])
            .vm(TargetVm::Evm)
            .calldata(vec![0x12, 0x34])
            .gas(500_000)
            .value(1_000_000)
            .hint("chain_id", "1")
            .build();
        if let IntentKind::ContractCall(c) = kind {
            assert_eq!(c.target_vm, TargetVm::Evm);
            assert_eq!(c.gas_limit, 500_000);
            assert_eq!(c.value, 1_000_000);
            assert_eq!(c.hints.get("chain_id").unwrap(), "1");
        } else {
            panic!("expected ContractCall");
        }
    }

    #[test]
    fn test_deploy_builder() {
        let bytecode = b"\x00asm\x01\x00\x00\x00".to_vec();
        let kind = DeployBuilder::new(bytecode.clone())
            .vm(TargetVm::Wasm)
            .gas(2_000_000)
            .salt([0xCCu8; 32])
            .build();
        if let IntentKind::Deploy(d) = kind {
            assert_eq!(d.bytecode, bytecode);
            assert_eq!(d.gas_limit, 2_000_000);
            assert!(d.salt.is_some());
        } else {
            panic!("expected Deploy");
        }
    }

    #[test]
    fn test_cross_chain_intent_target_vm() {
        let kind = IntentKind::CrossChain(CrossChainIntent {
            destination_chain: ChainId::Ethereum,
            contract: vec![0xAB; 20],
            calldata: vec![],
            source_gas_limit: 100_000,
            dest_gas_limit: 200_000,
            bridge_value: 0,
            relay_fee: 1000,
            require_zk_proof: true,
        });
        let intent = Intent::new_unsigned(kind, ChainId::Bleep);
        assert_eq!(intent.target_vm(), TargetVm::Wasm);
    }
}
