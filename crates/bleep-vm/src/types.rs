//! Core types for bleep-vm — shared across all subsystems.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// CHAIN IDENTITY
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies the origin chain of a contract or transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    Bleep,
    Ethereum,
    EthereumL2(String), // Arbitrum, Optimism, Base …
    Bitcoin,
    Solana,
    CosmosHub,
    Polkadot,
    Near,
    Sui,
    Aptos,
    Custom(String),
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainId::Bleep => write!(f, "bleep"),
            ChainId::Ethereum => write!(f, "ethereum"),
            ChainId::EthereumL2(name) => write!(f, "evm-l2:{name}"),
            ChainId::Bitcoin => write!(f, "bitcoin"),
            ChainId::Solana => write!(f, "solana"),
            ChainId::CosmosHub => write!(f, "cosmos"),
            ChainId::Polkadot => write!(f, "polkadot"),
            ChainId::Near => write!(f, "near"),
            ChainId::Sui => write!(f, "sui"),
            ChainId::Aptos => write!(f, "aptos"),
            ChainId::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CONTRACT FORMATS
// ─────────────────────────────────────────────────────────────────────────────

/// The bytecode / IR format of a contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContractFormat {
    /// Raw WASM binary — universal target.
    Wasm,
    /// EVM bytecode — Ethereum and all EVM-compatible chains.
    Evm,
    /// Solana eBPF binary.
    SolanaBpf,
    /// Substrate WASM (ink! contracts).
    SubstrateWasm,
    /// Move bytecode (Sui / Aptos).
    Move,
    /// CosmWasm binary.
    CosmWasm,
}

// ─────────────────────────────────────────────────────────────────────────────
// CONTRACT METADATA
// ─────────────────────────────────────────────────────────────────────────────

/// Rich metadata attached to every contract submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMeta {
    /// Human-readable name (optional).
    pub name: Option<String>,
    /// Origin chain.
    pub chain_id: ChainId,
    /// Bytecode format.
    pub format: ContractFormat,
    /// SHA-256 (32 bytes) of the *unoptimised* contract bytes.
    pub source_hash: [u8; 32],
    /// ABI JSON (EVM) or IDL JSON (Solana), if provided.
    pub abi: Option<String>,
    /// UNIX timestamp of deployment.
    pub deployed_at: u64,
}

impl ContractMeta {
    pub fn new(bytecode: &[u8], chain_id: ChainId, format: ContractFormat) -> Self {
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(bytecode).into();
        ContractMeta {
            name: None,
            chain_id,
            format,
            source_hash: hash,
            abi: None,
            deployed_at: unix_now(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TRANSACTIONS
// ─────────────────────────────────────────────────────────────────────────────

/// A signed transaction submitted for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// Sequential nonce for replay protection.
    pub nonce: u64,
    /// Maximum gas the caller is willing to spend.
    pub gas_limit: u64,
    /// Wei-denominated gas price (or priority fee for EIP-1559 style).
    pub gas_price: u64,
    /// Contract bytecode *or* calldata for an already-deployed contract.
    pub payload: Vec<u8>,
    /// Ed25519 signature over canonical signing bytes.
    pub signature: Vec<u8>,
    /// Ed25519 public key (32 bytes).
    pub signer: Vec<u8>,
    /// Call arguments serialised by the caller (ABI / Borsh / BCS depending on format).
    pub calldata: Vec<u8>,
    /// Target chain (if cross-chain deployment).
    pub chain_id: ChainId,
}

impl SignedTransaction {
    /// Canonical bytes that must be signed.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.payload.len() + self.calldata.len());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.gas_limit.to_le_bytes());
        buf.extend_from_slice(&self.gas_price.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.calldata);
        buf.extend_from_slice(self.chain_id.to_string().as_bytes());
        buf
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────────────────────────────────────

/// A single state-storage write (key/value pair).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateWrite {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    /// Monotonically increasing counter so writes are hashed in order.
    pub write_index: u64,
}

/// Committed state snapshot: ordered set of writes + a Merkle-like root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub writes: Vec<StateWrite>,
    pub state_root: [u8; 32],
    pub block_num: u64,
}

impl StateSnapshot {
    /// Compute the state root from the ordered writes using SHA-256 chaining.
    pub fn compute_root(writes: &[StateWrite]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for w in writes {
            h.update(&w.write_index.to_le_bytes());
            h.update(&(w.key.len() as u64).to_le_bytes());
            h.update(&w.key);
            h.update(&(w.value.len() as u64).to_le_bytes());
            h.update(&w.value);
        }
        h.finalize().into()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTION RESULT
// ─────────────────────────────────────────────────────────────────────────────

/// Comprehensive result of a single contract execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// ABI-encoded return data.
    pub output: Vec<u8>,
    /// Actual gas consumed.
    pub gas_used: u64,
    /// State root after all writes committed.
    pub state_root: [u8; 32],
    /// Wall-clock execution time.
    pub execution_time: Duration,
    /// Peak memory in bytes.
    pub memory_peak: usize,
    /// ZK proof of correct execution (optional — generated when requested).
    pub zk_proof: Option<ZkExecutionProof>,
    /// Logs emitted by the contract.
    pub logs: Vec<ExecutionLog>,
    /// Chain-specific return code.
    pub return_code: i32,
    /// Optimisation report.
    pub opt_report: OptimisationReport,
}

impl ExecutionResult {
    pub fn success(&self) -> bool {
        self.return_code == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLog {
    pub level: LogLevel,
    pub message: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

// ─────────────────────────────────────────────────────────────────────────────
// ZK PROOF
// ─────────────────────────────────────────────────────────────────────────────

/// A Groth16 proof of execution correctness on BN254.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkExecutionProof {
    /// Serialised ark-groth16 proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Public inputs: [state_root_before, state_root_after, gas_used, tx_hash].
    pub public_inputs: Vec<Vec<u8>>,
    /// SHA-256 of the verification key used.
    pub vk_hash: [u8; 32],
}

// ─────────────────────────────────────────────────────────────────────────────
// OPTIMISATION
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptimisationLevel {
    /// No transformations; useful for debugging.
    None,
    /// Dead-code elimination and constant folding only.
    Basic,
    /// Full Cranelift mid-tier + inlining.
    Standard,
    /// Aggressive — includes cross-function inlining and profile-guided hints.
    Aggressive,
}

impl Default for OptimisationLevel {
    fn default() -> Self {
        OptimisationLevel::Standard
    }
}

/// Summary of all transformations applied.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptimisationReport {
    pub level: OptimisationLevel,
    /// Original bytecode size in bytes.
    pub original_size: usize,
    /// Optimised bytecode size in bytes.
    pub optimised_size: usize,
    /// Estimated gas saving (%).
    pub gas_saving_pct: f64,
    /// List of passes applied.
    pub passes_applied: Vec<String>,
    /// Dead instructions removed.
    pub dead_instr_removed: u32,
    /// Constants folded.
    pub constants_folded: u32,
}

impl OptimisationReport {
    pub fn size_reduction_pct(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        (1.0 - self.optimised_size as f64 / self.original_size as f64) * 100.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GAS SCHEDULE
// ─────────────────────────────────────────────────────────────────────────────

/// Per-opcode gas costs — compatible with EVM yellow-paper naming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasSchedule {
    pub costs: BTreeMap<WasmOpcode, u64>,
    /// Per-byte cost for memory page allocation.
    pub memory_per_page: u64,
    /// Per-byte cost for storage writes.
    pub storage_per_byte: u64,
    /// Cost of a cross-contract call.
    pub cross_call_base: u64,
    /// Cost of computing a SHA-256 hash (per 32 bytes).
    pub sha256_per_chunk: u64,
    /// Cost for emitting a log entry.
    pub log_base: u64,
}

impl Default for GasSchedule {
    fn default() -> Self {
        let mut costs = BTreeMap::new();
        // WASM numeric operations
        costs.insert(WasmOpcode::I32Const, 1);
        costs.insert(WasmOpcode::I64Const, 1);
        costs.insert(WasmOpcode::I32Add, 3);
        costs.insert(WasmOpcode::I64Add, 3);
        costs.insert(WasmOpcode::I32Sub, 3);
        costs.insert(WasmOpcode::I64Sub, 3);
        costs.insert(WasmOpcode::I32Mul, 5);
        costs.insert(WasmOpcode::I64Mul, 5);
        costs.insert(WasmOpcode::I32DivU, 10);
        costs.insert(WasmOpcode::I64DivU, 10);
        costs.insert(WasmOpcode::I32DivS, 10);
        costs.insert(WasmOpcode::I64DivS, 10);
        costs.insert(WasmOpcode::I32RemU, 10);
        costs.insert(WasmOpcode::I32RemS, 10);
        costs.insert(WasmOpcode::F32Add, 5);
        costs.insert(WasmOpcode::F64Add, 5);
        costs.insert(WasmOpcode::F32Mul, 8);
        costs.insert(WasmOpcode::F64Mul, 8);
        // Memory
        costs.insert(WasmOpcode::I32Load, 3);
        costs.insert(WasmOpcode::I64Load, 3);
        costs.insert(WasmOpcode::I32Store, 5);
        costs.insert(WasmOpcode::I64Store, 5);
        costs.insert(WasmOpcode::MemoryGrow, 200);
        costs.insert(WasmOpcode::MemorySize, 2);
        // Control flow
        costs.insert(WasmOpcode::Call, 20);
        costs.insert(WasmOpcode::CallIndirect, 25);
        costs.insert(WasmOpcode::If, 2);
        costs.insert(WasmOpcode::BrIf, 3);
        costs.insert(WasmOpcode::Return, 2);
        // Bulk memory
        costs.insert(WasmOpcode::MemoryCopy, 10);
        costs.insert(WasmOpcode::MemoryFill, 8);

        GasSchedule {
            costs,
            memory_per_page: 6400, // 64k page
            storage_per_byte: 50,
            cross_call_base: 2000,
            sha256_per_chunk: 100,
            log_base: 50,
        }
    }
}

/// WASM opcodes we track individually for gas purposes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WasmOpcode {
    I32Const,
    I64Const,
    F32Const,
    F64Const,
    I32Add,
    I64Add,
    I32Sub,
    I64Sub,
    I32Mul,
    I64Mul,
    I32DivU,
    I64DivU,
    I32DivS,
    I64DivS,
    I32RemU,
    I32RemS,
    F32Add,
    F64Add,
    F32Mul,
    F64Mul,
    I32Load,
    I64Load,
    F32Load,
    F64Load,
    I32Store,
    I64Store,
    F32Store,
    F64Store,
    MemoryGrow,
    MemorySize,
    MemoryCopy,
    MemoryFill,
    Call,
    CallIndirect,
    If,
    Block,
    Loop,
    Br,
    BrIf,
    BrTable,
    Return,
    Unreachable,
    Nop,
    LocalGet,
    LocalSet,
    LocalTee,
    GlobalGet,
    GlobalSet,
    Select,
    Other(u8),
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER
// ─────────────────────────────────────────────────────────────────────────────

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
