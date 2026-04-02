//! # BLEEP Connect Types
//!
//! Core type definitions for the BLEEP Connect Protocol
//!
//! This module defines all fundamental types used across the BLEEP Connect system,
//! including transfers, intents, proofs, and layer-specific types.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════
//  CHAIN IDENTIFIERS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    Ethereum,
    Bitcoin,
    Solana,
    Polygon,
    Arbitrum,
    Optimism,
    Base,
    Avalanche,
    BSC,
    Cosmos,
    Near,
    Polkadot,
    ZkSync,
    StarkNet,
    Filecoin,
    Celestia,
    Sui,
    Aptos,
    BLEEP,
    Custom(u32),
}

impl ChainId {
    pub fn canonical_name(&self) -> &str {
        match self {
            ChainId::Ethereum => "ethereum",
            ChainId::Bitcoin => "bitcoin",
            ChainId::Solana => "solana",
            ChainId::Polygon => "polygon",
            ChainId::Arbitrum => "arbitrum",
            ChainId::Optimism => "optimism",
            ChainId::Base => "base",
            ChainId::Avalanche => "avalanche",
            ChainId::BSC => "bsc",
            ChainId::Cosmos => "cosmos",
            ChainId::Near => "near",
            ChainId::Polkadot => "polkadot",
            ChainId::ZkSync => "zksync",
            ChainId::StarkNet => "starknet",
            ChainId::Filecoin => "filecoin",
            ChainId::Celestia => "celestia",
            ChainId::Sui => "sui",
            ChainId::Aptos => "aptos",
            ChainId::BLEEP => "bleep",
            ChainId::Custom(id) => return Box::leak(format!("custom-{}", id).into_boxed_str()),
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "ethereum" => Some(ChainId::Ethereum),
            "bitcoin" => Some(ChainId::Bitcoin),
            "solana" => Some(ChainId::Solana),
            "polygon" => Some(ChainId::Polygon),
            "arbitrum" => Some(ChainId::Arbitrum),
            "optimism" => Some(ChainId::Optimism),
            "base" => Some(ChainId::Base),
            "avalanche" => Some(ChainId::Avalanche),
            "bsc" => Some(ChainId::BSC),
            "cosmos" => Some(ChainId::Cosmos),
            "near" => Some(ChainId::Near),
            "polkadot" => Some(ChainId::Polkadot),
            "zksync" => Some(ChainId::ZkSync),
            "starknet" => Some(ChainId::StarkNet),
            "filecoin" => Some(ChainId::Filecoin),
            "celestia" => Some(ChainId::Celestia),
            "sui" => Some(ChainId::Sui),
            "aptos" => Some(ChainId::Aptos),
            "bleep" => Some(ChainId::BLEEP),
            _ => None,
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            ChainId::Ethereum => 1,
            ChainId::Bitcoin => 2,
            ChainId::Solana => 3,
            ChainId::Polygon => 4,
            ChainId::Arbitrum => 5,
            ChainId::Optimism => 6,
            ChainId::Base => 7,
            ChainId::Avalanche => 8,
            ChainId::BSC => 9,
            ChainId::Cosmos => 10,
            ChainId::Near => 11,
            ChainId::Polkadot => 12,
            ChainId::ZkSync => 13,
            ChainId::StarkNet => 14,
            ChainId::Filecoin => 15,
            ChainId::Celestia => 16,
            ChainId::Sui => 17,
            ChainId::Aptos => 18,
            ChainId::BLEEP => 999,
            ChainId::Custom(id) => *id,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  UNIVERSAL ADDRESS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UniversalAddress {
    pub chain: ChainId,
    pub address: String,
}

impl UniversalAddress {
    pub fn new(chain: ChainId, address: String) -> Self {
        Self { chain, address }
    }

    pub fn ethereum(address: &str) -> Self {
        Self::new(ChainId::Ethereum, address.to_string())
    }

    pub fn bitcoin(address: &str) -> Self {
        Self::new(ChainId::Bitcoin, address.to_string())
    }

    pub fn solana(address: &str) -> Self {
        Self::new(ChainId::Solana, address.to_string())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.chain.to_u32().to_be_bytes());
        bytes.extend_from_slice(self.address.as_bytes());
        bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.to_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

impl fmt::Display for UniversalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.chain.canonical_name(), self.address)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  ASSET IDENTIFIER
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId {
    pub chain: ChainId,
    pub contract_address: Option<String>,
    pub token_id: Option<String>,
    pub asset_type: AssetType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetType {
    Native,    // ETH, BTC, SOL, etc.
    ERC20,     // ERC-20 tokens
    ERC721,    // NFTs
    ERC1155,   // Multi-token
    SPLToken,  // Solana tokens
    CosmosIBC, // Cosmos IBC tokens
    Custom,
}

impl AssetId {
    pub fn native(chain: ChainId) -> Self {
        Self {
            chain,
            contract_address: None,
            token_id: None,
            asset_type: AssetType::Native,
        }
    }

    pub fn erc20(chain: ChainId, contract: String) -> Self {
        Self {
            chain,
            contract_address: Some(contract),
            token_id: None,
            asset_type: AssetType::ERC20,
        }
    }

    pub fn to_string(&self) -> String {
        match &self.contract_address {
            Some(addr) => format!(
                "{}:{}:{}",
                self.chain.canonical_name(),
                addr,
                self.token_id.as_deref().unwrap_or("0")
            ),
            None => format!("{}:native", self.chain.canonical_name()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  LAYER 4: INSTANT TRANSFER TYPES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantIntent {
    pub intent_id: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,

    // Transfer details
    pub source_chain: ChainId,
    pub dest_chain: ChainId,
    pub source_asset: AssetId,
    pub dest_asset: AssetId,
    pub source_amount: u128,
    pub min_dest_amount: u128,

    // Parties
    pub sender: UniversalAddress,
    pub recipient: UniversalAddress,

    // Economics
    pub max_solver_reward_bps: u16, // Basis points (1 bps = 0.01%)
    pub slippage_tolerance_bps: u16,

    // Security
    pub nonce: u64,
    pub signature: Vec<u8>,

    // Escrow proof
    pub escrow_tx_hash: String,
    pub escrow_proof: Vec<u8>,
}

impl InstantIntent {
    pub fn calculate_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BLEEP-CONNECT-INTENT-V1:");
        hasher.update(&self.source_chain.to_u32().to_be_bytes());
        hasher.update(&self.dest_chain.to_u32().to_be_bytes());
        hasher.update(&self.source_amount.to_be_bytes());
        hasher.update(&self.sender.to_bytes());
        hasher.update(&self.recipient.to_bytes());
        hasher.update(&self.nonce.to_be_bytes());
        hasher.update(&self.created_at.to_be_bytes());

        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires_at
    }

    pub fn calculate_min_executor_bond(&self, tier: ExecutorTier) -> u128 {
        let ratio_bps = tier.bond_ratio_bps();
        (self.source_amount * ratio_bps as u128) / 10_000
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  EXECUTOR TYPES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutorTier {
    Bootstrap,     // New executors: 200% bond, $100K max
    Standard,      // Proven: 110% bond, $1M max
    Premium,       // High reputation: 50% bond, $10M max
    Institutional, // Major institutions: 10% bond, $100M max
}

impl ExecutorTier {
    pub fn bond_ratio_bps(&self) -> u16 {
        match self {
            ExecutorTier::Bootstrap => 20_000,    // 200%
            ExecutorTier::Standard => 11_000,     // 110%
            ExecutorTier::Premium => 5_000,       // 50%
            ExecutorTier::Institutional => 1_000, // 10%
        }
    }

    pub fn max_transfer_value(&self) -> u128 {
        match self {
            ExecutorTier::Bootstrap => 100_000_000_000, // $100K (8 decimals)
            ExecutorTier::Standard => 1_000_000_000_000, // $1M
            ExecutorTier::Premium => 10_000_000_000_000, // $10M
            ExecutorTier::Institutional => 100_000_000_000_000, // $100M
        }
    }

    pub fn required_successful_transfers(&self) -> u64 {
        match self {
            ExecutorTier::Bootstrap => 0,
            ExecutorTier::Standard => 1_000,
            ExecutorTier::Premium => 10_000,
            ExecutorTier::Institutional => 100_000,
        }
    }

    pub fn max_failure_rate_bps(&self) -> u16 {
        match self {
            ExecutorTier::Bootstrap => 100,   // 1%
            ExecutorTier::Standard => 50,     // 0.5%
            ExecutorTier::Premium => 10,      // 0.1%
            ExecutorTier::Institutional => 1, // 0.01%
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorCommitment {
    pub executor_address: UniversalAddress,
    pub intent_id: [u8; 32],
    pub bond_amount: u128,
    pub bond_tx_hash: String,
    pub execution_guarantee_ms: u64,
    pub committed_at: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorProfile {
    pub address: UniversalAddress,
    pub tier: ExecutorTier,
    pub reputation_score: f64,

    // Statistics
    pub total_executions: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub total_volume: u128,

    // Performance metrics
    pub average_execution_time_ms: u64,
    pub uptime_percentage: f64,

    // Staking
    pub total_staked: u128,
    pub available_liquidity: u128,

    // Timestamps
    pub registered_at: u64,
    pub last_execution_at: u64,
}

impl ExecutorProfile {
    pub fn failure_rate_bps(&self) -> u16 {
        if self.total_executions == 0 {
            return 10_000; // 100% unknown
        }
        ((self.failed_executions as f64 / self.total_executions as f64) * 10_000.0) as u16
    }

    pub fn can_upgrade_tier(&self) -> Option<ExecutorTier> {
        let failure_rate = self.failure_rate_bps();

        match self.tier {
            ExecutorTier::Bootstrap => {
                if self.successful_executions
                    >= ExecutorTier::Standard.required_successful_transfers()
                    && failure_rate <= ExecutorTier::Standard.max_failure_rate_bps()
                {
                    Some(ExecutorTier::Standard)
                } else {
                    None
                }
            }
            ExecutorTier::Standard => {
                if self.successful_executions
                    >= ExecutorTier::Premium.required_successful_transfers()
                    && failure_rate <= ExecutorTier::Premium.max_failure_rate_bps()
                {
                    Some(ExecutorTier::Premium)
                } else {
                    None
                }
            }
            ExecutorTier::Premium => {
                if self.successful_executions
                    >= ExecutorTier::Institutional.required_successful_transfers()
                    && failure_rate <= ExecutorTier::Institutional.max_failure_rate_bps()
                {
                    Some(ExecutorTier::Institutional)
                } else {
                    None
                }
            }
            ExecutorTier::Institutional => None, // Already at max
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TRANSFER STATE MACHINE
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferStatus {
    Created {
        created_at: u64,
    },
    EscrowLocked {
        escrow_tx: String,
        locked_at: u64,
    },
    AuctionOpen {
        opened_at: u64,
        bids_received: u32,
    },
    BidAccepted {
        executor: UniversalAddress,
        bond_tx: String,
        accepted_at: u64,
    },
    ExecutionStarted {
        executor: UniversalAddress,
        started_at: u64,
    },
    ExecutionCompleted {
        executor: UniversalAddress,
        dest_tx: String,
        completed_at: u64,
    },
    ZKProofPending {
        executor: UniversalAddress,
        proof_submitted_at: u64,
    },
    ZKProofVerified {
        executor: UniversalAddress,
        proof_hash: [u8; 32],
        verified_at: u64,
    },
    Settled {
        executor: UniversalAddress,
        settlement_tx: String,
        settled_at: u64,
    },
    Failed {
        reason: FailureReason,
        failed_at: u64,
    },
    Expired {
        expired_at: u64,
    },
    Refunded {
        refund_tx: String,
        refunded_at: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureReason {
    ExecutorTimeout,
    InvalidExecution,
    InsufficientBond,
    EscrowFailed,
    ProofVerificationFailed,
    ChainReorganization,
    Other(String),
}

// ═══════════════════════════════════════════════════════════════════════════
//  LAYER 3: ZK PROOF TYPES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProof {
    pub proof_id: [u8; 32],
    pub proof_type: ProofType,
    pub groth16_bytes: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
    pub intent_id: [u8; 32],
    pub generated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProofType {
    EscrowLocked = 0,
    ExecutionCompleted = 1,
    StateTransition = 2,
    AtomicSwap = 3,
    BatchAggregated = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBatch {
    pub batch_id: [u8; 32],
    pub proofs: Vec<ZKProof>,
    pub merkle_root: [u8; 32],
    pub aggregated_proof: Vec<u8>,
    pub created_at: u64,
}

impl ProofBatch {
    pub fn calculate_batch_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BLEEP-CONNECT-BATCH-V1:");
        for proof in &self.proofs {
            hasher.update(&proof.proof_id);
        }
        hasher.update(&self.created_at.to_be_bytes());

        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  LAYER 2: FULL NODE VERIFICATION TYPES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullNodeVerification {
    pub verification_id: [u8; 32],
    pub chain: ChainId,
    pub block_number: u64,
    pub state_root: [u8; 32],
    pub verifier_nodes: Vec<VerifierAttestation>,
    pub consensus_reached: bool,
    pub verified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierAttestation {
    pub node_id: [u8; 32],
    pub client_implementation: ClientImplementation,
    pub state_root: [u8; 32],
    pub tee_attestation: Option<TEEAttestation>,
    pub signature: Vec<u8>,
    pub attested_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientImplementation {
    // Ethereum
    Geth,
    Nethermind,
    Erigon,
    Reth,

    // Bitcoin
    BitcoinCore,
    Btcd,

    // Solana
    SolanaValidator,
    JitoValidator,

    // Other
    Custom(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEAttestation {
    pub attestation_report: Vec<u8>,
    pub code_measurement: [u8; 32],
    pub tee_public_key: Vec<u8>,
    pub tee_type: TEEType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TEEType {
    IntelSGX,
    AMDSEV,
    ARMTT,
}

// ═══════════════════════════════════════════════════════════════════════════
//  LAYER 1: SOCIAL CONSENSUS TYPES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialProposal {
    pub proposal_id: [u8; 32],
    pub proposal_type: ProposalType,
    pub proposer: UniversalAddress,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub created_at: u64,
    pub voting_deadline: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalType {
    EmergencyPause {
        reason: String,
    },
    StateRollback {
        target_block: u64,
        affected_transfers: Vec<[u8; 32]>,
    },
    DisputeResolution {
        transfer_id: [u8; 32],
        ruling: String,
    },
    ProtocolUpgrade {
        upgrade_version: String,
        audit_report_hash: [u8; 32],
    },
    ParameterChange {
        parameter: String,
        old_value: String,
        new_value: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub data_hash: [u8; 32],
    pub ipfs_cid: String,
    pub submitted_by: UniversalAddress,
    pub submitted_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    ChainData,
    TransactionTrace,
    LogFile,
    AuditReport,
    WitnessStatement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter: UniversalAddress,
    pub voter_type: VoterType,
    pub proposal_id: [u8; 32],
    pub vote: VoteChoice,
    pub voting_power: u128,
    pub voted_at: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoterType {
    Validator,
    User,
    Developer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VoteChoice {
    Approve = 0,
    Reject = 1,
    Abstain = 2,
}

// ═══════════════════════════════════════════════════════════════════════════
//  COMMITMENT CHAIN TYPES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentBlock {
    pub block_number: u64,
    pub timestamp: u64,
    pub previous_hash: [u8; 32],
    pub commitments: Vec<StateCommitment>,
    pub validator_signatures: Vec<ValidatorSignature>,
}

impl CommitmentBlock {
    pub fn calculate_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BLEEP-CONNECT-BLOCK-V1:");
        hasher.update(&self.block_number.to_be_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(&self.previous_hash);

        for commitment in &self.commitments {
            hasher.update(&commitment.commitment_id);
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateCommitment {
    pub commitment_id: [u8; 32],
    pub commitment_type: CommitmentType,
    pub data_hash: [u8; 32],
    pub layer: u8,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitmentType {
    InstantTransfer,
    ZKProofBatch,
    FullNodeVerification,
    SocialDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator_id: [u8; 32],
    pub signature: Vec<u8>,
    pub signed_at: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
//  ERROR TYPES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Error)]
pub enum BleepConnectError {
    #[error("Invalid chain ID: {0}")]
    InvalidChainId(String),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    #[error("Intent expired at {0}")]
    IntentExpired(u64),

    #[error("Insufficient bond: required {required}, provided {provided}")]
    InsufficientBond { required: u128, provided: u128 },

    #[error("Executor not qualified: {0}")]
    ExecutorNotQualified(String),

    #[error("Transfer limit exceeded: max {max}, attempted {attempted}")]
    TransferLimitExceeded { max: u128, attempted: u128 },

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Consensus not reached: {agreement}% agreement")]
    ConsensusNotReached { agreement: f64 },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

pub type BleepConnectResult<T> = Result<T, BleepConnectError>;

// ═══════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

pub mod constants {
    use std::time::Duration;

    // Layer 4 constants
    pub const EXECUTOR_AUCTION_DURATION: Duration = Duration::from_secs(15);
    pub const EXECUTION_TIMEOUT: Duration = Duration::from_secs(120);
    pub const INTENT_DEFAULT_EXPIRY: Duration = Duration::from_secs(300); // 5 minutes

    // Layer 3 constants
    pub const PROOF_GENERATION_TIMEOUT: Duration = Duration::from_secs(30);
    pub const BATCH_TARGET_SIZE: usize = 50;
    pub const BATCH_MAX_SIZE: usize = 500;
    pub const BATCH_MIN_SIZE: usize = 5;
    pub const BATCH_INTERVAL: Duration = Duration::from_secs(5);

    // Layer 2 constants
    pub const FULL_NODE_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(60);
    pub const CONSENSUS_THRESHOLD: f64 = 0.90; // 90% agreement
    pub const MIN_VERIFIER_NODES: usize = 3;

    // Layer 1 constants
    pub const VOTING_PERIOD_NORMAL: Duration = Duration::from_secs(7 * 24 * 3600); // 7 days
    pub const VOTING_PERIOD_EMERGENCY: Duration = Duration::from_secs(24 * 3600); // 1 day
    pub const VOTING_THRESHOLD_NORMAL: f64 = 0.66; // 66%
    pub const VOTING_THRESHOLD_EMERGENCY: f64 = 0.80; // 80%

    // Economic constants
    pub const MIN_EXECUTOR_STAKE: u128 = 10_000_000_000; // 100 tokens (8 decimals)
    pub const SLASH_PENALTY_BPS: u16 = 3_000; // 30%
    pub const PROTOCOL_FEE_BPS: u16 = 10; // 0.1%

    // Security constants
    pub const MAX_REORG_DEPTH: u64 = 100;
    pub const CHAIN_FINALITY_BLOCKS: &[(super::ChainId, u64)] = &[
        (super::ChainId::Ethereum, 12),
        (super::ChainId::Bitcoin, 6),
        (super::ChainId::Solana, 32),
        (super::ChainId::Polygon, 128),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_id_conversion() {
        assert_eq!(ChainId::Ethereum.to_u32(), 1);
        assert_eq!(ChainId::from_name("ethereum"), Some(ChainId::Ethereum));
        assert_eq!(ChainId::Bitcoin.canonical_name(), "bitcoin");
    }

    #[test]
    fn test_universal_address() {
        let addr = UniversalAddress::ethereum("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb");
        assert_eq!(addr.chain, ChainId::Ethereum);
        assert_eq!(
            addr.to_string(),
            "ethereum:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
        );
    }

    #[test]
    fn test_executor_tier_requirements() {
        assert_eq!(ExecutorTier::Bootstrap.bond_ratio_bps(), 20_000);
        assert_eq!(
            ExecutorTier::Standard.required_successful_transfers(),
            1_000
        );
        assert_eq!(
            ExecutorTier::Premium.max_transfer_value(),
            10_000_000_000_000
        );
    }

    #[test]
    fn test_instant_intent_id_calculation() {
        let intent = InstantIntent {
            intent_id: [0u8; 32],
            created_at: 1234567890,
            expires_at: 1234567990,
            source_chain: ChainId::Ethereum,
            dest_chain: ChainId::Solana,
            source_asset: AssetId::native(ChainId::Ethereum),
            dest_asset: AssetId::native(ChainId::Solana),
            source_amount: 1_000_000_000,
            min_dest_amount: 950_000_000,
            sender: UniversalAddress::ethereum("0xabc"),
            recipient: UniversalAddress::solana("xyz"),
            max_solver_reward_bps: 50,
            slippage_tolerance_bps: 100,
            nonce: 1,
            signature: vec![],
            escrow_tx_hash: String::new(),
            escrow_proof: vec![],
        };

        let id1 = intent.calculate_id();
        let id2 = intent.calculate_id();
        assert_eq!(id1, id2); // Deterministic
        assert_ne!(id1, [0u8; 32]); // Non-zero
    }
}
