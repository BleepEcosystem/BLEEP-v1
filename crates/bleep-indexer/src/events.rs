// ============================================================================
// BLEEP-INDEXER: Chain Event Types
//
// All chain events that can be submitted to the indexer.
// These mirror the on-chain structures from bleep-core / bleep-consensus /
// bleep-governance / bleep-state, but are decoupled so the indexer does not
// take compile-time dependencies on those crates (avoiding circular deps).
// ============================================================================

use serde::{Deserialize, Serialize};

// ── Transaction ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TxType {
    Transfer,
    ContractDeploy,
    ContractInvoke,
    GovernanceVote,
    ValidatorRegistration,
    CrossShard,
    ShardHealing,
    TokenBurn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxStatus {
    Pending,
    Confirmed {
        block_height: u64,
        block_hash: String,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxData {
    pub hash: String,
    pub sender: String,
    pub receiver: String,
    pub amount: u128,
    pub fee: u128,
    pub nonce: u64,
    pub tx_type: TxType,
    pub status: TxStatus,
    pub gas_used: u64,
    pub timestamp: u64,
    pub shard_id: u64,
}

// ── Block ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    pub hash: String,
    pub parent_hash: String,
    pub height: u64,
    pub epoch: u64,
    pub shard_id: u64,
    pub timestamp: u64,
    pub producer: String,
    pub consensus_mode: String,
    pub transaction_count: u32,
    pub transactions: Vec<TxData>,
    pub merkle_root: String,
    pub state_root: String,
    pub gas_used: u64,
    pub gas_limit: u64,
}

// ── Governance ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceEventKind {
    Proposed { description: String },
    SubmittedForValidation,
    ConstitutionallyValidated { passed: bool },
    VotingStarted { end_height: u64 },
    VoteCast { commitment_hash: String },
    VotingEnded,
    Approved { yes_weight: f64, no_weight: f64 },
    Rejected { yes_weight: f64, no_weight: f64 },
    Executed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEventData {
    pub proposal_id: String,
    pub kind: GovernanceEventKind,
    pub actor_id: String,
    pub block_height: u64,
    pub epoch: u64,
}

// ── Validator ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidatorEventKind {
    Registered {
        stake: u128,
        kyber_pubkey_hash: String,
    },
    Activated,
    StakeAdded {
        amount: u128,
    },
    StakeWithdrawn {
        amount: u128,
    },
    Slashed {
        amount: u128,
        reason: String,
        evidence_hash: String,
    },
    Deactivated,
    ExitScheduled {
        exit_epoch: u64,
    },
    ExitFinalised,
    ReputationUpdated {
        old: f64,
        new: f64,
    },
    ConsensusReward {
        amount: u128,
    },
    HealingReward {
        amount: u128,
    },
    BlockMissed {
        height: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEventData {
    pub validator_id: String,
    pub kind: ValidatorEventKind,
    pub block_height: u64,
    pub epoch: u64,
}

// ── Shard ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardEventKind {
    Created {
        initial_validators: Vec<String>,
    },
    ValidatorAssigned {
        validator_id: String,
    },
    ValidatorRemoved {
        validator_id: String,
    },
    FaultDetected {
        severity: String,
        fault_type: String,
    },
    Isolated,
    HealingStarted {
        operation_id: String,
    },
    HealingCompleted {
        operation_id: String,
    },
    HealingFailed {
        operation_id: String,
        reason: String,
    },
    Split {
        new_shard_ids: Vec<u64>,
    },
    Merged {
        absorbed_shard: u64,
    },
    CheckpointCreated {
        checkpoint_hash: String,
    },
    StateRootUpdated {
        state_root: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardEventData {
    pub shard_id: u64,
    pub kind: ShardEventKind,
    pub block_height: u64,
    pub epoch: u64,
}

// ── Cross-shard ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossShardEventKind {
    Initiated,
    Prepared,
    Committed,
    Aborted { reason: String },
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardEventData {
    pub tx_id: String,
    pub source_shard: u64,
    pub dest_shard: u64,
    pub kind: CrossShardEventKind,
    pub block_height: u64,
}

// ── AI advisory ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AiEventKind {
    AnomalyDetected {
        anomaly_class: String,
    },
    ConsensusModeSuggested {
        suggested: String,
        current: String,
    },
    ShardRebalanceSuggested {
        shard_id: u64,
        action: String,
    },
    ProposalClassified {
        proposal_id: String,
        risk_level: String,
    },
    FeeMultiplierAdjusted {
        old: f64,
        new: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiEventData {
    pub event_id: String,
    pub kind: AiEventKind,
    pub model_hash: String,
    pub confidence: f64,
    pub block_height: u64,
    pub epoch: u64,
}

// ── Master event enum ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexerEvent {
    /// A new finalised block with all its transactions
    Block(BlockData),
    /// A transaction seen in the mempool (not yet confirmed)
    MempoolTx(TxData),
    /// A governance lifecycle event
    Governance(GovernanceEventData),
    /// A validator lifecycle event
    Validator(ValidatorEventData),
    /// A shard-level event
    Shard(ShardEventData),
    /// A cross-shard 2PC event
    CrossShard(CrossShardEventData),
    /// An AI advisory event
    Ai(AiEventData),
    /// Chain reorganisation detected
    Reorg {
        from_height: u64,
        to_height: u64,
        new_tip_hash: String,
    },
    /// Graceful shutdown signal
    Shutdown,
}
