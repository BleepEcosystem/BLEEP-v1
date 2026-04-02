// PHASE 1: CONSENSUS ENGINE TRAIT
// Unified interface for all consensus modes
//
// SAFETY: This trait enforces a contract that all consensus engines must follow:
// 1. Deterministic block proposal (same state → same proposal)
// 2. Byzantine-tolerant verification (rejects invalid blocks)
// 3. No internal state mutations (state parameter is explicit)

use crate::epoch::{ConsensusMode, EpochState};
use bleep_core::block::Block;
use bleep_core::blockchain::BlockchainState;
use std::fmt;

/// Consensus engine errors with detailed context.
///
/// SAFETY: All errors are logged and may trigger consensus mode switching
/// or chain halts, so error variants must be precise and actionable.
#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusError {
    /// Block hash is invalid (indicates tampering or computation error)
    InvalidBlockHash { block_height: u64, reason: String },

    /// Epoch ID in block does not match expected epoch
    EpochMismatch {
        expected: u64,
        got: u64,
        height: u64,
    },

    /// Consensus mode in block does not match epoch's locked mode
    ConsensusModeMismatch {
        expected: String,
        got: String,
        epoch: u64,
    },

    /// Protocol version mismatch (hard fork detected)
    ProtocolVersionMismatch { expected: u32, got: u32 },

    /// Insufficient validator stake or participation
    InsufficientValidatorParticipation {
        participation_rate: f64,
        threshold: f64,
    },

    /// Block signature verification failed
    InvalidSignature { validator_id: String },

    /// Block proposal violates consensus rules
    ProposalRejected { reason: String },

    /// Proof-of-Work does not meet difficulty target
    InsufficientProofOfWork { reason: String },

    /// PBFT consensus did not reach quorum
    PbftQuorumNotReached { validators: usize, threshold: usize },

    /// Generic consensus error
    Other(String),
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusError::InvalidBlockHash {
                block_height,
                reason,
            } => {
                write!(
                    f,
                    "Invalid block hash at height {}: {}",
                    block_height, reason
                )
            }
            ConsensusError::EpochMismatch {
                expected,
                got,
                height,
            } => {
                write!(
                    f,
                    "Epoch mismatch at height {}: expected {}, got {}",
                    height, expected, got
                )
            }
            ConsensusError::ConsensusModeMismatch {
                expected,
                got,
                epoch,
            } => {
                write!(
                    f,
                    "Consensus mode mismatch in epoch {}: expected {}, got {}",
                    epoch, expected, got
                )
            }
            ConsensusError::ProtocolVersionMismatch { expected, got } => {
                write!(
                    f,
                    "Protocol version mismatch: expected {}, got {}",
                    expected, got
                )
            }
            ConsensusError::InsufficientValidatorParticipation {
                participation_rate,
                threshold,
            } => {
                write!(
                    f,
                    "Insufficient validator participation: {:.2}% < {:.2}%",
                    participation_rate * 100.0,
                    threshold * 100.0
                )
            }
            ConsensusError::InvalidSignature { validator_id } => {
                write!(f, "Invalid signature from validator {}", validator_id)
            }
            ConsensusError::ProposalRejected { reason } => {
                write!(f, "Block proposal rejected: {}", reason)
            }
            ConsensusError::InsufficientProofOfWork { reason } => {
                write!(f, "Insufficient proof of work: {}", reason)
            }
            ConsensusError::PbftQuorumNotReached {
                validators,
                threshold,
            } => {
                write!(
                    f,
                    "PBFT quorum not reached: {} validators < {} threshold",
                    validators, threshold
                )
            }
            ConsensusError::Other(msg) => write!(f, "Consensus error: {}", msg),
        }
    }
}

/// Consensus engine trait: unified interface for all consensus modes.
///
/// SAFETY INVARIANTS:
/// 1. verify_block is idempotent (calling twice produces identical result)
/// 2. propose_block produces identical output given identical state
/// 3. No mutable state (all state is passed explicitly)
/// 4. Errors are deterministic (same state → same error)
pub trait ConsensusEngine: Send + Sync {
    /// Verify that a block is valid according to this consensus mode.
    ///
    /// SAFETY: This method is the ONLY block validation gate.
    /// It must reject any block that violates consensus rules.
    ///
    /// # Arguments
    /// * `block` - The block to verify
    /// * `epoch_state` - The epoch parameters for this block
    /// * `blockchain_state` - Current state (balances, validator info, etc.)
    ///
    /// # Returns
    /// - `Ok(())` if block is valid
    /// - `Err(ConsensusError)` if block violates any rule
    ///
    /// # Notes
    /// - Must be deterministic (same input → same output)
    /// - Must check epoch_id, consensus_mode, protocol_version
    /// - Must verify block signature and/or proof-of-work
    fn verify_block(
        &self,
        block: &Block,
        epoch_state: &EpochState,
        blockchain_state: &BlockchainState,
    ) -> Result<(), ConsensusError>;

    /// Propose a new block according to this consensus mode.
    ///
    /// SAFETY: This method produces blocks that must pass verify_block.
    /// The orchestrator ensures only the correct mode proposes blocks.
    ///
    /// # Arguments
    /// * `height` - The block height to propose
    /// * `previous_hash` - Hash of the previous block
    /// * `transactions` - Transactions to include
    /// * `epoch_state` - Epoch parameters for this block
    /// * `blockchain_state` - Current state
    ///
    /// # Returns
    /// - `Ok(Block)` with a valid, signed block
    /// - `Err(ConsensusError)` if proposal cannot be created
    ///
    /// # Notes
    /// - Must set epoch_id, consensus_mode, protocol_version
    /// - Must sign the block with validator key
    /// - May perform mode-specific computations (PoW, PBFT, etc.)
    fn propose_block(
        &self,
        height: u64,
        previous_hash: String,
        transactions: Vec<bleep_core::block::Transaction>,
        epoch_state: &EpochState,
        blockchain_state: &BlockchainState,
    ) -> Result<Block, ConsensusError>;

    /// Return the consensus mode this engine implements.
    fn consensus_mode(&self) -> ConsensusMode;

    /// Health check: return whether this engine is operating normally.
    /// Used by the orchestrator to decide if mode switching is needed.
    fn health_status(&self) -> f64;
}

/// Metrics for evaluating consensus engine performance.
///
/// Used by the orchestrator to make deterministic decisions about
/// mode switching.
#[derive(Debug, Clone, Copy)]
pub struct ConsensusMetrics {
    /// Percentage of active validators participating (0.0 to 1.0)
    pub validator_participation: f64,

    /// Average block proposal time in milliseconds
    pub block_proposal_time_ms: u64,

    /// Number of blocks rejected due to validation failures in this epoch
    pub rejected_block_count: u64,

    /// Number of slashing events (Byzantine faults detected)
    pub slashing_event_count: u64,

    /// Average finality latency in blocks
    pub finality_latency_blocks: u64,

    /// Network bandwidth utilization (0.0 to 1.0)
    pub network_utilization: f64,
}

impl ConsensusMetrics {
    /// Create metrics with all values at zero/default.
    pub fn new() -> Self {
        ConsensusMetrics {
            validator_participation: 1.0,
            block_proposal_time_ms: 0,
            rejected_block_count: 0,
            slashing_event_count: 0,
            finality_latency_blocks: 0,
            network_utilization: 0.0,
        }
    }

    /// Compute a health score (0.0 to 1.0).
    /// Used to detect when the current mode is degraded.
    ///
    /// Lower scores indicate worse health.
    pub fn health_score(&self) -> f64 {
        // Health degrades if:
        // - Participation drops below 66% (requires 2/3 + 1 honest validators)
        // - Too many rejections
        // - Byzantine faults detected

        let participation_score = if self.validator_participation >= 0.66 {
            1.0
        } else if self.validator_participation >= 0.50 {
            0.5
        } else {
            0.0 // Chain safety compromised
        };

        let rejection_score = 1.0 - (self.rejected_block_count as f64 / 100.0).min(1.0);
        let slashing_score = 1.0 - (self.slashing_event_count as f64 / 10.0).min(1.0);

        (participation_score + rejection_score + slashing_score) / 3.0
    }

    /// Check if metrics indicate an emergency condition.
    /// Returns true if health is severely degraded.
    pub fn is_emergency_condition(&self) -> bool {
        self.validator_participation < 0.50
            || self.slashing_event_count > 5
            || self.rejected_block_count > 50
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_error_display() {
        let err = ConsensusError::EpochMismatch {
            expected: 10,
            got: 11,
            height: 5000,
        };
        let msg = err.to_string();
        assert!(msg.contains("Epoch mismatch"));
        assert!(msg.contains("5000"));
    }

    #[test]
    fn test_metrics_health_score_full() {
        let metrics = ConsensusMetrics {
            validator_participation: 1.0,
            block_proposal_time_ms: 100,
            rejected_block_count: 0,
            slashing_event_count: 0,
            finality_latency_blocks: 1,
            network_utilization: 0.5,
        };
        assert_eq!(metrics.health_score(), 1.0);
    }

    #[test]
    fn test_metrics_health_score_degraded() {
        let metrics = ConsensusMetrics {
            validator_participation: 0.60,
            block_proposal_time_ms: 100,
            rejected_block_count: 20,
            slashing_event_count: 2,
            finality_latency_blocks: 5,
            network_utilization: 0.8,
        };
        let score = metrics.health_score();
        assert!(score < 1.0);
        assert!(score > 0.0);
    }

    #[test]
    fn test_metrics_emergency_condition_low_participation() {
        let metrics = ConsensusMetrics {
            validator_participation: 0.40,
            block_proposal_time_ms: 100,
            rejected_block_count: 0,
            slashing_event_count: 0,
            finality_latency_blocks: 1,
            network_utilization: 0.5,
        };
        assert!(metrics.is_emergency_condition());
    }

    #[test]
    fn test_metrics_emergency_condition_many_slashing() {
        let metrics = ConsensusMetrics {
            validator_participation: 0.90,
            block_proposal_time_ms: 100,
            rejected_block_count: 0,
            slashing_event_count: 10,
            finality_latency_blocks: 1,
            network_utilization: 0.5,
        };
        assert!(metrics.is_emergency_condition());
    }
}
