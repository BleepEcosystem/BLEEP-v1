use bincode;
/// AI Decision Types and Proposal Schemas
///
/// This module defines the complete set of AI proposal types that BLEEP can generate.
/// Each proposal:
/// - Is strongly typed
/// - Validates against schema
/// - Includes confidence scores
/// - Provides supporting evidence
/// - Must be cryptographically signed
/// - Cannot self-execute
///
/// DOMAINS COVERED:
/// 1. Consensus Mode Switching
/// 2. Self-Healing & Recovery
/// 3. Security & Validator Management
/// 4. Tokenomics & Fee Tuning
/// 5. Governance & Proposal Prioritization
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ==================== ERROR TYPES ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AIProposalError {
    SchemaValidationFailed(String),
    InvalidConfidence(String),
    MissingEvidence(String),
    ConstraintViolation(String),
    SerializationError(String),
}

impl fmt::Display for AIProposalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaValidationFailed(msg) => write!(f, "Schema validation failed: {}", msg),
            Self::InvalidConfidence(msg) => write!(f, "Invalid confidence: {}", msg),
            Self::MissingEvidence(msg) => write!(f, "Missing evidence: {}", msg),
            Self::ConstraintViolation(msg) => write!(f, "Constraint violation: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for AIProposalError {}

pub type AIProposalResult<T> = Result<T, AIProposalError>;

// ==================== EVIDENCE TYPES ====================

/// Supporting evidence for AI decisions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceType {
    /// Numerical metric
    Metric {
        name: String,
        value: f32,
        threshold: f32,
        direction: String, // "above", "below", "equal"
    },

    /// Historical performance data
    HistoricalData {
        metric: String,
        samples: Vec<f32>,
        mean: f32,
        std_dev: f32,
    },

    /// Byzantine fault count
    FaultCount {
        detected_faults: u32,
        epoch_range: (u64, u64),
        severity: String,
    },

    /// Validator participation
    ValidatorParticipation {
        total_validators: u32,
        active_validators: u32,
        participation_rate: f32,
    },

    /// Block finality latency
    FinalityLatency {
        avg_blocks_to_finality: u32,
        max_latency_blocks: u32,
        target_latency: u32,
    },

    /// Cross-shard transaction health
    CrossShardHealth {
        total_txs: u64,
        successful_txs: u64,
        failed_txs: u64,
        success_rate: f32,
    },

    /// Gas/fee statistics
    FeeStatistics {
        avg_fee: u64,
        min_fee: u64,
        max_fee: u64,
        target_fee: u64,
    },

    /// Custom evidence (auditor-provable)
    Custom {
        category: String,
        data: String,
        confidence: f32,
    },
}

impl EvidenceType {
    /// Validate evidence meets constraints
    pub fn validate(&self) -> AIProposalResult<()> {
        match self {
            EvidenceType::Metric {
                value, threshold, ..
            } => {
                if value.is_nan() || value.is_infinite() {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Metric value is NaN or infinite".to_string(),
                    ));
                }
                if threshold.is_nan() || threshold.is_infinite() {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Threshold is NaN or infinite".to_string(),
                    ));
                }
                Ok(())
            }
            EvidenceType::HistoricalData {
                metric: _,
                samples,
                mean,
                std_dev,
            } => {
                if samples.is_empty() {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Historical data has no samples".to_string(),
                    ));
                }
                if mean.is_nan() || std_dev.is_nan() {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Mean or std dev is NaN".to_string(),
                    ));
                }
                if *std_dev < 0.0 {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Std dev cannot be negative".to_string(),
                    ));
                }
                Ok(())
            }
            EvidenceType::ValidatorParticipation {
                total_validators,
                active_validators,
                participation_rate,
            } => {
                if *active_validators > *total_validators {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Active validators exceeds total".to_string(),
                    ));
                }
                if !(*participation_rate >= 0.0 && *participation_rate <= 1.0) {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Participation rate must be [0, 1]".to_string(),
                    ));
                }
                Ok(())
            }
            EvidenceType::CrossShardHealth {
                total_txs,
                successful_txs,
                failed_txs,
                success_rate,
            } => {
                if successful_txs + failed_txs > *total_txs {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Success + failed txs exceeds total".to_string(),
                    ));
                }
                if !(*success_rate >= 0.0 && *success_rate <= 1.0) {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Success rate must be [0, 1]".to_string(),
                    ));
                }
                Ok(())
            }
            EvidenceType::FeeStatistics {
                min_fee,
                avg_fee,
                max_fee,
                ..
            } => {
                if !(min_fee <= avg_fee && avg_fee <= max_fee) {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Fee ordering violated: min > avg or avg > max".to_string(),
                    ));
                }
                Ok(())
            }
            EvidenceType::Custom { confidence, .. } => {
                if !(*confidence >= 0.0 && *confidence <= 1.0) {
                    return Err(AIProposalError::SchemaValidationFailed(
                        "Custom evidence confidence must be [0, 1]".to_string(),
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

// ==================== CONSENSUS PROPOSALS ====================

/// Propose a consensus mode switch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusModeProposal {
    /// Current consensus mode
    pub current_mode: String,

    /// Proposed new mode
    pub proposed_mode: String,

    /// Epoch to activate new mode
    pub activation_epoch: u64,

    /// Reason for switch
    pub reason: String,

    /// Confidence (0.0-1.0)
    pub confidence: f32,

    /// Supporting evidence
    pub evidence: Vec<EvidenceType>,

    /// Risk score (0-100)
    pub risk_score: u32,

    /// Recommended cooldown epochs after switch
    pub cooldown_epochs: u64,
}

impl ConsensusModeProposal {
    /// Validate proposal schema
    pub fn validate(&self) -> AIProposalResult<()> {
        if self.current_mode.is_empty() {
            return Err(AIProposalError::SchemaValidationFailed(
                "Current mode cannot be empty".to_string(),
            ));
        }
        if self.proposed_mode.is_empty() {
            return Err(AIProposalError::SchemaValidationFailed(
                "Proposed mode cannot be empty".to_string(),
            ));
        }
        if self.current_mode == self.proposed_mode {
            return Err(AIProposalError::SchemaValidationFailed(
                "Cannot propose same mode".to_string(),
            ));
        }
        if !(self.confidence >= 0.0 && self.confidence <= 1.0) {
            return Err(AIProposalError::InvalidConfidence(
                "Confidence must be [0, 1]".to_string(),
            ));
        }
        if self.evidence.is_empty() {
            return Err(AIProposalError::MissingEvidence(
                "Consensus mode switch requires evidence".to_string(),
            ));
        }
        if self.risk_score > 100 {
            return Err(AIProposalError::SchemaValidationFailed(
                "Risk score must be [0, 100]".to_string(),
            ));
        }

        // Validate all evidence
        for evidence in &self.evidence {
            evidence.validate()?;
        }

        Ok(())
    }
}

// ==================== SELF-HEALING PROPOSALS ====================

/// Propose shard rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRollbackProposal {
    /// Shard ID
    pub shard_id: u32,

    /// Checkpoint height to rollback to
    pub target_checkpoint: u64,

    /// Reason for rollback
    pub reason: String,

    /// Confidence (0.0-1.0)
    pub confidence: f32,

    /// Evidence of fault
    pub evidence: Vec<EvidenceType>,

    /// Whether to slash validators
    pub slash_validators: bool,

    /// Validators to slash (if applicable)
    pub validators_to_slash: Vec<String>,
}

impl ShardRollbackProposal {
    /// Validate proposal
    pub fn validate(&self) -> AIProposalResult<()> {
        if self.reason.is_empty() {
            return Err(AIProposalError::SchemaValidationFailed(
                "Rollback reason required".to_string(),
            ));
        }
        if !(self.confidence >= 0.0 && self.confidence <= 1.0) {
            return Err(AIProposalError::InvalidConfidence(
                "Confidence must be [0, 1]".to_string(),
            ));
        }
        if self.evidence.is_empty() {
            return Err(AIProposalError::MissingEvidence(
                "Rollback requires fault evidence".to_string(),
            ));
        }
        if self.slash_validators && self.validators_to_slash.is_empty() {
            return Err(AIProposalError::SchemaValidationFailed(
                "Slashing enabled but no validators specified".to_string(),
            ));
        }

        for evidence in &self.evidence {
            evidence.validate()?;
        }

        Ok(())
    }
}

/// Propose shard rebalancing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRebalanceProposal {
    /// Shards to rebalance
    pub affected_shards: Vec<u32>,

    /// New validator distribution (shard -> count)
    pub new_distribution: BTreeMap<u32, u32>,

    /// Reason for rebalance
    pub reason: String,

    /// Confidence
    pub confidence: f32,

    /// Supporting evidence
    pub evidence: Vec<EvidenceType>,
}

impl ShardRebalanceProposal {
    /// Validate proposal
    pub fn validate(&self) -> AIProposalResult<()> {
        if self.affected_shards.is_empty() {
            return Err(AIProposalError::SchemaValidationFailed(
                "At least one shard must be affected".to_string(),
            ));
        }
        if self.new_distribution.is_empty() {
            return Err(AIProposalError::SchemaValidationFailed(
                "New distribution required".to_string(),
            ));
        }
        if !(self.confidence >= 0.0 && self.confidence <= 1.0) {
            return Err(AIProposalError::InvalidConfidence(
                "Confidence must be [0, 1]".to_string(),
            ));
        }

        for evidence in &self.evidence {
            evidence.validate()?;
        }

        Ok(())
    }
}

// ==================== SECURITY PROPOSALS ====================

/// Propose validator isolation/removal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSecurityProposal {
    /// Validator ID
    pub validator_id: String,

    /// Security action
    pub action: String, // "isolate", "remove", "increase_monitoring"

    /// Reason
    pub reason: String,

    /// Confidence
    pub confidence: f32,

    /// Supporting evidence
    pub evidence: Vec<EvidenceType>,

    /// Risk assessment
    pub risk_level: String, // "low", "medium", "high", "critical"
}

impl ValidatorSecurityProposal {
    /// Validate proposal
    pub fn validate(&self) -> AIProposalResult<()> {
        if self.validator_id.is_empty() {
            return Err(AIProposalError::SchemaValidationFailed(
                "Validator ID required".to_string(),
            ));
        }
        if !["isolate", "remove", "increase_monitoring"].contains(&self.action.as_str()) {
            return Err(AIProposalError::SchemaValidationFailed(
                "Invalid security action".to_string(),
            ));
        }
        if !(self.confidence >= 0.0 && self.confidence <= 1.0) {
            return Err(AIProposalError::InvalidConfidence(
                "Confidence must be [0, 1]".to_string(),
            ));
        }
        if !["low", "medium", "high", "critical"].contains(&self.risk_level.as_str()) {
            return Err(AIProposalError::SchemaValidationFailed(
                "Invalid risk level".to_string(),
            ));
        }

        for evidence in &self.evidence {
            evidence.validate()?;
        }

        Ok(())
    }
}

// ==================== TOKENOMICS PROPOSALS ====================

/// Propose fee/reward adjustments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenomicsProposal {
    /// Parameter being adjusted
    pub parameter: String, // "base_fee", "validator_reward", "slashing_penalty"

    /// Current value
    pub current_value: u64,

    /// Proposed new value
    pub new_value: u64,

    /// Adjustment reason
    pub reason: String,

    /// Confidence
    pub confidence: f32,

    /// Supporting evidence
    pub evidence: Vec<EvidenceType>,

    /// Rollback epoch if adjustment fails
    pub max_epochs_to_test: u64,
}

impl TokenomicsProposal {
    /// Validate proposal
    pub fn validate(&self) -> AIProposalResult<()> {
        if self.parameter.is_empty() {
            return Err(AIProposalError::SchemaValidationFailed(
                "Parameter name required".to_string(),
            ));
        }
        if !(self.confidence >= 0.0 && self.confidence <= 1.0) {
            return Err(AIProposalError::InvalidConfidence(
                "Confidence must be [0, 1]".to_string(),
            ));
        }
        if self.current_value == self.new_value {
            return Err(AIProposalError::SchemaValidationFailed(
                "New value must differ from current".to_string(),
            ));
        }

        for evidence in &self.evidence {
            evidence.validate()?;
        }

        Ok(())
    }
}

// ==================== GOVERNANCE PROPOSALS ====================

/// Propose governance-level priority adjustments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernancePriorityProposal {
    /// Proposal IDs to prioritize
    pub proposal_ids: Vec<String>,

    /// Priority level
    pub priority: u32, // 1 (highest) to 10 (lowest)

    /// Reason for prioritization
    pub reason: String,

    /// Confidence
    pub confidence: f32,

    /// Supporting evidence
    pub evidence: Vec<EvidenceType>,
}

impl GovernancePriorityProposal {
    /// Validate proposal
    pub fn validate(&self) -> AIProposalResult<()> {
        if self.proposal_ids.is_empty() {
            return Err(AIProposalError::SchemaValidationFailed(
                "At least one proposal ID required".to_string(),
            ));
        }
        if !(1..=10).contains(&self.priority) {
            return Err(AIProposalError::SchemaValidationFailed(
                "Priority must be [1, 10]".to_string(),
            ));
        }
        if !(self.confidence >= 0.0 && self.confidence <= 1.0) {
            return Err(AIProposalError::InvalidConfidence(
                "Confidence must be [0, 1]".to_string(),
            ));
        }

        for evidence in &self.evidence {
            evidence.validate()?;
        }

        Ok(())
    }
}

// ==================== PROPOSAL WRAPPER ====================

/// Universal proposal type (contains all possible proposals)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AIProposal {
    ConsensusModeSwitch(ConsensusModeProposal),
    ShardRollback(ShardRollbackProposal),
    ShardRebalance(ShardRebalanceProposal),
    ValidatorSecurity(ValidatorSecurityProposal),
    TokenomicsAdjustment(TokenomicsProposal),
    GovernancePriority(GovernancePriorityProposal),
}

impl AIProposal {
    /// Get proposal ID (deterministic hash)
    pub fn compute_id(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let serialized = bincode::serialize(self).unwrap_or_default();
        let mut hasher = Sha3_256::new();
        hasher.update(&serialized);
        format!("{:x}", hasher.finalize())
    }

    /// Get proposal epoch
    pub fn epoch(&self) -> u64 {
        match self {
            AIProposal::ConsensusModeSwitch(p) => p.activation_epoch,
            AIProposal::ShardRollback(_) => 0,
            AIProposal::ShardRebalance(_) => 0,
            AIProposal::ValidatorSecurity(_) => 0,
            AIProposal::TokenomicsAdjustment(p) => p.max_epochs_to_test,
            AIProposal::GovernancePriority(_) => 0,
        }
    }

    /// Validate proposal schema
    pub fn validate(&self) -> AIProposalResult<()> {
        match self {
            AIProposal::ConsensusModeSwitch(p) => p.validate(),
            AIProposal::ShardRollback(p) => p.validate(),
            AIProposal::ShardRebalance(p) => p.validate(),
            AIProposal::ValidatorSecurity(p) => p.validate(),
            AIProposal::TokenomicsAdjustment(p) => p.validate(),
            AIProposal::GovernancePriority(p) => p.validate(),
        }
    }

    /// Get confidence score
    pub fn confidence(&self) -> f32 {
        match self {
            AIProposal::ConsensusModeSwitch(p) => p.confidence,
            AIProposal::ShardRollback(p) => p.confidence,
            AIProposal::ShardRebalance(p) => p.confidence,
            AIProposal::ValidatorSecurity(p) => p.confidence,
            AIProposal::TokenomicsAdjustment(p) => p.confidence,
            AIProposal::GovernancePriority(p) => p.confidence,
        }
    }
}

// ==================== TESTS ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_proposal_validation() {
        let proposal = ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Improve finality".to_string(),
            confidence: 0.85,
            evidence: vec![EvidenceType::Metric {
                name: "finality_latency".to_string(),
                value: 15.0,
                threshold: 20.0,
                direction: "below".to_string(),
            }],
            risk_score: 25,
            cooldown_epochs: 5,
        };

        assert!(proposal.validate().is_ok());
    }

    #[test]
    fn test_consensus_proposal_invalid_confidence() {
        let proposal = ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Improve finality".to_string(),
            confidence: 1.5, // Invalid!
            evidence: vec![EvidenceType::Metric {
                name: "metric".to_string(),
                value: 1.0,
                threshold: 2.0,
                direction: "below".to_string(),
            }],
            risk_score: 25,
            cooldown_epochs: 5,
        };

        assert!(proposal.validate().is_err());
    }

    #[test]
    fn test_validator_participation_evidence() {
        let evidence = EvidenceType::ValidatorParticipation {
            total_validators: 100,
            active_validators: 150, // Invalid!
            participation_rate: 0.95,
        };

        assert!(evidence.validate().is_err());
    }

    #[test]
    fn test_proposal_id_deterministic() {
        let proposal1 = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Test".to_string(),
            confidence: 0.8,
            evidence: vec![],
            risk_score: 20,
            cooldown_epochs: 2,
        });

        let proposal2 = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Test".to_string(),
            confidence: 0.8,
            evidence: vec![],
            risk_score: 20,
            cooldown_epochs: 2,
        });

        let id1 = proposal1.compute_id();
        let id2 = proposal2.compute_id();

        // Deterministic: same proposal -> same ID
        assert_eq!(id1, id2);
    }
}
