/// AI Integration with Consensus and Self-Healing
///
/// This module connects AI proposals to the consensus engine and self-healing system.
///
/// FLOW:
/// 1. AI generates proposal + attestation
/// 2. Constraints validate proposal
/// 3. Proposal enters consensus pool
/// 4. Consensus votes on proposal
/// 5. If approved, self-healing system executes (if applicable)
/// 6. Outcome is tracked for AI performance feedback
///
/// KEY INVARIANT:
/// AI never directly executes. It only proposes.
/// Execution requires consensus approval.
use crate::ai_attestation::AIAttestationRecord;
use crate::ai_proposal_types::AIProposal;
use crate::deterministic_inference::InferenceRecord;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ==================== ERROR TYPES ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrationError {
    ProposalNotAttested(String),
    ConsensusRejected(String),
    HealingNotApplicable(String),
    ExecutionError(String),
    InvalidState(String),
}

impl fmt::Display for IntegrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProposalNotAttested(msg) => write!(f, "Proposal not attested: {}", msg),
            Self::ConsensusRejected(msg) => write!(f, "Consensus rejected: {}", msg),
            Self::HealingNotApplicable(msg) => write!(f, "Healing not applicable: {}", msg),
            Self::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            Self::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
        }
    }
}

impl std::error::Error for IntegrationError {}

/// Result type for consensus integration operations
pub type IntegrationResult<T> = Result<T, IntegrationError>;

// ==================== PROPOSAL LIFECYCLE ====================

/// Track proposal through consensus and execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalState {
    /// Proposed by AI
    Proposed,

    /// In consensus pool
    InConsensus,

    /// Approved by consensus
    Approved,

    /// Rejected by consensus
    Rejected,

    /// Executing (if applicable)
    Executing,

    /// Successfully executed
    Executed,

    /// Execution failed
    ExecutionFailed,

    /// Cancelled/reverted
    Cancelled,
}

/// Track outcome of a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalOutcome {
    /// Proposal ID
    pub proposal_id: String,

    /// Type of proposal
    pub proposal_type: String,

    /// Current state
    pub state: ProposalState,

    /// Epoch proposed
    pub epoch_proposed: u64,

    /// Epoch decided (if applicable)
    pub epoch_decided: Option<u64>,

    /// Epoch executed (if applicable)
    pub epoch_executed: Option<u64>,

    /// Consensus votes for
    pub votes_for: u32,

    /// Consensus votes against
    pub votes_against: u32,

    /// Whether AI was correct
    pub ai_accuracy: Option<bool>,

    /// Notes
    pub notes: String,
}

impl ProposalOutcome {
    /// Create new outcome
    pub fn new(proposal_id: String, proposal_type: String, epoch: u64) -> Self {
        Self {
            proposal_id,
            proposal_type,
            state: ProposalState::Proposed,
            epoch_proposed: epoch,
            epoch_decided: None,
            epoch_executed: None,
            votes_for: 0,
            votes_against: 0,
            ai_accuracy: None,
            notes: String::new(),
        }
    }

    /// Mark as in consensus
    pub fn mark_in_consensus(&mut self) {
        self.state = ProposalState::InConsensus;
    }

    /// Mark as approved
    pub fn mark_approved(&mut self, votes_for: u32, votes_against: u32, epoch: u64) {
        self.state = ProposalState::Approved;
        self.votes_for = votes_for;
        self.votes_against = votes_against;
        self.epoch_decided = Some(epoch);
    }

    /// Mark as rejected
    pub fn mark_rejected(&mut self, votes_for: u32, votes_against: u32, epoch: u64) {
        self.state = ProposalState::Rejected;
        self.votes_for = votes_for;
        self.votes_against = votes_against;
        self.epoch_decided = Some(epoch);
    }

    /// Mark as executing
    pub fn mark_executing(&mut self) {
        self.state = ProposalState::Executing;
    }

    /// Mark as executed
    pub fn mark_executed(&mut self, epoch: u64) {
        self.state = ProposalState::Executed;
        self.epoch_executed = Some(epoch);
    }

    /// Mark as failed
    pub fn mark_failed(&mut self, error: String) {
        self.state = ProposalState::ExecutionFailed;
        self.notes = error;
    }

    /// Record AI accuracy (for feedback loop)
    pub fn record_accuracy(&mut self, was_correct: bool) {
        self.ai_accuracy = Some(was_correct);
    }
}

// ==================== CONSENSUS PROPOSAL ====================

/// A proposal entering the consensus pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposal {
    /// The AI proposal
    pub ai_proposal: AIProposal,

    /// Attestation record
    pub attestation: AIAttestationRecord,

    /// Inference record
    pub inference: InferenceRecord,

    /// Whether constraints passed
    pub constraints_passed: bool,

    /// List of passed constraints
    pub passed_constraints: Vec<String>,

    /// Activation epoch
    pub activation_epoch: u64,

    /// Timeout epoch (after which proposal expires)
    pub timeout_epoch: u64,
}

impl ConsensusProposal {
    /// Create new consensus proposal
    pub fn new(
        ai_proposal: AIProposal,
        attestation: AIAttestationRecord,
        inference: InferenceRecord,
        constraints_passed: bool,
        passed_constraints: Vec<String>,
        activation_epoch: u64,
        current_epoch: u64,
    ) -> Self {
        let timeout_epoch = current_epoch + 50; // 50 epoch timeout

        Self {
            ai_proposal,
            attestation,
            inference,
            constraints_passed,
            passed_constraints,
            activation_epoch,
            timeout_epoch,
        }
    }

    /// Check if proposal is still valid
    pub fn is_valid(&self, current_epoch: u64) -> bool {
        current_epoch < self.timeout_epoch && self.constraints_passed
    }
}

// ==================== HEALING INTEGRATION ====================

/// Actions that can trigger self-healing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealingAction {
    /// Rollback a shard to checkpoint
    ShardRollback {
        shard_id: u32,
        checkpoint_height: u64,
    },

    /// Rebalance validators across shards
    ShardRebalance {
        affected_shards: Vec<u32>,
        new_distribution: BTreeMap<u32, u32>,
    },

    /// Isolate or remove validator
    ValidatorIsolation { validator_id: String },

    /// Restart healing for a shard
    RestartHealing { shard_id: u32 },

    /// Adjust consensus parameters
    ParameterAdjustment { parameter: String, new_value: u64 },
}

/// Track healing execution linked to AI proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingExecution {
    /// ID of triggering proposal
    pub proposal_id: String,

    /// Healing action
    pub action: HealingAction,

    /// Epoch healing started
    pub epoch_started: u64,

    /// Epoch healing completed (if applicable)
    pub epoch_completed: Option<u64>,

    /// Status
    pub status: HealingStatus,

    /// Evidence of completion
    pub completion_evidence: Option<String>,

    /// Metrics before healing
    pub metrics_before: BTreeMap<String, f32>,

    /// Metrics after healing
    pub metrics_after: BTreeMap<String, f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealingStatus {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Cancelled,
}

// ==================== CONSENSUS + HEALING ORCHESTRATOR ====================

/// Orchestrates AI proposal flow through consensus and healing
pub struct AIConsensusOrchestrator {
    /// Active proposals (proposal_id -> proposal)
    active_proposals: BTreeMap<String, ConsensusProposal>,

    /// Proposal outcomes (proposal_id -> outcome)
    outcomes: BTreeMap<String, ProposalOutcome>,

    /// Healing executions linked to proposals
    healing_executions: BTreeMap<String, HealingExecution>,

    /// Current epoch
    current_epoch: u64,
}

impl AIConsensusOrchestrator {
    /// Create new orchestrator
    pub fn new(current_epoch: u64) -> Self {
        Self {
            active_proposals: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            healing_executions: BTreeMap::new(),
            current_epoch,
        }
    }

    /// Submit AI proposal to consensus
    pub fn submit_proposal(&mut self, proposal: ConsensusProposal) -> IntegrationResult<String> {
        // Verify proposal is properly attested
        if !proposal.attestation.verified {
            return Err(IntegrationError::ProposalNotAttested(
                "Attestation not verified".to_string(),
            ));
        }

        // Verify constraints passed
        if !proposal.constraints_passed {
            return Err(IntegrationError::ProposalNotAttested(
                "Constraints not passed".to_string(),
            ));
        }

        let proposal_id = proposal.ai_proposal.compute_id();

        // Create outcome record
        let outcome = ProposalOutcome::new(
            proposal_id.clone(),
            match &proposal.ai_proposal {
                AIProposal::ConsensusModeSwitch(_) => "ConsensusModeSwitch".to_string(),
                AIProposal::ShardRollback(_) => "ShardRollback".to_string(),
                AIProposal::ShardRebalance(_) => "ShardRebalance".to_string(),
                AIProposal::ValidatorSecurity(_) => "ValidatorSecurity".to_string(),
                AIProposal::TokenomicsAdjustment(_) => "TokenomicsAdjustment".to_string(),
                AIProposal::GovernancePriority(_) => "GovernancePriority".to_string(),
            },
            self.current_epoch,
        );

        self.outcomes.insert(proposal_id.clone(), outcome);
        self.active_proposals.insert(proposal_id.clone(), proposal);

        Ok(proposal_id)
    }

    /// Record consensus decision
    pub fn record_consensus_decision(
        &mut self,
        proposal_id: &str,
        approved: bool,
        votes_for: u32,
        votes_against: u32,
    ) -> IntegrationResult<()> {
        let outcome = self.outcomes.get_mut(proposal_id).ok_or_else(|| {
            IntegrationError::InvalidState(format!("Proposal not found: {}", proposal_id))
        })?;

        if approved {
            outcome.mark_approved(votes_for, votes_against, self.current_epoch);
        } else {
            outcome.mark_rejected(votes_for, votes_against, self.current_epoch);
        }

        Ok(())
    }

    /// Start healing execution for approved proposal
    pub fn start_healing(
        &mut self,
        proposal_id: &str,
        action: HealingAction,
    ) -> IntegrationResult<()> {
        let outcome = self.outcomes.get(proposal_id).ok_or_else(|| {
            IntegrationError::InvalidState(format!("Proposal not found: {}", proposal_id))
        })?;

        if outcome.state != ProposalState::Approved {
            return Err(IntegrationError::HealingNotApplicable(
                "Proposal not approved".to_string(),
            ));
        }

        let execution = HealingExecution {
            proposal_id: proposal_id.to_string(),
            action,
            epoch_started: self.current_epoch,
            epoch_completed: None,
            status: HealingStatus::InProgress,
            completion_evidence: None,
            metrics_before: BTreeMap::new(),
            metrics_after: BTreeMap::new(),
        };

        self.healing_executions
            .insert(proposal_id.to_string(), execution);

        Ok(())
    }

    /// Complete healing execution
    pub fn complete_healing(
        &mut self,
        proposal_id: &str,
        success: bool,
        metrics_after: BTreeMap<String, f32>,
    ) -> IntegrationResult<()> {
        let execution = self
            .healing_executions
            .get_mut(proposal_id)
            .ok_or_else(|| {
                IntegrationError::InvalidState(format!("Healing not in progress: {}", proposal_id))
            })?;

        execution.epoch_completed = Some(self.current_epoch);
        execution.status = if success {
            HealingStatus::Succeeded
        } else {
            HealingStatus::Failed
        };
        execution.metrics_after = metrics_after;

        // Update outcome
        if let Some(outcome) = self.outcomes.get_mut(proposal_id) {
            if success {
                outcome.mark_executed(self.current_epoch);
            } else {
                outcome.mark_failed("Healing failed".to_string());
            }
        }

        Ok(())
    }

    /// Record AI accuracy
    pub fn record_ai_accuracy(&mut self, proposal_id: &str, was_correct: bool) {
        if let Some(outcome) = self.outcomes.get_mut(proposal_id) {
            outcome.record_accuracy(was_correct);
        }
    }

    /// Get proposal outcome
    pub fn get_outcome(&self, proposal_id: &str) -> Option<ProposalOutcome> {
        self.outcomes.get(proposal_id).cloned()
    }

    /// Get all outcomes
    pub fn get_all_outcomes(&self) -> Vec<ProposalOutcome> {
        self.outcomes.values().cloned().collect()
    }

    /// Update epoch
    pub fn update_epoch(&mut self, new_epoch: u64) {
        self.current_epoch = new_epoch;
    }

    /// Get statistics
    pub fn get_stats(&self) -> OrchestrationStats {
        let total_proposals = self.outcomes.len();
        let approved = self
            .outcomes
            .values()
            .filter(|o| o.state == ProposalState::Approved)
            .count();
        let executed = self
            .outcomes
            .values()
            .filter(|o| o.state == ProposalState::Executed)
            .count();
        let ai_correct = self
            .outcomes
            .values()
            .filter(|o| o.ai_accuracy == Some(true))
            .count();

        OrchestrationStats {
            total_proposals,
            approved_proposals: approved,
            executed_proposals: executed,
            ai_correct_predictions: ai_correct,
        }
    }
}

/// Statistics about orchestration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationStats {
    pub total_proposals: usize,
    pub approved_proposals: usize,
    pub executed_proposals: usize,
    pub ai_correct_predictions: usize,
}

// ==================== TESTS ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proposal_outcome_lifecycle() {
        let mut outcome =
            ProposalOutcome::new("prop1".to_string(), "ConsensusModeSwitch".to_string(), 10);

        assert_eq!(outcome.state, ProposalState::Proposed);

        outcome.mark_in_consensus();
        assert_eq!(outcome.state, ProposalState::InConsensus);

        outcome.mark_approved(80, 20, 15);
        assert_eq!(outcome.state, ProposalState::Approved);
        assert_eq!(outcome.votes_for, 80);

        outcome.mark_executed(20);
        assert_eq!(outcome.state, ProposalState::Executed);
    }

    #[test]
    fn test_orchestrator_basic_flow() {
        let mut orchestrator = AIConsensusOrchestrator::new(0);

        let stats = orchestrator.get_stats();
        assert_eq!(stats.total_proposals, 0);
    }
}
