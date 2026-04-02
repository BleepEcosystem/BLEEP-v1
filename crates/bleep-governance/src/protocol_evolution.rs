// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// Protocol Evolution Orchestrator - Governance integration & activation
//
// SAFETY INVARIANTS:
// 1. Proposals cannot activate without governance approval
// 2. Activation is deterministically epoch-bound
// 3. All honest nodes reach identical activation decisions
// 4. AI has zero execution authority
// 5. Consensus decides, AI only proposes
// 6. Rollback is possible if invariants are violated
// 7. Protocol versions are tracked for fork detection

use crate::ai_reputation::{AIReputationTracker, ProposalOutcome};
use crate::apip::{APIPStatus, APIP};
use crate::protocol_rules::ProtocolRuleSet;
use crate::safety_constraints::{SafetyConstraintsEngine, ValidationReport};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolEvolutionError {
    #[error("Proposal validation failed: {0}")]
    ValidationFailed(String),

    #[error("Governance vote failed: {0}")]
    VotingFailed(String),

    #[error("Activation failed: {0}")]
    ActivationFailed(String),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Unknown proposal: {0}")]
    UnknownProposal(String),

    #[error("Protocol version mismatch")]
    VersionMismatch,

    #[error("Invariant violation: {0}")]
    InvariantViolation(String),
}

impl From<crate::safety_constraints::SafetyConstraintError> for ProtocolEvolutionError {
    fn from(err: crate::safety_constraints::SafetyConstraintError) -> Self {
        ProtocolEvolutionError::ValidationFailed(err.to_string())
    }
}

/// Governance vote on an A-PIP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalVote {
    /// Proposal ID being voted on
    pub proposal_id: String,

    /// Validator who cast vote (public key)
    pub validator: Vec<u8>,

    /// True = approve, False = reject
    pub approval: bool,

    /// Epoch when vote was cast
    pub epoch: u64,
}

/// Voting result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingResult {
    /// Proposal ID
    pub proposal_id: String,

    /// Total votes cast
    pub total_votes: u64,

    /// Votes in favor
    pub votes_for: u64,

    /// Votes against
    pub votes_against: u64,

    /// Percentage approval
    pub approval_percentage: u64,

    /// Whether proposal was approved
    pub approved: bool,

    /// Epoch voting concluded
    pub conclusion_epoch: u64,
}

impl VotingResult {
    pub fn new(proposal_id: String, conclusion_epoch: u64) -> Self {
        VotingResult {
            proposal_id,
            total_votes: 0,
            votes_for: 0,
            votes_against: 0,
            approval_percentage: 0,
            approved: false,
            conclusion_epoch,
        }
    }

    /// Add votes and update result
    pub fn finalize(&mut self, votes_for: u64, votes_against: u64, threshold: u64) {
        self.votes_for = votes_for;
        self.votes_against = votes_against;
        self.total_votes = votes_for + votes_against;

        if self.total_votes > 0 {
            self.approval_percentage = (votes_for * 100) / self.total_votes;
        }

        self.approved = self.approval_percentage >= threshold;
    }
}

/// Activation record for a protocol rule change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationRecord {
    /// Proposal ID that was activated
    pub proposal_id: String,

    /// Rule that was changed
    pub rule_name: String,

    /// Old rule value
    pub old_value: u64,

    /// New rule value
    pub new_value: u64,

    /// Epoch when activated
    pub activation_epoch: u64,

    /// Protocol version after activation
    pub protocol_version: u32,

    /// Block height when activation occurred
    pub activation_height: u64,

    /// Whether activation was later rolled back
    pub was_rolled_back: bool,

    /// Epoch of rollback (if any)
    pub rollback_epoch: Option<u64>,
}

/// Protocol Evolution Orchestrator
///
/// CORE PRINCIPLE: AI proposes. Cryptography verifies. Consensus decides. Epochs activate.
pub struct ProtocolEvolutionOrchestrator {
    /// Current active rule set
    current_ruleset: ProtocolRuleSet,

    /// Map of proposal_id -> APIP
    proposals: HashMap<String, APIP>,

    /// Map of proposal_id -> validation report
    validations: HashMap<String, ValidationReport>,

    /// Map of proposal_id -> voting result
    voting_results: HashMap<String, VotingResult>,

    /// Activation history (immutable record)
    activation_history: Vec<ActivationRecord>,

    /// AI reputation tracker
    ai_reputation: AIReputationTracker,

    /// Current protocol version
    protocol_version: u32,
}

impl ProtocolEvolutionOrchestrator {
    /// Create orchestrator with genesis rule set
    pub fn new(genesis_ruleset: ProtocolRuleSet) -> Self {
        ProtocolEvolutionOrchestrator {
            current_ruleset: genesis_ruleset,
            proposals: HashMap::new(),
            validations: HashMap::new(),
            voting_results: HashMap::new(),
            activation_history: Vec::new(),
            ai_reputation: AIReputationTracker::new(),
            protocol_version: 1,
        }
    }

    /// STEP 1: Submit an A-PIP for validation
    ///
    /// SAFETY: Validates proposal structure and applies safety constraints
    pub fn submit_proposal(
        &mut self,
        mut apip: APIP,
        current_epoch: u64,
    ) -> Result<ValidationReport, ProtocolEvolutionError> {
        // Validate proposal structure
        if !apip.is_complete() {
            return Err(ProtocolEvolutionError::ValidationFailed(
                "A-PIP is incomplete".to_string(),
            ));
        }

        // Validate content hash
        apip.compute_content_hash()
            .map_err(|e| ProtocolEvolutionError::ValidationFailed(e.to_string()))?;

        if !apip
            .verify_content_hash()
            .map_err(|e| ProtocolEvolutionError::ValidationFailed(e.to_string()))?
        {
            return Err(ProtocolEvolutionError::ValidationFailed(
                "Content hash verification failed".to_string(),
            ));
        }

        // Apply machine-verifiable safety constraints
        let validation_report =
            SafetyConstraintsEngine::validate_proposal(&apip, &self.current_ruleset)?;

        // Store proposal and validation
        apip.mark_submitted(current_epoch)
            .map_err(|e| ProtocolEvolutionError::ValidationFailed(e.to_string()))?;

        let proposal_id = apip.proposal_id.clone();
        self.proposals.insert(proposal_id.clone(), apip);
        self.validations
            .insert(proposal_id.clone(), validation_report.clone());

        info!(
            "Proposal {} submitted and validated at epoch {}",
            proposal_id, current_epoch
        );

        Ok(validation_report)
    }

    /// STEP 2: Governance voting (off-chain aggregation)
    ///
    /// SAFETY: Voting threshold determined by risk level
    /// Result is deterministically verifiable
    pub fn record_voting_result(
        &mut self,
        proposal_id: String,
        votes_for: u64,
        votes_against: u64,
        conclusion_epoch: u64,
    ) -> Result<VotingResult, ProtocolEvolutionError> {
        let apip = self
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| ProtocolEvolutionError::UnknownProposal(proposal_id.clone()))?;

        let threshold = apip.risk_level.min_approval_threshold();

        let mut result = VotingResult::new(proposal_id.clone(), conclusion_epoch);
        result.finalize(votes_for, votes_against, threshold);

        self.voting_results
            .insert(proposal_id.clone(), result.clone());

        if result.approved {
            info!(
                "Proposal {} APPROVED with {:.1}% support (threshold: {}%)",
                proposal_id, result.approval_percentage, threshold
            );
        } else {
            info!(
                "Proposal {} REJECTED with only {:.1}% support (threshold: {}%)",
                proposal_id, result.approval_percentage, threshold
            );
        }

        Ok(result)
    }

    /// STEP 3: Activate approved proposal at target epoch
    ///
    /// SAFETY: Activation is deterministic, epoch-bound, and immutable
    pub fn activate_proposal(
        &mut self,
        proposal_id: String,
        current_epoch: u64,
        current_height: u64,
    ) -> Result<Vec<ActivationRecord>, ProtocolEvolutionError> {
        let apip = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or_else(|| ProtocolEvolutionError::UnknownProposal(proposal_id.clone()))?;

        let vote_result = self.voting_results.get(&proposal_id).ok_or_else(|| {
            ProtocolEvolutionError::ActivationFailed("No voting result recorded".to_string())
        })?;

        if !vote_result.approved {
            return Err(ProtocolEvolutionError::ActivationFailed(
                "Proposal was not approved".to_string(),
            ));
        }

        if current_epoch < apip.target_epoch {
            return Err(ProtocolEvolutionError::ActivationFailed(format!(
                "Target epoch {} not yet reached",
                apip.target_epoch
            )));
        }

        let mut activation_records = Vec::new();

        // Apply each rule change
        for change in &apip.rule_changes {
            let old_rule = self
                .current_ruleset
                .get_rule(&change.rule_name)
                .map_err(|e| ProtocolEvolutionError::ActivationFailed(e.to_string()))?;

            let old_value = old_rule.value;

            // Update rule
            let mut rule_copy = old_rule.clone();
            rule_copy
                .update(change.new_value, change.rule_version)
                .map_err(|e| ProtocolEvolutionError::ActivationFailed(e.to_string()))?;

            rule_copy.epoch_activated = current_epoch;

            // Store rule update
            self.current_ruleset
                .rules
                .insert(change.rule_name.clone(), rule_copy);

            // Record activation
            let record = ActivationRecord {
                proposal_id: proposal_id.clone(),
                rule_name: change.rule_name.clone(),
                old_value,
                new_value: change.new_value,
                activation_epoch: current_epoch,
                protocol_version: self.protocol_version,
                activation_height: current_height,
                was_rolled_back: false,
                rollback_epoch: None,
            };

            activation_records.push(record);
        }

        // Update proposal status
        apip.status = APIPStatus::Activated;

        // Increment protocol version
        self.protocol_version += 1;

        // Recompute rule set hash
        self.current_ruleset
            .compute_commitment_hash()
            .map_err(|e| ProtocolEvolutionError::ActivationFailed(e.to_string()))?;

        // Record in history
        self.activation_history.extend(activation_records.clone());

        info!(
            "Proposal {} ACTIVATED at epoch {} with {} rule changes",
            proposal_id,
            current_epoch,
            activation_records.len()
        );

        Ok(activation_records)
    }

    /// STEP 4: Rollback activated changes if invariants are violated
    ///
    /// SAFETY: Rollback is deterministic and leaves immutable audit trail
    pub fn rollback_proposal(
        &mut self,
        proposal_id: String,
        rollback_epoch: u64,
        reason: String,
    ) -> Result<Vec<ActivationRecord>, ProtocolEvolutionError> {
        let apip = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or_else(|| ProtocolEvolutionError::UnknownProposal(proposal_id.clone()))?;

        if apip.status != APIPStatus::Activated {
            return Err(ProtocolEvolutionError::RollbackFailed(
                "Only activated proposals can be rolled back".to_string(),
            ));
        }

        let mut rolledback_records = Vec::new();

        // Find activation records for this proposal
        for record in &mut self.activation_history {
            if record.proposal_id == proposal_id && !record.was_rolled_back {
                // Restore previous rule value
                if let Ok(mut rule) = self.current_ruleset.get_rule(&record.rule_name).cloned() {
                    rule.value = record.old_value;
                    rule.epoch_activated = rollback_epoch;

                    self.current_ruleset
                        .rules
                        .insert(record.rule_name.clone(), rule);
                }

                // Mark as rolled back
                record.was_rolled_back = true;
                record.rollback_epoch = Some(rollback_epoch);

                rolledback_records.push(record.clone());
            }
        }

        // Update proposal status
        apip.status = APIPStatus::RolledBack;

        // Increment protocol version
        self.protocol_version += 1;

        // Recompute rule set hash
        self.current_ruleset
            .compute_commitment_hash()
            .map_err(|e| ProtocolEvolutionError::RollbackFailed(e.to_string()))?;

        warn!(
            "Proposal {} ROLLED BACK at epoch {} (reason: {})",
            proposal_id, rollback_epoch, reason
        );

        Ok(rolledback_records)
    }

    /// Record proposal outcome for AI reputation tracking
    pub fn record_proposal_outcome(
        &mut self,
        proposal_id: String,
        outcome: ProposalOutcome,
        current_epoch: u64,
    ) -> Result<(), ProtocolEvolutionError> {
        let apip = self
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| ProtocolEvolutionError::UnknownProposal(proposal_id.clone()))?;

        self.ai_reputation
            .record_outcome(
                proposal_id,
                apip.ai_model.model_id.clone(),
                outcome,
                apip.confidence_score,
                apip.submission_epoch.unwrap_or(0),
                current_epoch,
            )
            .map_err(|e| ProtocolEvolutionError::ActivationFailed(e.to_string()))?;

        Ok(())
    }

    /// Get current rule set
    pub fn get_ruleset(&self) -> &ProtocolRuleSet {
        &self.current_ruleset
    }

    /// Get proposal
    pub fn get_proposal(&self, proposal_id: &str) -> Option<&APIP> {
        self.proposals.get(proposal_id)
    }

    /// Get validation report
    pub fn get_validation(&self, proposal_id: &str) -> Option<&ValidationReport> {
        self.validations.get(proposal_id)
    }

    /// Get voting result
    pub fn get_voting_result(&self, proposal_id: &str) -> Option<&VotingResult> {
        self.voting_results.get(proposal_id)
    }

    /// Get protocol version
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Apply AI reputation decay (typically once per epoch)
    pub fn apply_reputation_decay(&mut self, current_epoch: u64) {
        let decay_rate = self
            .current_ruleset
            .get_rule_value("AI_REPUTATION_DECAY_RATE")
            .unwrap_or(95);

        self.ai_reputation
            .apply_global_decay(current_epoch, decay_rate);
    }

    /// Get activation history (for auditing)
    pub fn activation_history(&self) -> &[ActivationRecord] {
        &self.activation_history
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apip::{AIModelMetadata, APIPBuilder, RuleChange};
    use crate::protocol_rules::ProtocolRuleSetFactory;

    fn create_test_orchestrator() -> ProtocolEvolutionOrchestrator {
        let genesis = ProtocolRuleSetFactory::create_genesis().unwrap();
        ProtocolEvolutionOrchestrator::new(genesis)
    }

    fn create_test_proposal() -> APIP {
        let model = AIModelMetadata::new(
            "test-model".to_string(),
            "1.0".to_string(),
            "Test".to_string(),
            "Test Org".to_string(),
        );

        APIPBuilder::new(
            "APIP-TEST".to_string(),
            model,
            "Test Proposal".to_string(),
            "Test description".to_string(),
            10,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000,
            1_100_000,
            RuleVersion::new(0, 1, 0),
            "Minor increase".to_string(),
        ))
        .unwrap()
        .confidence(75)
        .unwrap()
        .risk(RiskLevel::Low, "Minimal impact".to_string())
        .unwrap()
        .expected_impact("Better sharding".to_string())
        .unwrap()
        .rollback_strategy("Revert value".to_string())
        .unwrap()
        .ai_signature(vec![1, 2, 3])
        .unwrap()
        .build()
        .unwrap()
    }

    #[test]
    fn test_orchestrator_creation() {
        let orchestrator = create_test_orchestrator();
        assert_eq!(orchestrator.protocol_version(), 1);
    }

    #[test]
    fn test_proposal_submission() {
        let mut orchestrator = create_test_orchestrator();
        let proposal = create_test_proposal();

        let report = orchestrator.submit_proposal(proposal, 1).unwrap();
        assert!(report.is_valid);
    }

    #[test]
    fn test_voting_result() {
        let mut orchestrator = create_test_orchestrator();
        let proposal = create_test_proposal();

        orchestrator.submit_proposal(proposal, 1).unwrap();

        let result = orchestrator
            .record_voting_result("APIP-TEST".to_string(), 100, 50, 2)
            .unwrap();

        assert!(result.approved);
        assert_eq!(result.approval_percentage, 66);
    }
}
