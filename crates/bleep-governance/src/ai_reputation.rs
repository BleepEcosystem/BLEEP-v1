// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// AI Reputation & Accountability - Track AI proposal performance
//
// SAFETY INVARIANTS:
// 1. Reputation scores are deterministically calculated
// 2. AI reputation affects only advisory weighting, never execution
// 3. Reputation history is immutable and auditable
// 4. Poor-performing models lose influence gradually
// 5. Reputation decay is deterministic and epoch-based
// 6. AI cannot artificially inflate its own reputation

use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReputationError {
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    #[error("Invalid reputation score: {0}")]
    InvalidScore(String),

    #[error("History not found")]
    HistoryNotFound,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Outcome of an AI proposal
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalOutcome {
    /// Proposal accepted and activated
    Accepted,

    /// Proposal rejected by validators
    Rejected,

    /// Proposal activated but caused issues
    ActivatedWithIssues,

    /// Proposal was rolled back due to invariant violations
    RolledBack,
}

/// Historical record of an AI proposal performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationRecord {
    /// Proposal ID
    pub proposal_id: String,

    /// AI model ID that created proposal
    pub model_id: String,

    /// Epoch when proposal was submitted
    pub submission_epoch: u64,

    /// Epoch when proposal outcome was recorded
    pub outcome_epoch: u64,

    /// AI's confidence score for the proposal
    pub ai_confidence: u8,

    /// Outcome of the proposal
    pub outcome: ProposalOutcome,

    /// Score impact on reputation (+/- points)
    pub reputation_impact: i32,
}

impl ReputationRecord {
    pub fn new(
        proposal_id: String,
        model_id: String,
        submission_epoch: u64,
        ai_confidence: u8,
    ) -> Self {
        ReputationRecord {
            proposal_id,
            model_id,
            submission_epoch,
            outcome_epoch: submission_epoch, // Updated when outcome is known
            ai_confidence,
            outcome: ProposalOutcome::Rejected,
            reputation_impact: 0,
        }
    }

    /// Record the outcome and calculate reputation impact
    ///
    /// SAFETY: Reputation impact is deterministic based on outcome and confidence
    pub fn record_outcome(&mut self, outcome: ProposalOutcome) {
        self.outcome = outcome;
        self.reputation_impact = Self::calculate_impact(outcome, self.ai_confidence);
    }

    /// Calculate reputation impact from outcome
    ///
    /// SAFETY: This calculation is deterministic and identical on all nodes
    fn calculate_impact(outcome: ProposalOutcome, confidence: u8) -> i32 {
        match outcome {
            // Accepted: +points based on confidence (higher confidence = more reward)
            ProposalOutcome::Accepted => {
                let base_points = 100i32;
                let confidence_multiplier = (confidence as i32 * 100) / 100;
                (base_points * confidence_multiplier) / 100
            }

            // Rejected: -points (less punitive, proposals can be legitimately rejected)
            ProposalOutcome::Rejected => -10i32,

            // Activated but problematic: Medium penalty
            ProposalOutcome::ActivatedWithIssues => {
                let confidence_penalty = (confidence as i32 * 50) / 100;
                -confidence_penalty.max(25)
            }

            // Rolled back: Severe penalty (model made a bad proposal)
            ProposalOutcome::RolledBack => {
                let confidence_penalty = (confidence as i32 * 200) / 100;
                -confidence_penalty.max(100)
            }
        }
    }
}

/// Reputation score for an AI model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIReputation {
    /// Model identifier
    pub model_id: String,

    /// Current reputation score
    pub score: i64,

    /// Total proposals submitted
    pub total_proposals: u64,

    /// Proposals accepted
    pub accepted_count: u64,

    /// Proposals rejected
    pub rejected_count: u64,

    /// Proposals that were activated but had issues
    pub issue_count: u64,

    /// Proposals that were rolled back
    pub rollback_count: u64,

    /// Epoch when reputation was last updated
    pub last_updated_epoch: u64,

    /// Historical records of all proposals
    pub records: Vec<ReputationRecord>,
}

impl AIReputation {
    pub fn new(model_id: String) -> Self {
        AIReputation {
            model_id,
            score: 500, // Start with neutral score
            total_proposals: 0,
            accepted_count: 0,
            rejected_count: 0,
            issue_count: 0,
            rollback_count: 0,
            last_updated_epoch: 0,
            records: Vec::new(),
        }
    }

    /// Add a proposal record and update reputation
    pub fn record_proposal_outcome(&mut self, record: ReputationRecord, current_epoch: u64) {
        self.total_proposals += 1;

        match record.outcome {
            ProposalOutcome::Accepted => self.accepted_count += 1,
            ProposalOutcome::Rejected => self.rejected_count += 1,
            ProposalOutcome::ActivatedWithIssues => self.issue_count += 1,
            ProposalOutcome::RolledBack => self.rollback_count += 1,
        }

        // Update reputation score
        self.score = (self.score as i32 + record.reputation_impact) as i64;

        // Clamp score to reasonable bounds
        self.score = self.score.max(0).min(10_000);

        self.last_updated_epoch = current_epoch;
        self.records.push(record);
    }

    /// Calculate acceptance rate as percentage
    pub fn acceptance_rate(&self) -> f64 {
        if self.total_proposals == 0 {
            return 0.0;
        }
        (self.accepted_count as f64 / self.total_proposals as f64) * 100.0
    }

    /// Calculate reputation weight for advisory votes [0, 100]
    ///
    /// SAFETY: Weight is deterministic based on acceptance rate and score
    /// Higher acceptance = higher weight, but capped for fairness
    pub fn advisory_weight(&self) -> u8 {
        if self.total_proposals == 0 {
            return 50; // Neutral weight for untested models
        }

        let acceptance_rate = self.acceptance_rate();
        let score_factor = (self.score as f64 / 10_000.0) * 100.0;

        // Blend acceptance rate and score
        let weight = (acceptance_rate * 0.7 + score_factor * 0.3) as u8;

        // Cap at 100
        weight.min(100)
    }

    /// Apply exponential decay to reputation
    ///
    /// SAFETY: Decay is deterministic, epoch-based
    /// Older proposals have diminishing impact over time
    pub fn apply_decay(&mut self, current_epoch: u64, decay_rate: u64) {
        let epochs_elapsed = current_epoch.saturating_sub(self.last_updated_epoch);

        if epochs_elapsed == 0 {
            return;
        }

        // Decay formula: score *= (decay_rate / 100) ^ epochs_elapsed
        // Example: decay_rate=95 means 5% decay per epoch
        let decay_multiplier = (decay_rate as f64) / 100.0;
        let new_score = (self.score as f64) * decay_multiplier.powi(epochs_elapsed as i32);

        self.score = new_score.max(0.0) as i64;
    }
}

/// Global AI reputation tracking system
pub struct AIReputationTracker {
    /// Map of model_id -> reputation
    reputations: HashMap<String, AIReputation>,
}

impl AIReputationTracker {
    pub fn new() -> Self {
        AIReputationTracker {
            reputations: HashMap::new(),
        }
    }

    /// Register a new AI model
    pub fn register_model(&mut self, model_id: String) -> Result<(), ReputationError> {
        if self.reputations.contains_key(&model_id) {
            return Err(ReputationError::ModelNotFound(format!(
                "Model {} already registered",
                model_id
            )));
        }

        self.reputations
            .insert(model_id.clone(), AIReputation::new(model_id));
        Ok(())
    }

    /// Get reputation for a model
    pub fn get_reputation(&self, model_id: &str) -> Result<&AIReputation, ReputationError> {
        self.reputations
            .get(model_id)
            .ok_or_else(|| ReputationError::ModelNotFound(model_id.to_string()))
    }

    /// Get mutable reputation (for updates)
    pub fn get_reputation_mut(
        &mut self,
        model_id: &str,
    ) -> Result<&mut AIReputation, ReputationError> {
        self.reputations
            .get_mut(model_id)
            .ok_or_else(|| ReputationError::ModelNotFound(model_id.to_string()))
    }

    /// Record a proposal outcome
    pub fn record_outcome(
        &mut self,
        proposal_id: String,
        model_id: String,
        outcome: ProposalOutcome,
        confidence: u8,
        submission_epoch: u64,
        outcome_epoch: u64,
    ) -> Result<(), ReputationError> {
        // Ensure model is registered
        if !self.reputations.contains_key(&model_id) {
            self.register_model(model_id.clone())?;
        }

        let mut record =
            ReputationRecord::new(proposal_id, model_id.clone(), submission_epoch, confidence);

        record.outcome = outcome;
        record.outcome_epoch = outcome_epoch;
        record.reputation_impact = ReputationRecord::calculate_impact(outcome, confidence);

        let reputation = self.get_reputation_mut(&model_id)?;
        reputation.record_proposal_outcome(record, outcome_epoch);

        info!(
            "Recorded outcome for model {}: {:?} (impact: {})",
            model_id, outcome, reputation.score
        );

        Ok(())
    }

    /// Apply decay to all models' reputations
    pub fn apply_global_decay(&mut self, current_epoch: u64, decay_rate: u64) {
        for reputation in self.reputations.values_mut() {
            reputation.apply_decay(current_epoch, decay_rate);
        }

        info!(
            "Applied reputation decay at epoch {} (rate: {}%)",
            current_epoch, decay_rate
        );
    }

    /// Get aggregate advisory weight for all models
    /// Used for consensus if multiple AI models provide input
    pub fn aggregate_advisory_weight(&self) -> u8 {
        if self.reputations.is_empty() {
            return 50;
        }

        let total_weight: u64 = self
            .reputations
            .values()
            .map(|r| r.advisory_weight() as u64)
            .sum();

        let average = (total_weight / self.reputations.len() as u64) as u8;
        average.min(100)
    }

    /// Get all reputations (for auditing)
    pub fn all_reputations(&self) -> Vec<&AIReputation> {
        self.reputations.values().collect()
    }

    /// Generate audit report for a model
    pub fn audit_report(&self, model_id: &str) -> Result<String, ReputationError> {
        let rep = self.get_reputation(model_id)?;

        let report = format!(
            "=== AI Reputation Audit: {} ===\n\
             Current Score: {}/10000\n\
             Total Proposals: {}\n\
             Accepted: {} ({:.1}%)\n\
             Rejected: {}\n\
             Issues: {}\n\
             Rolled Back: {}\n\
             Advisory Weight: {}/100\n\
             Last Updated: Epoch {}\n",
            rep.model_id,
            rep.score,
            rep.total_proposals,
            rep.accepted_count,
            rep.acceptance_rate(),
            rep.rejected_count,
            rep.issue_count,
            rep.rollback_count,
            rep.advisory_weight(),
            rep.last_updated_epoch
        );

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_creation() {
        let rep = AIReputation::new("test-model".to_string());
        assert_eq!(rep.model_id, "test-model");
        assert_eq!(rep.score, 500);
        assert_eq!(rep.total_proposals, 0);
    }

    #[test]
    fn test_reputation_impact_calculation() {
        let accepted_impact = ReputationRecord::calculate_impact(ProposalOutcome::Accepted, 80);
        let rejected_impact = ReputationRecord::calculate_impact(ProposalOutcome::Rejected, 80);
        let issue_impact =
            ReputationRecord::calculate_impact(ProposalOutcome::ActivatedWithIssues, 80);
        let rollback_impact = ReputationRecord::calculate_impact(ProposalOutcome::RolledBack, 80);

        assert!(accepted_impact > 0);
        assert!(rejected_impact < 0);
        assert!(issue_impact < 0);
        assert!(rollback_impact < 0);
        assert!(rollback_impact < issue_impact); // Rollback worse than issues
    }

    #[test]
    fn test_reputation_tracking() {
        let mut rep = AIReputation::new("model-1".to_string());

        let record = ReputationRecord::new("APIP-001".to_string(), "model-1".to_string(), 1, 75);

        rep.record_proposal_outcome(record, 1);

        assert_eq!(rep.total_proposals, 1);
        assert_eq!(rep.accepted_count, 0); // outcome was default Rejected
    }

    #[test]
    fn test_acceptance_rate() {
        let mut rep = AIReputation::new("model-1".to_string());

        for i in 0..10 {
            let mut record = ReputationRecord::new(
                format!("APIP-{:03}", i),
                "model-1".to_string(),
                i as u64,
                80,
            );

            if i < 7 {
                record.outcome = ProposalOutcome::Accepted;
            } else {
                record.outcome = ProposalOutcome::Rejected;
            }

            rep.record_proposal_outcome(record, i as u64);
        }

        assert_eq!(rep.acceptance_rate(), 70.0);
    }

    #[test]
    fn test_advisory_weight() {
        let mut rep = AIReputation::new("model-1".to_string());

        // Add successful proposals
        for i in 0..10 {
            let mut record = ReputationRecord::new(
                format!("APIP-{:03}", i),
                "model-1".to_string(),
                i as u64,
                85,
            );
            record.outcome = ProposalOutcome::Accepted;
            rep.record_proposal_outcome(record, i as u64);
        }

        let weight = rep.advisory_weight();
        assert!(weight > 50);
        assert!(weight <= 100);
    }

    #[test]
    fn test_reputation_decay() {
        let mut rep = AIReputation::new("model-1".to_string());
        rep.score = 1000;
        rep.last_updated_epoch = 10;

        // Apply 5% decay per epoch for 10 epochs
        rep.apply_decay(20, 95);

        // Score should be reduced but not eliminated
        assert!(rep.score < 1000);
        assert!(rep.score > 0);
    }

    #[test]
    fn test_reputation_tracker() {
        let mut tracker = AIReputationTracker::new();

        tracker.register_model("model-1".to_string()).unwrap();

        let rep = tracker.get_reputation("model-1").unwrap();
        assert_eq!(rep.model_id, "model-1");
    }

    #[test]
    fn test_record_outcome() {
        let mut tracker = AIReputationTracker::new();

        tracker
            .record_outcome(
                "APIP-001".to_string(),
                "model-1".to_string(),
                ProposalOutcome::Accepted,
                80,
                1,
                2,
            )
            .unwrap();

        let rep = tracker.get_reputation("model-1").unwrap();
        assert_eq!(rep.total_proposals, 1);
        assert_eq!(rep.accepted_count, 1);
    }
}
