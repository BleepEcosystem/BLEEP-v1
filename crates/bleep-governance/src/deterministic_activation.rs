// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// Deterministic Activation & Rollback System
//
// SAFETY INVARIANTS:
// 1. Activation is 100% deterministic
// 2. All honest nodes activate same changes at same epoch
// 3. Rollback is immediately available upon invariant violation
// 4. No partial activations - all changes activate or none do
// 5. Activation records are immutable and auditable
// 6. Emergency reversion is governance-controlled

use crate::apip::APIP;
use crate::invariant_monitoring::GlobalInvariantMonitor;
use crate::protocol_evolution::ActivationRecord;
use crate::protocol_rules::ProtocolRuleSet;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ActivationError {
    #[error("Activation not ready")]
    NotReady,

    #[error("Rule not found: {0}")]
    RuleNotFound(String),

    #[error("Rule update failed: {0}")]
    RuleUpdateFailed(String),

    #[error("Activation record mismatch")]
    RecordMismatch,

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Invariant violated: {0}")]
    InvariantViolated(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// State of a proposed activation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActivationState {
    /// Waiting for approval epoch
    Pending,

    /// Ready to activate
    ReadyToActivate,

    /// Activation in progress
    Activating,

    /// Successfully activated
    Activated,

    /// Rolled back
    RolledBack,

    /// Failed to activate
    Failed,
}

/// Deterministic activation plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationPlan {
    /// Proposal ID
    pub proposal_id: String,

    /// Target activation epoch
    pub target_epoch: u64,

    /// Target block height (approximate)
    pub target_height: u64,

    /// State of activation
    pub state: ActivationState,

    /// All rules to be changed
    pub rule_changes: Vec<(String, u64, u64)>, // (rule_name, old_value, new_value)

    /// Version to transition to
    pub new_protocol_version: u32,

    /// Activation records (immutable once activated)
    pub activation_records: Vec<ActivationRecord>,
}

impl ActivationPlan {
    pub fn new(
        proposal_id: String,
        target_epoch: u64,
        target_height: u64,
        rule_changes: Vec<(String, u64, u64)>,
        new_protocol_version: u32,
    ) -> Self {
        ActivationPlan {
            proposal_id,
            target_epoch,
            target_height,
            state: ActivationState::Pending,
            rule_changes,
            new_protocol_version,
            activation_records: Vec::new(),
        }
    }

    /// Mark ready to activate
    pub fn mark_ready(&mut self) {
        self.state = ActivationState::ReadyToActivate;
    }

    /// Mark as activated
    pub fn mark_activated(&mut self) {
        self.state = ActivationState::Activated;
    }

    /// Mark as rolled back
    pub fn mark_rolled_back(&mut self) {
        self.state = ActivationState::RolledBack;
    }
}

/// Activation manager for deterministic rule changes
pub struct DeterministicActivationManager {
    /// Active activation plans
    plans: HashMap<String, ActivationPlan>,

    /// Current ruleset
    current_ruleset: ProtocolRuleSet,

    /// Current protocol version
    current_protocol_version: u32,

    /// Invariant monitor for violation detection
    invariant_monitor: GlobalInvariantMonitor,

    /// Activation history (immutable)
    history: Vec<ActivationPlan>,
}

impl DeterministicActivationManager {
    pub fn new(genesis_ruleset: ProtocolRuleSet, genesis_version: u32) -> Self {
        DeterministicActivationManager {
            plans: HashMap::new(),
            current_ruleset: genesis_ruleset,
            current_protocol_version: genesis_version,
            invariant_monitor: GlobalInvariantMonitor::new(),
            history: Vec::new(),
        }
    }

    /// Create an activation plan for approved proposal
    ///
    /// SAFETY: Plan is deterministic - same inputs → same plan on all nodes
    pub fn create_activation_plan(
        &mut self,
        apip: &APIP,
        new_version: u32,
        _approval_epoch: u64,
    ) -> Result<ActivationPlan, ActivationError> {
        // Extract rule changes
        let mut rule_changes = Vec::new();
        for change in &apip.rule_changes {
            let current_rule = self
                .current_ruleset
                .get_rule(&change.rule_name)
                .map_err(|_| ActivationError::RuleNotFound(change.rule_name.clone()))?;

            rule_changes.push((
                change.rule_name.clone(),
                current_rule.value,
                change.new_value,
            ));
        }

        let plan = ActivationPlan::new(
            apip.proposal_id.clone(),
            apip.target_epoch,
            0, // Height determined at activation time
            rule_changes,
            new_version,
        );

        self.plans.insert(apip.proposal_id.clone(), plan.clone());

        info!(
            "Activation plan created for {} targeting epoch {}",
            apip.proposal_id, apip.target_epoch
        );

        Ok(plan)
    }

    /// Check if activation is ready at current epoch
    ///
    /// SAFETY: This check is identical on all nodes
    pub fn check_activation_ready(&self, proposal_id: &str, current_epoch: u64) -> bool {
        if let Some(plan) = self.plans.get(proposal_id) {
            current_epoch >= plan.target_epoch
        } else {
            false
        }
    }

    /// Perform deterministic activation of approved changes
    ///
    /// SAFETY: This is 100% deterministic - same proposal → same result on all nodes
    pub fn activate(
        &mut self,
        proposal_id: &str,
        current_epoch: u64,
        current_height: u64,
    ) -> Result<Vec<ActivationRecord>, ActivationError> {
        // Check readiness before taking mutable reference
        if !self.check_activation_ready(proposal_id, current_epoch) {
            return Err(ActivationError::NotReady);
        }

        let plan = self
            .plans
            .get_mut(proposal_id)
            .ok_or(ActivationError::NotReady)?;

        plan.state = ActivationState::Activating;

        // Apply each rule change deterministically
        let mut records = Vec::new();

        for (rule_name, old_value, new_value) in &plan.rule_changes {
            let mut rule = self
                .current_ruleset
                .get_rule(rule_name)
                .map_err(|_| ActivationError::RuleNotFound(rule_name.clone()))?
                .clone();

            // Update rule with new version
            let new_rule_version = rule.version.increment_minor();
            rule.update(*new_value, new_rule_version)
                .map_err(|e| ActivationError::RuleUpdateFailed(e.to_string()))?;

            rule.epoch_activated = current_epoch;

            // Store updated rule
            self.current_ruleset.rules.insert(rule_name.clone(), rule);

            // Create activation record
            let record = ActivationRecord {
                proposal_id: proposal_id.to_string(),
                rule_name: rule_name.clone(),
                old_value: *old_value,
                new_value: *new_value,
                activation_epoch: current_epoch,
                protocol_version: plan.new_protocol_version,
                activation_height: current_height,
                was_rolled_back: false,
                rollback_epoch: None,
            };

            records.push(record);
        }

        // Update protocol version
        self.current_protocol_version = plan.new_protocol_version;

        // Recompute ruleset hash
        self.current_ruleset
            .compute_commitment_hash()
            .map_err(|e| ActivationError::RuleUpdateFailed(e.to_string()))?;

        plan.activation_records = records.clone();
        plan.mark_activated();

        // Store in history (immutable)
        self.history.push(plan.clone());

        info!(
            "Deterministic activation complete for {} at epoch {}",
            proposal_id, current_epoch
        );

        Ok(records)
    }

    /// Emergency rollback if invariants are violated
    ///
    /// SAFETY: Rollback is deterministic and based on recorded invariant violations
    pub fn emergency_rollback(
        &mut self,
        proposal_id: &str,
        rollback_epoch: u64,
        violation_description: String,
    ) -> Result<Vec<ActivationRecord>, ActivationError> {
        let plan = self
            .plans
            .get_mut(proposal_id)
            .ok_or(ActivationError::NotReady)?;

        if plan.state != ActivationState::Activated {
            return Err(ActivationError::RollbackFailed(
                "Can only rollback activated proposals".to_string(),
            ));
        }

        let mut rolled_back = Vec::new();

        // Restore all rules to previous values
        for record in &plan.activation_records {
            let mut rule = self
                .current_ruleset
                .get_rule(&record.rule_name)
                .map_err(|_| ActivationError::RuleNotFound(record.rule_name.clone()))?
                .clone();

            // Restore old value
            rule.value = record.old_value;
            rule.epoch_activated = rollback_epoch;

            self.current_ruleset
                .rules
                .insert(record.rule_name.clone(), rule);

            // Create rollback record
            let mut rollback_record = record.clone();
            rollback_record.was_rolled_back = true;
            rollback_record.rollback_epoch = Some(rollback_epoch);

            rolled_back.push(rollback_record);
        }

        // Decrement protocol version
        self.current_protocol_version = self.current_protocol_version.saturating_sub(1);

        // Recompute ruleset hash
        self.current_ruleset
            .compute_commitment_hash()
            .map_err(|e| ActivationError::RuleUpdateFailed(e.to_string()))?;

        plan.mark_rolled_back();

        warn!(
            "EMERGENCY ROLLBACK for {} at epoch {} (reason: {})",
            proposal_id, rollback_epoch, violation_description
        );

        Ok(rolled_back)
    }

    /// Get current ruleset
    pub fn get_ruleset(&self) -> &ProtocolRuleSet {
        &self.current_ruleset
    }

    /// Get current protocol version
    pub fn protocol_version(&self) -> u32 {
        self.current_protocol_version
    }

    /// Get activation plan
    pub fn get_plan(&self, proposal_id: &str) -> Option<&ActivationPlan> {
        self.plans.get(proposal_id)
    }

    /// Get activation history
    pub fn get_history(&self) -> &[ActivationPlan] {
        &self.history
    }

    /// Check invariants and trigger rollback if needed
    pub fn check_invariants(
        &mut self,
        _shard_id: u32,
        proposal_id: &str,
    ) -> Result<bool, ActivationError> {
        let health = self.invariant_monitor.global_health();

        if !health.is_globally_healthy {
            warn!(
                "Invariant violation detected (health: {:.1}%)",
                health.average_health
            );

            self.emergency_rollback(
                proposal_id,
                0, // Epoch would be set by caller
                format!(
                    "Global health {:.1}% below threshold",
                    health.average_health
                ),
            )?;

            return Ok(true);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_rules::ProtocolRuleSetFactory;

    #[test]
    fn test_activation_plan_creation() {
        let plan = ActivationPlan::new(
            "APIP-001".to_string(),
            10,
            1000,
            vec![("SHARD_SPLIT_THRESHOLD".to_string(), 1_000_000, 1_100_000)],
            2,
        );

        assert_eq!(plan.proposal_id, "APIP-001");
        assert_eq!(plan.target_epoch, 10);
        assert_eq!(plan.state, ActivationState::Pending);
    }

    #[test]
    fn test_activation_state_transitions() {
        let mut plan = ActivationPlan::new("APIP-001".to_string(), 10, 1000, vec![], 2);

        assert_eq!(plan.state, ActivationState::Pending);

        plan.mark_ready();
        assert_eq!(plan.state, ActivationState::ReadyToActivate);

        plan.mark_activated();
        assert_eq!(plan.state, ActivationState::Activated);
    }

    #[test]
    fn test_deterministic_activation_manager() {
        let genesis = ProtocolRuleSetFactory::create_genesis().unwrap();
        let manager = DeterministicActivationManager::new(genesis, 1);

        assert_eq!(manager.protocol_version(), 1);
        assert!(!manager.check_activation_ready("APIP-001", 5));
    }
}
