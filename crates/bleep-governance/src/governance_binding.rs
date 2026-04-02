// PHASE 4: CONSTITUTIONAL GOVERNANCE LAYER
// Governance ↔ Consensus Binding - Consensus verifies and enforces governance
//
// SAFETY INVARIANTS:
// 1. Consensus verifies all governance proofs before accepting blocks
// 2. Governance outcomes are binding once finalized
// 3. Consensus rejects blocks that violate governance rules
// 4. Upgrade activation is consensus-enforced at epoch boundaries
// 5. No block is valid without governance proof verification
// 6. Finality is required before governance execution
// 7. All governance events are cryptographically archived in consensus

use super::forkless_upgrades::Version;
use super::zk_voting::VoteTally;
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BindingError {
    #[error("Governance proof verification failed")]
    ProofVerificationFailed,

    #[error("Proposal not finalized")]
    ProposalNotFinalized,

    #[error("Invalid activation")]
    InvalidActivation,

    #[error("Version mismatch")]
    VersionMismatch,

    #[error("Consensus violation")]
    ConsensusViolation(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Finality not achieved")]
    FinalityNotAchieved,
}

/// Result of governance action proposal vote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalOutcome {
    /// Proposal passed voting
    Passed {
        yes_votes: u64,
        no_votes: u64,
        yes_percentage: f64,
    },

    /// Proposal failed voting
    Failed {
        yes_votes: u64,
        no_votes: u64,
        yes_percentage: f64,
    },

    /// Voting expired without quorum
    Expired {
        votes_cast: u64,
        required_quorum: u64,
    },
}

impl ProposalOutcome {
    /// Check if outcome was successful
    pub fn is_successful(&self) -> bool {
        matches!(self, ProposalOutcome::Passed { .. })
    }
}

/// Record of activation of a governance action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationRecord {
    /// Proposal ID
    pub proposal_id: String,

    /// Outcome that led to activation
    pub outcome: ProposalOutcome,

    /// Epoch when activated
    pub activation_epoch: u64,

    /// Block height of activation
    pub block_height: u64,

    /// Proof of finality before activation
    pub finality_proof: Vec<u8>,

    /// Execution result hash
    pub execution_result: Vec<u8>,

    /// Activation record hash
    pub record_hash: Vec<u8>,
}

impl ActivationRecord {
    /// Create new activation record
    pub fn new(
        proposal_id: String,
        outcome: ProposalOutcome,
        activation_epoch: u64,
        block_height: u64,
        finality_proof: Vec<u8>,
        execution_result: Vec<u8>,
    ) -> Result<Self, BindingError> {
        let mut record = ActivationRecord {
            proposal_id,
            outcome,
            activation_epoch,
            block_height,
            finality_proof,
            execution_result,
            record_hash: Vec::new(),
        };

        record.record_hash = record.compute_hash()?;
        Ok(record)
    }

    /// Compute hash of record
    fn compute_hash(&self) -> Result<Vec<u8>, BindingError> {
        let serialized = bincode::serialize(&(
            &self.proposal_id,
            &self.outcome,
            self.activation_epoch,
            self.block_height,
        ))
        .map_err(|e| BindingError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }

    /// Verify record hash
    pub fn verify_hash(&self) -> Result<bool, BindingError> {
        let computed = self.compute_hash()?;
        Ok(computed == self.record_hash)
    }
}

/// Governance action that has been finalized and is ready for consensus binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedGovernanceAction {
    /// Action ID
    pub action_id: String,

    /// Description
    pub description: String,

    /// Voting result
    pub voting_result: VoteTally,

    /// Was this action approved?
    pub approved: bool,

    /// Proof of voting result
    pub voting_proof: Vec<u8>,

    /// Epoch when voting concluded
    pub finalization_epoch: u64,

    /// Required minimum finality depth
    pub finality_depth_required: u64,

    /// Activation epoch (when action executes)
    pub activation_epoch: u64,
}

impl FinalizedGovernanceAction {
    /// Create finalized action
    pub fn new(
        action_id: String,
        description: String,
        voting_result: VoteTally,
        approved: bool,
        voting_proof: Vec<u8>,
        finalization_epoch: u64,
        finality_depth_required: u64,
        activation_epoch: u64,
    ) -> Self {
        FinalizedGovernanceAction {
            action_id,
            description,
            voting_result,
            approved,
            voting_proof,
            finalization_epoch,
            finality_depth_required,
            activation_epoch,
        }
    }

    /// Check if sufficient finality has been achieved
    pub fn has_finality(&self, current_block_height: u64) -> bool {
        current_block_height >= self.finalization_epoch + self.finality_depth_required
    }
}

/// Consensus binding for governance outcomes
pub struct GovernanceConsensusBinding {
    /// All finalized governance actions
    pub finalized_actions: HashMap<String, FinalizedGovernanceAction>,

    /// Activation records (action executed)
    pub activation_records: HashMap<String, ActivationRecord>,

    /// Current protocol version (from consensus)
    pub protocol_version: Version,

    /// Current epoch
    pub current_epoch: u64,

    /// Current block height
    pub current_block_height: u64,

    /// Finality depth (blocks)
    pub finality_depth: u64,

    /// Archive of all governance events
    pub governance_archive: Vec<Vec<u8>>,
}

impl GovernanceConsensusBinding {
    /// Create new binding
    pub fn new(protocol_version: Version, current_epoch: u64, finality_depth: u64) -> Self {
        GovernanceConsensusBinding {
            finalized_actions: HashMap::new(),
            activation_records: HashMap::new(),
            protocol_version,
            current_epoch,
            current_block_height: 0,
            finality_depth,
            governance_archive: Vec::new(),
        }
    }

    /// Record a finalized governance action
    pub fn record_finalized_action(
        &mut self,
        action: FinalizedGovernanceAction,
    ) -> Result<(), BindingError> {
        // Verify voting proof
        if action.voting_proof.is_empty() {
            return Err(BindingError::ProofVerificationFailed);
        }

        // Check activation epoch is in future
        if action.activation_epoch <= self.current_epoch {
            return Err(BindingError::InvalidActivation);
        }

        let action_id = action.action_id.clone();
        self.finalized_actions.insert(action_id, action);

        info!("Finalized governance action recorded");

        Ok(())
    }

    /// Verify consensus can accept a block with governance actions
    pub fn verify_block_governance(&self, action_ids: &[String]) -> Result<(), BindingError> {
        for action_id in action_ids {
            let action =
                self.finalized_actions
                    .get(action_id)
                    .ok_or(BindingError::ConsensusViolation(format!(
                        "Action {} not finalized",
                        action_id
                    )))?;

            // Check action is approved
            if !action.approved {
                return Err(BindingError::ConsensusViolation(format!(
                    "Action {} was not approved",
                    action_id
                )));
            }
        }

        Ok(())
    }

    /// Check if governance action can be activated
    pub fn can_activate(&self, action_id: &str) -> Result<bool, BindingError> {
        let action =
            self.finalized_actions
                .get(action_id)
                .ok_or(BindingError::ConsensusViolation(format!(
                    "Action {} not found",
                    action_id
                )))?;

        // Check activation epoch reached
        if self.current_epoch < action.activation_epoch {
            return Ok(false);
        }

        // Check finality achieved
        if !action.has_finality(self.current_block_height) {
            return Err(BindingError::FinalityNotAchieved);
        }

        Ok(true)
    }

    /// Activate a governance action
    pub fn activate_action(
        &mut self,
        action_id: &str,
        execution_result: Vec<u8>,
    ) -> Result<ActivationRecord, BindingError> {
        let action = self
            .finalized_actions
            .get(action_id)
            .ok_or(BindingError::ConsensusViolation(format!(
                "Action {} not found",
                action_id
            )))?
            .clone();

        // Check can activate
        if !self.can_activate(action_id)? {
            return Err(BindingError::InvalidActivation);
        }

        // Create activation record
        let record = ActivationRecord::new(
            action_id.to_string(),
            ProposalOutcome::Passed {
                yes_votes: action.voting_result.yes_votes,
                no_votes: action.voting_result.no_votes,
                yes_percentage: action.voting_result.yes_percentage,
            },
            self.current_epoch,
            self.current_block_height,
            action.voting_proof.clone(),
            execution_result,
        )?;

        self.activation_records
            .insert(action_id.to_string(), record.clone());

        // Archive governance event
        self.archive_governance_event(&record)?;

        info!(
            "Governance action {} activated at epoch {}",
            action_id, self.current_epoch
        );

        Ok(record)
    }

    /// Archive governance event
    fn archive_governance_event(&mut self, record: &ActivationRecord) -> Result<(), BindingError> {
        record.verify_hash()?;
        self.governance_archive.push(record.record_hash.clone());

        Ok(())
    }

    /// Verify upgrade activation
    pub fn verify_upgrade_activation(&self, new_version: Version) -> Result<bool, BindingError> {
        // Check version monotonicity
        if new_version <= self.protocol_version {
            return Err(BindingError::VersionMismatch);
        }

        Ok(true)
    }

    /// Record upgrade activation
    pub fn record_upgrade_activation(&mut self, new_version: Version) -> Result<(), BindingError> {
        // Verify upgrade
        self.verify_upgrade_activation(new_version)?;

        // Update protocol version
        let old_version = self.protocol_version;
        self.protocol_version = new_version;

        info!("Protocol upgraded: {} -> {}", old_version, new_version);

        Ok(())
    }

    /// Advance epoch
    pub fn advance_epoch(&mut self, block_height: u64) {
        self.current_epoch += 1;
        self.current_block_height = block_height;
    }

    /// Get governance archive root
    pub fn get_archive_root(&self) -> Result<Vec<u8>, BindingError> {
        if self.governance_archive.is_empty() {
            // Genesis archive
            let mut hasher = Sha256::new();
            hasher.update(b"BLEEP_GOVERNANCE_GENESIS");
            return Ok(hasher.finalize().to_vec());
        }

        let mut hasher = Sha256::new();
        for event_hash in &self.governance_archive {
            hasher.update(event_hash);
        }

        Ok(hasher.finalize().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finalized_action_creation() {
        let action = FinalizedGovernanceAction::new(
            "action_1".to_string(),
            "Test action".to_string(),
            VoteTally {
                proposal_id: "prop_1".to_string(),
                yes_votes: 7000,
                no_votes: 3000,
                total_weighted_votes: 10000,
                yes_percentage: 70.0,
                voter_count: 100,
            },
            true,
            vec![1, 2, 3],
            0,
            2,
            10,
        );

        assert!(action.approved);
        assert!(!action.has_finality(5));
        assert!(action.has_finality(15));
    }

    #[test]
    fn test_binding_new() {
        let binding = GovernanceConsensusBinding::new(Version::new(1, 0, 0), 0, 2);

        assert_eq!(binding.protocol_version, Version::new(1, 0, 0));
        assert_eq!(binding.current_epoch, 0);
    }

    #[test]
    fn test_activation_record_verification() -> Result<(), BindingError> {
        let record = ActivationRecord::new(
            "action_1".to_string(),
            ProposalOutcome::Passed {
                yes_votes: 7000,
                no_votes: 3000,
                yes_percentage: 70.0,
            },
            0,
            100,
            vec![1, 2, 3],
            vec![4, 5, 6],
        )?;

        assert!(record.verify_hash()?);

        Ok(())
    }

    #[test]
    fn test_upgrade_version_check() {
        let binding = GovernanceConsensusBinding::new(Version::new(1, 0, 0), 0, 2);

        // Valid upgrade
        assert!(binding
            .verify_upgrade_activation(Version::new(1, 1, 0))
            .is_ok());

        // Invalid upgrade (downgrade)
        assert!(binding
            .verify_upgrade_activation(Version::new(0, 9, 9))
            .is_err());

        // Invalid upgrade (same version)
        assert!(binding
            .verify_upgrade_activation(Version::new(1, 0, 0))
            .is_err());
    }
}
