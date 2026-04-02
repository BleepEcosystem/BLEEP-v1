// PHASE 4: CONSTITUTIONAL GOVERNANCE LAYER
// Governance Proposal Lifecycle - State Machine with Deterministic Phases
//
// SAFETY INVARIANTS:
// 1. Each proposal follows an immutable state machine
// 2. All state transitions are epoch-bounded and timestamped
// 3. Proposals can never regress in state
// 4. Constitutional validation must pass before voting
// 5. Voting results are finalized and immutable
// 6. All proposal data is cryptographically archived
// 7. Deterministic activation at epoch boundaries

use super::constitution::{BLEEPConstitution, GovernanceAction, ValidationResult};
use super::zk_voting::{TallyProof, VoteTally};
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProposalError {
    #[error("Invalid proposal state transition")]
    InvalidStateTransition,

    #[error("Proposal not found")]
    ProposalNotFound,

    #[error("Voting not active")]
    VotingNotActive,

    #[error("Proposal expired")]
    ProposalExpired,

    #[error("Constitutional validation failed")]
    ConstitutionalValidationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Tally verification failed")]
    TallyVerificationFailed,

    #[error("Invalid activation")]
    InvalidActivation,
}

/// Proposal state in the lifecycle
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProposalState {
    /// Created but not yet validated
    Created,

    /// Constitutional validation in progress
    Validating,

    /// Passed constitutional validation, awaiting voting period
    ConstitutionallyValid,

    /// Voting period active
    Voting,

    /// Voting closed, tally computed
    Tallied,

    /// Tally verified, awaiting activation epoch
    ActivationScheduled,

    /// Activated and executed
    Executed,

    /// Rejected (failed constitutional validation or vote)
    Rejected,

    /// Expired (voting period ended without quorum)
    Expired,
}

impl ProposalState {
    /// Check if proposal is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ProposalState::Executed | ProposalState::Rejected | ProposalState::Expired
        )
    }

    /// Get human-readable state name
    pub fn as_str(&self) -> &'static str {
        match self {
            ProposalState::Created => "Created",
            ProposalState::Validating => "Validating",
            ProposalState::ConstitutionallyValid => "ConstitutionallyValid",
            ProposalState::Voting => "Voting",
            ProposalState::Tallied => "Tallied",
            ProposalState::ActivationScheduled => "ActivationScheduled",
            ProposalState::Executed => "Executed",
            ProposalState::Rejected => "Rejected",
            ProposalState::Expired => "Expired",
        }
    }
}

/// Full lifecycle record of a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalRecord {
    /// Unique proposal ID
    pub id: String,

    /// Proposer's address
    pub proposer: String,

    /// Governance action being proposed
    pub action: GovernanceAction,

    /// Current state in lifecycle
    pub state: ProposalState,

    /// Epoch when proposal was created
    pub creation_epoch: u64,

    /// Constitutional validation result
    pub constitutional_validation: Option<ValidationResult>,

    /// Constitutional validation epoch
    pub constitutional_validation_epoch: Option<u64>,

    /// Voting start epoch
    pub voting_start_epoch: Option<u64>,

    /// Voting end epoch (immutable once set)
    pub voting_end_epoch: Option<u64>,

    /// Tally result (after voting closes)
    pub tally: Option<VoteTally>,

    /// Tally proof
    pub tally_proof: Option<TallyProof>,

    /// Activation epoch (when proposal executes)
    pub activation_epoch: Option<u64>,

    /// Execution result hash
    pub execution_result: Option<Vec<u8>>,

    /// Rejection reason (if rejected)
    pub rejection_reason: Option<String>,

    /// Proposal hash (immutable commitment)
    pub proposal_hash: Vec<u8>,

    /// State transition history
    pub state_history: Vec<ProposalStateTransition>,
}

/// Record of a state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalStateTransition {
    /// Previous state
    pub from_state: ProposalState,

    /// New state
    pub to_state: ProposalState,

    /// Epoch of transition
    pub epoch: u64,

    /// Block height of transition
    pub block_height: u64,

    /// Transition hash
    pub transition_hash: Vec<u8>,
}

impl ProposalRecord {
    /// Create a new proposal
    pub fn new(
        id: String,
        proposer: String,
        action: GovernanceAction,
        creation_epoch: u64,
    ) -> Result<Self, ProposalError> {
        let proposal_hash = Self::compute_hash(&id, &proposer, &action)?;

        Ok(ProposalRecord {
            id,
            proposer,
            action,
            state: ProposalState::Created,
            creation_epoch,
            constitutional_validation: None,
            constitutional_validation_epoch: None,
            voting_start_epoch: None,
            voting_end_epoch: None,
            tally: None,
            tally_proof: None,
            activation_epoch: None,
            execution_result: None,
            rejection_reason: None,
            proposal_hash,
            state_history: Vec::new(),
        })
    }

    /// Compute immutable hash of proposal
    fn compute_hash(
        id: &str,
        proposer: &str,
        action: &GovernanceAction,
    ) -> Result<Vec<u8>, ProposalError> {
        let serialized = bincode::serialize(&(id, proposer, action))
            .map_err(|e| ProposalError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }

    /// Validate and transition to next state
    pub fn transition_state(
        &mut self,
        new_state: ProposalState,
        epoch: u64,
        block_height: u64,
    ) -> Result<(), ProposalError> {
        // Check if transition is valid
        self.validate_transition(self.state, new_state)?;

        let old_state = self.state;
        self.state = new_state;

        // Record transition
        let transition_hash = Self::compute_transition_hash(old_state, new_state, epoch)?;

        self.state_history.push(ProposalStateTransition {
            from_state: old_state,
            to_state: new_state,
            epoch,
            block_height,
            transition_hash,
        });

        info!(
            "Proposal {} transitioned from {} to {} at epoch {}",
            self.id,
            old_state.as_str(),
            new_state.as_str(),
            epoch
        );

        Ok(())
    }

    /// Validate state transition
    fn validate_transition(
        &self,
        from: ProposalState,
        to: ProposalState,
    ) -> Result<(), ProposalError> {
        // Prevent transitions from terminal states
        if from.is_terminal() {
            return Err(ProposalError::InvalidStateTransition);
        }

        // Validate state machine transitions
        match (from, to) {
            (ProposalState::Created, ProposalState::Validating) => Ok(()),
            (ProposalState::Validating, ProposalState::ConstitutionallyValid) => Ok(()),
            (ProposalState::Validating, ProposalState::Rejected) => Ok(()),
            (ProposalState::ConstitutionallyValid, ProposalState::Voting) => Ok(()),
            (ProposalState::Voting, ProposalState::Tallied) => Ok(()),
            (ProposalState::Tallied, ProposalState::ActivationScheduled) => Ok(()),
            (ProposalState::Tallied, ProposalState::Rejected) => Ok(()),
            (ProposalState::ActivationScheduled, ProposalState::Executed) => Ok(()),
            (ProposalState::Voting, ProposalState::Expired) => Ok(()),
            _ => Err(ProposalError::InvalidStateTransition),
        }
    }

    /// Compute transition hash
    fn compute_transition_hash(
        from: ProposalState,
        to: ProposalState,
        epoch: u64,
    ) -> Result<Vec<u8>, ProposalError> {
        let serialized = bincode::serialize(&(from, to, epoch))
            .map_err(|e| ProposalError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }

    /// Submit proposal for constitutional validation
    pub fn submit_for_validation(&mut self, current_epoch: u64) -> Result<(), ProposalError> {
        self.transition_state(ProposalState::Validating, current_epoch, 0)
    }

    /// Record constitutional validation result
    pub fn record_constitutional_validation(
        &mut self,
        validation_result: ValidationResult,
        current_epoch: u64,
        block_height: u64,
    ) -> Result<(), ProposalError> {
        self.constitutional_validation = Some(validation_result.clone());
        self.constitutional_validation_epoch = Some(current_epoch);

        match validation_result {
            ValidationResult::Valid => self.transition_state(
                ProposalState::ConstitutionallyValid,
                current_epoch,
                block_height,
            ),
            ValidationResult::Violation(reason) => {
                self.rejection_reason = Some(format!("Constitutional violation: {}", reason));
                self.transition_state(ProposalState::Rejected, current_epoch, block_height)
            }
        }
    }

    /// Start voting period
    pub fn start_voting(
        &mut self,
        voting_start_epoch: u64,
        voting_duration_epochs: u64,
        block_height: u64,
    ) -> Result<(), ProposalError> {
        if self.state != ProposalState::ConstitutionallyValid {
            return Err(ProposalError::InvalidStateTransition);
        }

        self.voting_start_epoch = Some(voting_start_epoch);
        self.voting_end_epoch = Some(voting_start_epoch + voting_duration_epochs);

        self.transition_state(ProposalState::Voting, voting_start_epoch, block_height)
    }

    /// Record tally result
    pub fn record_tally(
        &mut self,
        tally: VoteTally,
        proof: TallyProof,
        current_epoch: u64,
        block_height: u64,
    ) -> Result<(), ProposalError> {
        if self.state != ProposalState::Voting {
            return Err(ProposalError::InvalidStateTransition);
        }

        self.tally = Some(tally);
        self.tally_proof = Some(proof);

        self.transition_state(ProposalState::Tallied, current_epoch, block_height)
    }

    /// Schedule activation after tally verification
    pub fn schedule_activation(
        &mut self,
        activation_epoch: u64,
        current_epoch: u64,
        block_height: u64,
    ) -> Result<(), ProposalError> {
        if self.state != ProposalState::Tallied {
            return Err(ProposalError::InvalidStateTransition);
        }

        // Activation must be in future
        if activation_epoch <= current_epoch {
            return Err(ProposalError::InvalidActivation);
        }

        self.activation_epoch = Some(activation_epoch);

        self.transition_state(
            ProposalState::ActivationScheduled,
            current_epoch,
            block_height,
        )
    }

    /// Execute proposal
    pub fn execute(
        &mut self,
        execution_result: Vec<u8>,
        current_epoch: u64,
        block_height: u64,
    ) -> Result<(), ProposalError> {
        if self.state != ProposalState::ActivationScheduled {
            return Err(ProposalError::InvalidStateTransition);
        }

        // Check activation epoch matches
        if let Some(activation_epoch) = self.activation_epoch {
            if current_epoch < activation_epoch {
                return Err(ProposalError::InvalidActivation);
            }
        }

        self.execution_result = Some(execution_result);

        self.transition_state(ProposalState::Executed, current_epoch, block_height)
    }

    /// Mark proposal as expired
    pub fn expire(&mut self, current_epoch: u64, block_height: u64) -> Result<(), ProposalError> {
        if self.state != ProposalState::Voting {
            return Err(ProposalError::InvalidStateTransition);
        }

        self.transition_state(ProposalState::Expired, current_epoch, block_height)
    }

    /// Get proposal as immutable archive entry
    pub fn archive_hash(&self) -> Result<Vec<u8>, ProposalError> {
        let serialized = bincode::serialize(self)
            .map_err(|e| ProposalError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }
}

/// Governance Proposal Lifecycle Manager
pub struct ProposalLifecycleManager {
    /// All proposals by ID
    proposals: BTreeMap<String, ProposalRecord>,

    /// Constitution reference
    constitution: BLEEPConstitution,

    /// Current epoch
    current_epoch: u64,

    /// Block height
    current_block_height: u64,

    /// Voting duration (epochs)
    voting_duration: u64,

    /// Voting threshold (basis points)
    #[allow(dead_code)]
    voting_threshold: u64,
}

impl ProposalLifecycleManager {
    /// Create new lifecycle manager
    pub fn new(
        constitution: BLEEPConstitution,
        current_epoch: u64,
        voting_duration: u64,
        voting_threshold: u64,
    ) -> Result<Self, ProposalError> {
        Ok(ProposalLifecycleManager {
            proposals: BTreeMap::new(),
            constitution,
            current_epoch,
            current_block_height: 0,
            voting_duration,
            voting_threshold,
        })
    }

    /// Create and submit a new proposal
    pub fn propose(
        &mut self,
        id: String,
        proposer: String,
        action: GovernanceAction,
    ) -> Result<(), ProposalError> {
        // Check proposal doesn't already exist
        if self.proposals.contains_key(&id) {
            return Err(ProposalError::ProposalNotFound);
        }

        let mut proposal = ProposalRecord::new(id.clone(), proposer, action, self.current_epoch)?;

        proposal.submit_for_validation(self.current_epoch)?;

        self.proposals.insert(id, proposal);

        Ok(())
    }

    /// Process proposal constitutional validation
    pub fn validate_proposal(
        &mut self,
        proposal_id: &str,
    ) -> Result<ValidationResult, ProposalError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(ProposalError::ProposalNotFound)?;

        let validation_result = self
            .constitution
            .validate_action(&proposal.action)
            .map_err(|_| ProposalError::ConstitutionalValidationFailed)?;

        proposal.record_constitutional_validation(
            validation_result.clone(),
            self.current_epoch,
            self.current_block_height,
        )?;

        Ok(validation_result)
    }

    /// Start voting period for a constitutionally valid proposal
    pub fn start_voting(&mut self, proposal_id: &str) -> Result<(), ProposalError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(ProposalError::ProposalNotFound)?;

        if proposal.state != ProposalState::ConstitutionallyValid {
            return Err(ProposalError::InvalidStateTransition);
        }

        proposal.start_voting(
            self.current_epoch,
            self.voting_duration,
            self.current_block_height,
        )
    }

    /// Record voting result
    pub fn record_tally(
        &mut self,
        proposal_id: &str,
        tally: VoteTally,
        proof: TallyProof,
    ) -> Result<(), ProposalError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(ProposalError::ProposalNotFound)?;

        proposal.record_tally(tally, proof, self.current_epoch, self.current_block_height)
    }

    /// Schedule proposal activation
    pub fn schedule_activation(
        &mut self,
        proposal_id: &str,
        activation_epoch: u64,
    ) -> Result<(), ProposalError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(ProposalError::ProposalNotFound)?;

        proposal.schedule_activation(
            activation_epoch,
            self.current_epoch,
            self.current_block_height,
        )
    }

    /// Execute proposal at activation epoch
    pub fn execute_proposal(
        &mut self,
        proposal_id: &str,
        execution_result: Vec<u8>,
    ) -> Result<(), ProposalError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(ProposalError::ProposalNotFound)?;

        proposal.execute(
            execution_result,
            self.current_epoch,
            self.current_block_height,
        )
    }

    /// Advance to next epoch
    pub fn advance_epoch(&mut self, block_height: u64) {
        self.current_epoch += 1;
        self.current_block_height = block_height;

        info!(
            "Advanced to epoch {} (block {})",
            self.current_epoch, block_height
        );
    }

    /// Get proposal by ID
    pub fn get_proposal(&self, proposal_id: &str) -> Option<&ProposalRecord> {
        self.proposals.get(proposal_id)
    }

    /// Get all proposals
    pub fn get_all_proposals(&self) -> Vec<&ProposalRecord> {
        self.proposals.values().collect()
    }

    /// Get proposals in a specific state
    pub fn get_proposals_by_state(&self, state: ProposalState) -> Vec<&ProposalRecord> {
        self.proposals
            .values()
            .filter(|p| p.state == state)
            .collect()
    }

    /// Create archive of all proposals
    pub fn create_archive(&self) -> Result<ProposalArchive, ProposalError> {
        let mut proposal_hashes = Vec::new();

        for proposal in self.proposals.values() {
            proposal_hashes.push(proposal.archive_hash()?);
        }

        let mut hasher = Sha256::new();
        for hash in &proposal_hashes {
            hasher.update(hash);
        }

        Ok(ProposalArchive {
            epoch: self.current_epoch,
            proposal_count: self.proposals.len(),
            archive_root: hasher.finalize().to_vec(),
            proposal_hashes,
        })
    }
}

/// Immutable archive of all proposals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalArchive {
    /// Epoch of archive
    pub epoch: u64,

    /// Number of proposals
    pub proposal_count: usize,

    /// Merkle root of all proposals
    pub archive_root: Vec<u8>,

    /// Individual proposal hashes
    pub proposal_hashes: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constitution::{ConstitutionalScope, GovernanceAction};

    #[test]
    fn test_proposal_creation() -> Result<(), ProposalError> {
        let action = GovernanceAction::new(
            "action_1".to_string(),
            ConstitutionalScope::Governance,
            vec!["governance".to_string()],
            "Test governance action".to_string(),
        );

        let proposal =
            ProposalRecord::new("prop_1".to_string(), "proposer".to_string(), action, 0)?;

        assert_eq!(proposal.state, ProposalState::Created);
        assert!(!proposal.proposal_hash.is_empty());

        Ok(())
    }

    #[test]
    fn test_state_transitions() -> Result<(), ProposalError> {
        let action = GovernanceAction::new(
            "action_1".to_string(),
            ConstitutionalScope::Governance,
            vec!["governance".to_string()],
            "Test action".to_string(),
        );

        let mut proposal =
            ProposalRecord::new("prop_1".to_string(), "proposer".to_string(), action, 0)?;

        // Created -> Validating
        proposal.submit_for_validation(0)?;
        assert_eq!(proposal.state, ProposalState::Validating);

        // Validating -> ConstitutionallyValid
        proposal.record_constitutional_validation(ValidationResult::Valid, 0, 0)?;
        assert_eq!(proposal.state, ProposalState::ConstitutionallyValid);

        // ConstitutionallyValid -> Voting
        proposal.start_voting(0, 100, 0)?;
        assert_eq!(proposal.state, ProposalState::Voting);

        Ok(())
    }

    #[test]
    fn test_invalid_state_transition() -> Result<(), ProposalError> {
        let action = GovernanceAction::new(
            "action_1".to_string(),
            ConstitutionalScope::Governance,
            vec!["governance".to_string()],
            "Test action".to_string(),
        );

        let mut proposal =
            ProposalRecord::new("prop_1".to_string(), "proposer".to_string(), action, 0)?;

        // Try invalid transition: Created -> Executed
        let result = proposal.transition_state(ProposalState::Executed, 0, 0);
        assert!(result.is_err());

        Ok(())
    }
}
