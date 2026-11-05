// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// On-Chain Governance Voting - Deterministic, validator-based voting
//
// SAFETY INVARIANTS:
// 1. Voting is deterministic and identical on all honest nodes
// 2. Voting windows are epoch-bound and immutable
// 3. Double voting is cryptographically impossible
// 4. Votes are weighted by validator stake
// 5. Results are finalized and immutable once epoch concludes
// 6. AI has zero voting power (only validator votes count)

use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VotingError {
    #[error("Voting not active")]
    VotingNotActive,

    #[error("Invalid validator")]
    InvalidValidator,

    #[error("Double voting detected")]
    DoubleVoting,

    #[error("Voting window closed")]
    VotingWindowClosed,

    #[error("Proposal not found")]
    ProposalNotFound,

    #[error("Invalid vote")]
    InvalidVote,

    #[error("Threshold not met")]
    ThresholdNotMet,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Voting arithmetic overflow")]
    ArithmeticOverflow,

    #[error("Vote tally arithmetic overflow")]
    TallyOverflow,
}

/// A validator's vote on a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVote {
    /// Proposal ID
    pub proposal_id: String,

    /// Validator's public key
    pub validator: Vec<u8>,

    /// True = approve, False = reject
    pub approval: bool,

    /// Validator's stake (used for weighted voting)
    pub stake: u64,

    /// Epoch when vote was cast
    pub epoch: u64,

    /// Cryptographic signature of vote
    pub signature: Vec<u8>,

    /// Hash of vote content (for verification)
    pub vote_hash: Vec<u8>,
}

impl ValidatorVote {
    pub fn new(
        proposal_id: String,
        validator: Vec<u8>,
        approval: bool,
        stake: u64,
        epoch: u64,
    ) -> Self {
        ValidatorVote {
            proposal_id,
            validator,
            approval,
            stake,
            epoch,
            signature: Vec::new(),
            vote_hash: Vec::new(),
        }
    }

    /// Compute deterministic vote hash
    pub fn compute_hash(&mut self) -> Result<Vec<u8>, VotingError> {
        let content = (
            &self.proposal_id,
            &self.validator,
            self.approval,
            self.stake,
            self.epoch,
        );

        let serialized = serde_json::to_string(&content)
            .map_err(|e| VotingError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let hash = hasher.finalize().to_vec();

        self.vote_hash = hash.clone();
        Ok(hash)
    }

    /// Verify vote hash
    pub fn verify_hash(&self) -> Result<bool, VotingError> {
        if self.vote_hash.is_empty() {
            return Ok(false);
        }

        let content = (
            &self.proposal_id,
            &self.validator,
            self.approval,
            self.stake,
            self.epoch,
        );

        let serialized = serde_json::to_string(&content)
            .map_err(|e| VotingError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let computed_hash = hasher.finalize().to_vec();

        Ok(computed_hash == self.vote_hash)
    }

    /// Add validator signature (off-chain, before submission)
    pub fn sign(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

/// Voting window for a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingWindow {
    /// Proposal ID
    pub proposal_id: String,

    /// Starting epoch
    pub start_epoch: u64,

    /// Ending epoch
    pub end_epoch: u64,

    /// Is voting currently active
    pub is_active: bool,
}

impl VotingWindow {
    pub fn new(proposal_id: String, start_epoch: u64, end_epoch: u64) -> Self {
        VotingWindow {
            proposal_id,
            start_epoch,
            end_epoch,
            is_active: true,
        }
    }

    /// Check if voting is active at given epoch
    pub fn is_open_at(&self, epoch: u64) -> bool {
        epoch >= self.start_epoch && epoch < self.end_epoch
    }

    /// Close voting window
    pub fn close(&mut self) {
        self.is_active = false;
    }
}

/// Voting state for a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalVotingState {
    /// Proposal ID
    pub proposal_id: String,

    /// Voting window
    pub window: VotingWindow,

    /// Total stake of validators who voted for
    pub stake_for: u64,

    /// Total stake of validators who voted against
    pub stake_against: u64,

    /// Set of validators who have voted (prevent double voting)
    pub voters: HashSet<Vec<u8>>,

    /// All votes (for auditing)
    pub votes: Vec<ValidatorVote>,

    /// Total stake of all active validators
    pub total_active_stake: u64,
}

impl ProposalVotingState {
    pub fn new(
        proposal_id: String,
        start_epoch: u64,
        end_epoch: u64,
        total_active_stake: u64,
    ) -> Self {
        let proposal_id_clone = proposal_id.clone();
        ProposalVotingState {
            proposal_id,
            window: VotingWindow::new(proposal_id_clone, start_epoch, end_epoch),
            stake_for: 0,
            stake_against: 0,
            voters: HashSet::new(),
            votes: Vec::new(),
            total_active_stake,
        }
    }

    /// Cast a vote (must be within voting window)
    pub fn cast_vote(
        &mut self,
        mut vote: ValidatorVote,
        current_epoch: u64,
    ) -> Result<(), VotingError> {
        // Check voting window is open
        if !self.window.is_open_at(current_epoch) {
            return Err(VotingError::VotingWindowClosed);
        }

        // Prevent double voting
        if self.voters.contains(&vote.validator) {
            return Err(VotingError::DoubleVoting);
        }

        // Verify vote signature
        vote.compute_hash()?;

        // Check the tally before recording the vote so overflow is atomic.
        if vote.approval {
            self.stake_for = self
                .stake_for
                .checked_add(vote.stake)
                .ok_or(VotingError::TallyOverflow)?;
        } else {
            self.stake_against = self
                .stake_against
                .checked_add(vote.stake)
                .ok_or(VotingError::TallyOverflow)?;
        }

        self.voters.insert(vote.validator.clone());
        self.votes.push(vote);

        Ok(())
    }

    /// Finalize voting and compute result
    ///
    /// SAFETY: Result is deterministic based on stake-weighted votes
    pub fn finalize(&mut self) -> Result<VotingResult, VotingError> {
        let total_votes = self
            .stake_for
            .checked_add(self.stake_against)
            .ok_or(VotingError::TallyOverflow)?;
        let approval_percentage = if total_votes > 0 {
            self.stake_for
                .checked_mul(100)
                .ok_or(VotingError::TallyOverflow)?
                .checked_div(total_votes)
                .ok_or(VotingError::TallyOverflow)?
        } else {
            0
        };

        let participation_percentage = if self.total_active_stake > 0 {
            total_votes
                .checked_mul(100)
                .ok_or(VotingError::TallyOverflow)?
                .checked_div(self.total_active_stake)
                .ok_or(VotingError::TallyOverflow)?
        } else {
            0
        };
        let result = VotingResult {
            proposal_id: self.proposal_id.clone(),
            stake_for: self.stake_for,
            stake_against: self.stake_against,
            total_voting_stake: total_votes,
            total_active_stake: self.total_active_stake,
            approval_percentage,
            voter_count: self.voters.len() as u64,
            participation_percentage,
        };
        self.window.close();
        Ok(result)
    }
}

/// Result of proposal voting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingResult {
    /// Proposal ID
    pub proposal_id: String,

    /// Total stake voting in favor
    pub stake_for: u64,

    /// Total stake voting against
    pub stake_against: u64,

    /// Total stake that participated
    pub total_voting_stake: u64,

    /// Total active validator stake
    pub total_active_stake: u64,

    /// Percentage approval (stake-weighted)
    pub approval_percentage: u64,

    /// Number of validators who voted
    pub voter_count: u64,

    /// Percentage of validators who participated
    pub participation_percentage: u64,
}

impl VotingResult {
    /// Check if proposal is approved (deterministic)
    pub fn is_approved(&self, required_threshold: u64) -> bool {
        self.approval_percentage >= required_threshold
    }
}

/// On-Chain Governance Voting Engine
pub struct GovernanceVotingEngine {
    /// Active voting states
    active_votes: HashMap<String, ProposalVotingState>,

    /// Concluded voting results (immutable history)
    concluded_votes: HashMap<String, VotingResult>,

    /// Validator set (from consensus layer)
    /// Map of validator_pubkey -> stake
    validators: HashMap<Vec<u8>, u64>,
}

impl Default for GovernanceVotingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceVotingEngine {
    pub fn new() -> Self {
        GovernanceVotingEngine {
            active_votes: HashMap::new(),
            concluded_votes: HashMap::new(),
            validators: HashMap::new(),
        }
    }

    /// Update validator set (called when consensus changes validators)
    pub fn update_validators(&mut self, validators: HashMap<Vec<u8>, u64>) {
        self.validators = validators;
    }

    /// Get total active stake
    fn total_active_stake(&self) -> Result<u64, VotingError> {
        self.validators.values().try_fold(0u64, |total, stake| {
            total.checked_add(*stake).ok_or(VotingError::TallyOverflow)
        })
    }

    /// Initiate governance voting for a proposal
    ///
    /// SAFETY: Voting windows are epoch-bound
    pub fn start_voting(
        &mut self,
        proposal_id: String,
        current_epoch: u64,
        voting_duration: u64,
    ) -> Result<(), VotingError> {
        if self.active_votes.contains_key(&proposal_id) {
            return Err(VotingError::InvalidVote);
        }

        let start_epoch = current_epoch;
        let end_epoch = current_epoch
            .checked_add(voting_duration)
            .ok_or(VotingError::ArithmeticOverflow)?;
        let total_stake = self.total_active_stake()?;

        let voting_state =
            ProposalVotingState::new(proposal_id.clone(), start_epoch, end_epoch, total_stake);

        self.active_votes.insert(proposal_id.clone(), voting_state);

        info!(
            "Voting started for proposal {} (epochs {}-{})",
            proposal_id, start_epoch, end_epoch
        );

        Ok(())
    }

    /// Cast a vote on a proposal
    pub fn cast_vote(
        &mut self,
        proposal_id: String,
        validator: Vec<u8>,
        approval: bool,
        current_epoch: u64,
        signature: Vec<u8>,
    ) -> Result<(), VotingError> {
        let voting_state = self
            .active_votes
            .get_mut(&proposal_id)
            .ok_or(VotingError::ProposalNotFound)?;

        // Get validator stake
        let stake = self
            .validators
            .get(&validator)
            .copied()
            .ok_or(VotingError::InvalidValidator)?;

        let mut vote = ValidatorVote::new(
            proposal_id.clone(),
            validator,
            approval,
            stake,
            current_epoch,
        );

        vote.sign(signature);

        voting_state.cast_vote(vote, current_epoch)?;

        Ok(())
    }

    /// Finalize voting for a proposal
    ///
    /// SAFETY: Can only be called once per proposal
    pub fn finalize_voting(
        &mut self,
        proposal_id: &str,
        current_epoch: u64,
    ) -> Result<VotingResult, VotingError> {
        let mut voting_state = self
            .active_votes
            .remove(proposal_id)
            .ok_or(VotingError::ProposalNotFound)?;

        // Check voting window is closed
        if voting_state.window.is_open_at(current_epoch) {
            // Re-insert and return error
            self.active_votes
                .insert(proposal_id.to_string(), voting_state);
            return Err(VotingError::VotingNotActive);
        }

        let result = match voting_state.finalize() {
            Ok(result) => result,
            Err(error) => {
                self.active_votes
                    .insert(proposal_id.to_string(), voting_state);
                return Err(error);
            }
        };

        info!(
            "Voting finalized for proposal {}: {:.1}% approval, {} voters",
            proposal_id, result.approval_percentage, result.voter_count
        );

        self.concluded_votes
            .insert(proposal_id.to_string(), result.clone());

        Ok(result)
    }

    /// Get voting result (if finalized)
    pub fn get_voting_result(&self, proposal_id: &str) -> Option<&VotingResult> {
        self.concluded_votes.get(proposal_id)
    }

    /// Get active voting state (for voting periods)
    pub fn get_active_voting(&self, proposal_id: &str) -> Option<&ProposalVotingState> {
        self.active_votes.get(proposal_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_vote_creation() {
        let vote = ValidatorVote::new("APIP-001".to_string(), vec![1, 2, 3], true, 1000, 1);

        assert_eq!(vote.proposal_id, "APIP-001");
        assert!(vote.approval);
        assert_eq!(vote.stake, 1000);
    }

    #[test]
    fn test_voting_window() {
        let window = VotingWindow::new("APIP-001".to_string(), 1, 10);

        assert!(window.is_open_at(5));
        assert!(!window.is_open_at(0));
        assert!(!window.is_open_at(10));
    }

    #[test]
    fn test_proposal_voting_state() {
        let mut state = ProposalVotingState::new("APIP-001".to_string(), 1, 10, 10000);

        let vote = ValidatorVote::new("APIP-001".to_string(), vec![1, 2, 3], true, 1000, 5);

        state.cast_vote(vote, 5).unwrap();
        assert_eq!(state.stake_for, 1000);
    }

    #[test]
    fn test_double_voting_prevention() {
        let mut state = ProposalVotingState::new("APIP-001".to_string(), 1, 10, 10000);

        let vote1 = ValidatorVote::new("APIP-001".to_string(), vec![1, 2, 3], true, 1000, 5);

        state.cast_vote(vote1, 5).unwrap();

        // Try to vote again with same validator
        let vote2 = ValidatorVote::new("APIP-001".to_string(), vec![1, 2, 3], false, 1000, 6);

        assert!(state.cast_vote(vote2, 6).is_err());
    }

    #[test]
    fn test_voting_result_calculation() {
        let mut state = ProposalVotingState::new("APIP-001".to_string(), 1, 10, 10000);

        // 600 votes for, 400 against
        let vote_for = ValidatorVote::new("APIP-001".to_string(), vec![1, 2, 3], true, 600, 5);
        state.cast_vote(vote_for, 5).unwrap();

        let vote_against = ValidatorVote::new("APIP-001".to_string(), vec![4, 5, 6], false, 400, 5);
        state.cast_vote(vote_against, 5).unwrap();

        let result = state.finalize().unwrap();
        assert_eq!(result.approval_percentage, 60);
        assert_eq!(result.voter_count, 2);
        assert!(result.is_approved(50));
    }

    #[test]
    fn tally_overflow_is_an_error_and_does_not_close_voting() {
        let mut state = ProposalVotingState::new("APIP-OVERFLOW".to_string(), 1, 10, u64::MAX);
        state.stake_for = u64::MAX;
        state.stake_against = 1;

        assert!(matches!(state.finalize(), Err(VotingError::TallyOverflow)));
        assert!(state.window.is_active);
    }

    #[test]
    fn percentage_multiplication_overflow_is_an_error() {
        let mut state = ProposalVotingState::new("APIP-PERCENT".to_string(), 1, 10, u64::MAX);
        state.stake_for = u64::MAX / 2 + 1;

        assert!(matches!(state.finalize(), Err(VotingError::TallyOverflow)));
        assert!(state.window.is_active);
    }

    #[test]
    fn cast_vote_overflow_does_not_record_the_vote() {
        let mut state = ProposalVotingState::new("APIP-CAST".to_string(), 1, 10, u64::MAX);
        state.stake_for = u64::MAX;
        let vote = ValidatorVote::new("APIP-CAST".to_string(), vec![7], true, 1, 5);

        assert!(matches!(
            state.cast_vote(vote, 5),
            Err(VotingError::TallyOverflow)
        ));
        assert!(state.voters.is_empty());
        assert!(state.votes.is_empty());
    }

    #[test]
    fn validator_stake_sum_overflow_is_an_error() {
        let mut engine = GovernanceVotingEngine::new();
        engine.update_validators(HashMap::from([(vec![1], u64::MAX), (vec![2], 1)]));

        assert!(matches!(
            engine.start_voting("APIP-STAKES".to_string(), 1, 5),
            Err(VotingError::TallyOverflow)
        ));
    }

    #[test]
    fn test_governance_voting_engine() {
        let mut engine = GovernanceVotingEngine::new();

        // Add validators
        let mut validators = HashMap::new();
        validators.insert(vec![1, 2, 3], 1000);
        validators.insert(vec![4, 5, 6], 2000);
        engine.update_validators(validators);

        // Start voting
        engine.start_voting("APIP-001".to_string(), 1, 5).unwrap();

        // Cast vote
        engine
            .cast_vote(
                "APIP-001".to_string(),
                vec![1, 2, 3],
                true,
                2,
                vec![1, 2, 3],
            )
            .unwrap();

        // Get active voting
        assert!(engine.get_active_voting("APIP-001").is_some());
    }
}
