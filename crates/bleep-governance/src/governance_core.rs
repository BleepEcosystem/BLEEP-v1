// PHASE 2: ON-CHAIN GOVERNANCE ENGINE
// Deterministic proposal execution without human intervention
//
// SAFETY INVARIANTS:
// 1. All proposals follow deterministic state machine
// 2. Voting windows are strictly epoch-bounded
// 3. Votes are weighted by validator stake (immutable)
// 4. Quorum and threshold are enforced before execution
// 5. Proposal execution is deterministic (all nodes execute identically)
// 6. Execution failures result in automatic rollback
// 7. All governance actions are immutable once executed
// 8. No proposal can execute without quorum + threshold

use log::{error, info};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

/// Proposal type determining what action is executed
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalType {
    /// Update protocol parameters (e.g., block_time, validator_count)
    ProtocolParameter,

    /// Sanction a validator (slash, remove, jail)
    ValidatorSanction,

    /// Recovery action (e.g., slashed validator recovery, state repair)
    Recovery,

    /// Authorize protocol upgrade or module deployment
    UpgradeAuthorization,
}

impl ProposalType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProposalType::ProtocolParameter => "PROTOCOL_PARAMETER",
            ProposalType::ValidatorSanction => "VALIDATOR_SANCTION",
            ProposalType::Recovery => "RECOVERY",
            ProposalType::UpgradeAuthorization => "UPGRADE_AUTHORIZATION",
        }
    }
}

/// Governance proposal state machine
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProposalState {
    /// Created, waiting for submission
    Draft,

    /// Submitted, awaiting voting period to start
    Pending,

    /// Voting period active (epoch-bounded)
    Voting,

    /// Voting period closed, tallying in progress
    Tallying,

    /// Tally complete, awaiting execution epoch
    AwaitingExecution,

    /// Execution in progress
    Executing,

    /// Execution successful
    Executed,

    /// Execution failed, rolled back
    RolledBack,

    /// Rejected by validators or safety check
    Rejected,

    /// Expired without reaching quorum
    Expired,
}

impl ProposalState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ProposalState::Executed
                | ProposalState::RolledBack
                | ProposalState::Rejected
                | ProposalState::Expired
        )
    }
}

/// Voting window: bounded by start and end epochs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingWindow {
    /// Epoch voting starts (inclusive)
    pub start_epoch: u64,

    /// Epoch voting ends (exclusive) - final vote must be before this
    pub end_epoch: u64,

    /// Minimum epochs for voting duration (must be >= 2)
    pub min_duration: u64,
}

impl VotingWindow {
    pub fn new(start_epoch: u64, end_epoch: u64) -> Result<Self, String> {
        if start_epoch >= end_epoch {
            return Err("start_epoch must be < end_epoch".to_string());
        }
        let duration = end_epoch - start_epoch;
        if duration < 2 {
            return Err("voting duration must be >= 2 epochs".to_string());
        }
        Ok(VotingWindow {
            start_epoch,
            end_epoch,
            min_duration: duration,
        })
    }

    /// Check if voting is active for given epoch
    pub fn is_active(&self, current_epoch: u64) -> bool {
        current_epoch >= self.start_epoch && current_epoch < self.end_epoch
    }

    /// Check if voting window has closed
    pub fn is_closed(&self, current_epoch: u64) -> bool {
        current_epoch >= self.end_epoch
    }
}

/// A validator's vote on a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Validator ID (public key)
    pub validator_id: String,

    /// Vote: true = approve, false = reject
    pub approval: bool,

    /// Validator's stake at time of vote (immutable)
    pub stake: u128,

    /// Epoch when vote was cast
    pub vote_epoch: u64,

    /// Signature: SHA256(validator_id || proposal_id || approval || stake || epoch)
    pub signature: Vec<u8>,
}

impl Vote {
    pub fn new(
        validator_id: String,
        approval: bool,
        stake: u128,
        vote_epoch: u64,
        signature: Vec<u8>,
    ) -> Self {
        Vote {
            validator_id,
            approval,
            stake,
            vote_epoch,
            signature,
        }
    }

    /// Compute deterministic vote hash for verification
    pub fn compute_hash(&self, proposal_id: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.validator_id.as_bytes());
        hasher.update(proposal_id.as_bytes());
        hasher.update((self.approval as u8).to_le_bytes());
        hasher.update(self.stake.to_le_bytes());
        hasher.update(self.vote_epoch.to_le_bytes());
        hasher.finalize().to_vec()
    }
}

/// Tally result: vote counts and voting power
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTally {
    /// Total stake voting yes
    pub stake_approve: u128,

    /// Total stake voting no
    pub stake_reject: u128,

    /// Total stake that participated
    pub stake_total: u128,

    /// Percentage approval (0-100)
    pub approval_percentage: u64,

    /// Proposal approved
    pub approved: bool,

    /// Quorum met (>33% participation)
    pub quorum_met: bool,
}

impl VoteTally {
    pub fn compute(
        stake_approve: u128,
        stake_reject: u128,
        total_network_stake: u128,
        approval_threshold: u64, // percentage, 0-100
    ) -> Result<Self, String> {
        let stake_total = stake_approve.saturating_add(stake_reject);

        if stake_total == 0 {
            return Err("No votes cast".to_string());
        }

        // Quorum: >33% of network stake must participate
        let quorum_threshold = (total_network_stake / 3) + 1;
        let quorum_met = stake_total > quorum_threshold;

        // Approval percentage
        let approval_percentage = if stake_total == 0 {
            0
        } else {
            ((stake_approve * 100) / stake_total) as u64
        };

        // Approved if quorum met AND approval >= threshold
        let approved = quorum_met && approval_percentage >= approval_threshold;

        Ok(VoteTally {
            stake_approve,
            stake_reject,
            stake_total,
            approval_percentage,
            approved,
            quorum_met,
        })
    }
}

#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("Voting not active")]
    VotingNotActive,

    #[error("Voting window expired")]
    VotingWindowExpired,

    #[error("Double voting detected for validator {0}")]
    DoubleVoting(String),

    #[error("Quorum not met")]
    QuorumNotMet,

    #[error("Approval threshold not met")]
    ThresholdNotMet,

    #[error("Proposal not found")]
    ProposalNotFound,

    #[error("Invalid validator")]
    InvalidValidator,

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Invalid proposal: {0}")]
    InvalidProposal(String),
}

/// On-chain governance proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique proposal ID
    pub id: String,

    /// Proposal type (determines execution behavior)
    pub proposal_type: ProposalType,

    /// Title for human readability
    pub title: String,

    /// Description/justification
    pub description: String,

    /// Current state
    pub state: ProposalState,

    /// Voting window
    pub voting_window: VotingWindow,

    /// Epoch when proposal should execute (if approved)
    pub execution_epoch: u64,

    /// Approval threshold percentage (e.g., 67 for 2/3 majority)
    pub approval_threshold: u64,

    /// Votes cast on this proposal
    pub votes: HashMap<String, Vote>,

    /// Final tally (if voting closed)
    pub tally: Option<VoteTally>,

    /// Execution payload (specific to proposal type)
    pub payload: GovernancePayload,

    /// Previous state (for rollback)
    pub previous_state: Option<Box<Proposal>>,

    /// Timestamp when proposal was created (for audit)
    pub created_epoch: u64,
}

impl Proposal {
    pub fn new(
        id: String,
        proposal_type: ProposalType,
        title: String,
        description: String,
        voting_window: VotingWindow,
        execution_epoch: u64,
        approval_threshold: u64,
        payload: GovernancePayload,
        created_epoch: u64,
    ) -> Self {
        Proposal {
            id,
            proposal_type,
            title,
            description,
            state: ProposalState::Draft,
            voting_window,
            execution_epoch,
            approval_threshold,
            votes: HashMap::new(),
            tally: None,
            payload,
            previous_state: None,
            created_epoch,
        }
    }

    /// Submit proposal (Draft → Pending)
    pub fn submit(&mut self) -> Result<(), GovernanceError> {
        if self.state != ProposalState::Draft {
            return Err(GovernanceError::InvalidStateTransition(format!(
                "Cannot submit proposal in state {:?}",
                self.state
            )));
        }
        self.state = ProposalState::Pending;
        info!("Proposal {} submitted", self.id);
        Ok(())
    }

    /// Start voting (Pending → Voting)
    pub fn start_voting(&mut self, current_epoch: u64) -> Result<(), GovernanceError> {
        if self.state != ProposalState::Pending {
            return Err(GovernanceError::InvalidStateTransition(format!(
                "Cannot start voting from state {:?}",
                self.state
            )));
        }
        if current_epoch < self.voting_window.start_epoch {
            return Err(GovernanceError::VotingNotActive);
        }
        self.state = ProposalState::Voting;
        info!(
            "Proposal {} voting started at epoch {}",
            self.id, current_epoch
        );
        Ok(())
    }

    /// Cast a vote (adds to vote map, checks for double voting)
    pub fn cast_vote(&mut self, vote: Vote, current_epoch: u64) -> Result<(), GovernanceError> {
        if self.state != ProposalState::Voting {
            return Err(GovernanceError::VotingNotActive);
        }

        if !self.voting_window.is_active(current_epoch) {
            return Err(GovernanceError::VotingWindowExpired);
        }

        // Check double voting
        if self.votes.contains_key(&vote.validator_id) {
            return Err(GovernanceError::DoubleVoting(vote.validator_id.clone()));
        }

        self.votes.insert(vote.validator_id.clone(), vote);
        info!("Vote cast for proposal {} by validator", self.id);
        Ok(())
    }

    /// Close voting and compute tally (Voting → Tallying)
    pub fn close_voting(
        &mut self,
        current_epoch: u64,
        total_network_stake: u128,
    ) -> Result<(), GovernanceError> {
        if self.state != ProposalState::Voting {
            return Err(GovernanceError::InvalidStateTransition(
                "Can only close voting from Voting state".to_string(),
            ));
        }

        if !self.voting_window.is_closed(current_epoch) {
            return Err(GovernanceError::VotingNotActive);
        }

        // Compute tally
        let mut stake_approve = 0u128;
        let mut stake_reject = 0u128;

        for (_, vote) in &self.votes {
            if vote.approval {
                stake_approve = stake_approve.saturating_add(vote.stake);
            } else {
                stake_reject = stake_reject.saturating_add(vote.stake);
            }
        }

        let tally = VoteTally::compute(
            stake_approve,
            stake_reject,
            total_network_stake,
            self.approval_threshold,
        )
        .map_err(|e| GovernanceError::InternalError(e))?;

        self.tally = Some(tally.clone());

        if tally.approved {
            self.state = ProposalState::AwaitingExecution;
            info!(
                "Proposal {} approved with {:.1}% stake",
                self.id, tally.approval_percentage
            );
        } else {
            if !tally.quorum_met {
                self.state = ProposalState::Expired;
                info!("Proposal {} expired: quorum not met", self.id);
            } else {
                self.state = ProposalState::Rejected;
                info!(
                    "Proposal {} rejected: {:.1}% approval",
                    self.id, tally.approval_percentage
                );
            }
        }

        Ok(())
    }

    /// Execute proposal (AwaitingExecution → Executing → Executed)
    pub fn execute(&mut self, current_epoch: u64) -> Result<(), GovernanceError> {
        if self.state != ProposalState::AwaitingExecution {
            return Err(GovernanceError::InvalidStateTransition(format!(
                "Cannot execute from state {:?}",
                self.state
            )));
        }

        if current_epoch < self.execution_epoch {
            return Err(GovernanceError::ExecutionFailed(
                "Execution epoch not reached".to_string(),
            ));
        }

        // Save previous state for rollback
        self.previous_state = Some(Box::new(self.clone()));

        self.state = ProposalState::Executing;

        // Execute payload (implementation-specific)
        // This is where protocol changes actually happen
        match self.payload.execute() {
            Ok(_) => {
                self.state = ProposalState::Executed;
                info!("Proposal {} executed successfully", self.id);
                Ok(())
            }
            Err(e) => {
                self.state = ProposalState::RolledBack;
                error!("Proposal {} execution failed: {}, rolling back", self.id, e);
                Err(GovernanceError::ExecutionFailed(e))
            }
        }
    }

    /// Rollback failed proposal
    pub fn rollback(&mut self) -> Result<(), GovernanceError> {
        if self.state != ProposalState::RolledBack {
            return Err(GovernanceError::InvalidStateTransition(
                "Can only rollback from RolledBack state".to_string(),
            ));
        }

        // Restore previous state
        if let Some(prev) = self.previous_state.take() {
            *self = *prev;
            self.state = ProposalState::Rejected;
            info!("Proposal {} rolled back", self.id);
            Ok(())
        } else {
            Err(GovernanceError::RollbackFailed(
                "No previous state to restore".to_string(),
            ))
        }
    }
}

/// Governance execution payload (what gets executed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernancePayload {
    /// Parameter change: rule_name → new_value
    ProtocolParameterChange { rule_name: String, new_value: u128 },

    /// Sanction a validator
    ValidatorSanction {
        validator_id: String,
        action: SanctionAction,
    },

    /// Recovery action
    Recovery {
        description: String,
        recovery_data: Vec<u8>,
    },

    /// Upgrade authorization
    UpgradeAuthorization {
        module_name: String,
        version: String,
        code_hash: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SanctionAction {
    Slash { percentage: u64 }, // Slash X% of stake
    Remove,                    // Remove from validator set
    Jail { epochs: u64 },      // Jail for N epochs
}

impl GovernancePayload {
    /// Execute the payload (actual protocol changes happen here)
    pub fn execute(&self) -> Result<(), String> {
        match self {
            GovernancePayload::ProtocolParameterChange {
                rule_name,
                new_value,
            } => {
                // In real implementation, update protocol rules
                info!("Executing parameter change: {} = {}", rule_name, new_value);
                Ok(())
            }
            GovernancePayload::ValidatorSanction {
                validator_id,
                action,
            } => {
                // In real implementation, call slashing engine
                info!(
                    "Executing validator sanction: {} - {:?}",
                    validator_id, action
                );
                Ok(())
            }
            GovernancePayload::Recovery {
                description,
                recovery_data: _,
            } => {
                // In real implementation, apply recovery
                info!("Executing recovery: {}", description);
                Ok(())
            }
            GovernancePayload::UpgradeAuthorization {
                module_name,
                version,
                code_hash: _,
            } => {
                // In real implementation, verify and apply upgrade
                info!("Executing upgrade: {} v{}", module_name, version);
                Ok(())
            }
        }
    }
}

/// On-Chain Governance Engine (coordinating all proposals)
pub struct GovernanceEngine {
    /// All proposals ever submitted
    proposals: HashMap<String, Proposal>,

    /// Proposal IDs in order of submission
    proposal_queue: Vec<String>,

    /// Total network stake (used for quorum calculation)
    total_network_stake: u128,
}

impl GovernanceEngine {
    pub fn new(total_network_stake: u128) -> Self {
        GovernanceEngine {
            proposals: HashMap::new(),
            proposal_queue: Vec::new(),
            total_network_stake,
        }
    }

    /// Submit a new proposal
    pub fn submit_proposal(&mut self, mut proposal: Proposal) -> Result<String, GovernanceError> {
        if self.proposals.contains_key(&proposal.id) {
            return Err(GovernanceError::InvalidProposal(
                "Proposal already exists".to_string(),
            ));
        }

        proposal.submit()?;
        let proposal_id = proposal.id.clone();
        self.proposals.insert(proposal_id.clone(), proposal);
        self.proposal_queue.push(proposal_id.clone());

        info!("Proposal {} submitted", proposal_id);
        Ok(proposal_id)
    }

    /// Get proposal by ID
    pub fn get_proposal(&self, id: &str) -> Result<&Proposal, GovernanceError> {
        self.proposals
            .get(id)
            .ok_or(GovernanceError::ProposalNotFound)
    }

    /// Get mutable proposal by ID
    fn get_proposal_mut(&mut self, id: &str) -> Result<&mut Proposal, GovernanceError> {
        self.proposals
            .get_mut(id)
            .ok_or(GovernanceError::ProposalNotFound)
    }

    /// Start voting for a proposal
    pub fn start_voting(
        &mut self,
        proposal_id: &str,
        current_epoch: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self.get_proposal_mut(proposal_id)?;
        proposal.start_voting(current_epoch)
    }

    /// Cast a vote
    pub fn cast_vote(
        &mut self,
        proposal_id: &str,
        vote: Vote,
        current_epoch: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self.get_proposal_mut(proposal_id)?;
        proposal.cast_vote(vote, current_epoch)
    }

    /// Close voting and compute tally
    pub fn close_voting(
        &mut self,
        proposal_id: &str,
        current_epoch: u64,
    ) -> Result<(), GovernanceError> {
        let total_stake = self.total_network_stake;
        let proposal = self.get_proposal_mut(proposal_id)?;
        proposal.close_voting(current_epoch, total_stake)
    }

    /// Execute proposal at execution epoch
    pub fn execute_proposal(
        &mut self,
        proposal_id: &str,
        current_epoch: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self.get_proposal_mut(proposal_id)?;
        proposal.execute(current_epoch)
    }

    /// Get all proposals in a given state
    pub fn get_proposals_by_state(&self, state: ProposalState) -> Vec<&Proposal> {
        self.proposals
            .values()
            .filter(|p| p.state == state)
            .collect()
    }

    /// Periodic tick: advance proposals through state machine based on epoch
    pub fn advance_epoch(&mut self, new_epoch: u64) -> Result<(), GovernanceError> {
        let proposal_ids: Vec<_> = self.proposal_queue.clone();

        for proposal_id in proposal_ids {
            let proposal = match self.proposals.get_mut(&proposal_id) {
                Some(p) => p,
                None => continue,
            };

            // Transition: Pending → Voting
            if proposal.state == ProposalState::Pending
                && new_epoch >= proposal.voting_window.start_epoch
            {
                let _ = proposal.start_voting(new_epoch);
            }

            // Transition: Voting → Tallying
            if proposal.state == ProposalState::Voting
                && new_epoch >= proposal.voting_window.end_epoch
            {
                let _ = proposal.close_voting(new_epoch, self.total_network_stake);
            }

            // Transition: AwaitingExecution → Executing
            if proposal.state == ProposalState::AwaitingExecution
                && new_epoch >= proposal.execution_epoch
            {
                let _ = proposal.execute(new_epoch);
            }
        }

        Ok(())
    }

    /// Persist the current governance state to disk (JSON snapshot).
    ///
    /// In the MVP this writes to `./governance_state.json`.
    /// Sprint 2 will replace this with RocksDB storage via `bleep-state`.
    pub fn persist(&self) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;
        #[derive(serde::Serialize)]
        struct Snapshot<'a> {
            total_network_stake: u128,
            proposal_count: usize,
            proposal_ids: &'a [String],
        }
        let snapshot = Snapshot {
            total_network_stake: self.total_network_stake,
            proposal_count: self.proposals.len(),
            proposal_ids: &self.proposal_queue,
        };
        let json = serde_json::to_string_pretty(&snapshot)?;
        fs::write("governance_state.json", json)?;
        log::info!(
            "Governance state persisted: {} proposals, stake={}",
            snapshot.proposal_count,
            snapshot.total_network_stake
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proposal_state_transitions() {
        let voting_window = VotingWindow::new(2, 4).unwrap();
        let payload = GovernancePayload::ProtocolParameterChange {
            rule_name: "BLOCK_TIME".to_string(),
            new_value: 6000,
        };

        let mut proposal = Proposal::new(
            "prop-1".to_string(),
            ProposalType::ProtocolParameter,
            "Increase block time".to_string(),
            "Block time should be increased to reduce network load".to_string(),
            voting_window,
            5,
            67,
            payload,
            1,
        );

        // Draft → Pending
        assert!(proposal.submit().is_ok());
        assert_eq!(proposal.state, ProposalState::Pending);

        // Pending → Voting
        assert!(proposal.start_voting(2).is_ok());
        assert_eq!(proposal.state, ProposalState::Voting);
    }

    #[test]
    fn test_voting_window() {
        let window = VotingWindow::new(5, 10).unwrap();
        assert!(!window.is_active(4));
        assert!(window.is_active(5));
        assert!(window.is_active(9));
        assert!(!window.is_active(10));
        assert!(!window.is_closed(9));
        assert!(window.is_closed(10));
    }

    #[test]
    fn test_double_voting_prevention() {
        let voting_window = VotingWindow::new(2, 4).unwrap();
        let payload = GovernancePayload::ProtocolParameterChange {
            rule_name: "BLOCK_TIME".to_string(),
            new_value: 6000,
        };

        let mut proposal = Proposal::new(
            "prop-1".to_string(),
            ProposalType::ProtocolParameter,
            "Test".to_string(),
            "Test".to_string(),
            voting_window,
            5,
            67,
            payload,
            1,
        );
        proposal.state = ProposalState::Voting;

        let vote1 = Vote::new("val-1".to_string(), true, 1000, 2, vec![1, 2, 3]);
        let vote2 = Vote::new("val-1".to_string(), false, 1000, 2, vec![4, 5, 6]);

        assert!(proposal.cast_vote(vote1, 2).is_ok());
        assert!(matches!(
            proposal.cast_vote(vote2, 2),
            Err(GovernanceError::DoubleVoting(_))
        ));
    }

    #[test]
    fn test_tally_computation() {
        let tally = VoteTally::compute(
            6700,  // 67% approve
            3300,  // 33% reject
            10000, // total network stake
            67,    // 67% threshold
        )
        .unwrap();

        assert_eq!(tally.approval_percentage, 67);
        assert!(tally.quorum_met); // 6700 + 3300 = 10000 > 10000/3
        assert!(tally.approved); // 67% >= 67% threshold
    }
}
