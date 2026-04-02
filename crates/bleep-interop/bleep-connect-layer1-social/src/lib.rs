//! # bleep-connect-layer1-social
//!
//! Social consensus layer: on-chain governance for catastrophic scenarios.
//! Used for chain reorgs, quantum attacks, smart contract bugs, and protocol upgrades.
//!
//! ## Governance Flow
//! 1. Any stakeholder submits a proposal with evidence
//! 2. Voters (validators, users, developers) cast votes during the voting period
//! 3. If threshold is met, the proposal is executed
//! 4. Emergency proposals have a shorter window (24h) but higher threshold (80%)

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use bleep_connect_commitment_chain::CommitmentChain;
use bleep_connect_crypto::{sha256, ClassicalKeyPair};
use bleep_connect_types::{
    constants::{
        VOTING_PERIOD_EMERGENCY, VOTING_PERIOD_NORMAL, VOTING_THRESHOLD_EMERGENCY,
        VOTING_THRESHOLD_NORMAL,
    },
    BleepConnectError, BleepConnectResult, CommitmentType, Evidence, ProposalType, SocialProposal,
    StateCommitment, UniversalAddress, Vote, VoteChoice, VoterType,
};

// ─────────────────────────────────────────────────────────────────────────────
// PROPOSAL OUTCOME
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ProposalOutcome {
    Approved,
    Rejected,
    Expired,
    Pending,
}

#[derive(Debug, Clone)]
pub struct ProposalResult {
    pub proposal_id: [u8; 32],
    pub outcome: ProposalOutcome,
    pub for_votes: u128,
    pub against_votes: u128,
    pub abstain_votes: u128,
    pub total_voting_power: u128,
    pub approval_percentage: f64,
    pub decided_at: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// VOTER REGISTRY
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RegisteredVoter {
    pub address: UniversalAddress,
    pub voter_type: VoterType,
    pub voting_power: u128,
    pub public_key: [u8; 32],
}

pub struct VoterRegistry {
    voters: DashMap<String, RegisteredVoter>,
    total_voting_power: Arc<RwLock<u128>>,
}

impl VoterRegistry {
    pub fn new() -> Self {
        Self {
            voters: DashMap::new(),
            total_voting_power: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn register(&self, voter: RegisteredVoter) {
        let power = voter.voting_power;
        self.voters.insert(voter.address.to_string(), voter);
        *self.total_voting_power.write().await += power;
    }

    pub fn get(&self, address: &str) -> Option<RegisteredVoter> {
        self.voters.get(address).map(|e| e.value().clone())
    }

    pub async fn total_power(&self) -> u128 {
        *self.total_voting_power.read().await
    }

    pub fn verify_voter_signature(&self, address: &str, message: &[u8], signature: &[u8]) -> bool {
        match self.get(address) {
            Some(voter) => {
                ClassicalKeyPair::verify(&voter.public_key, message, signature).unwrap_or(false)
            }
            None => false,
        }
    }
}

impl Default for VoterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPOSAL STORE
// ─────────────────────────────────────────────────────────────────────────────

pub struct ProposalStore {
    proposals: DashMap<[u8; 32], SocialProposal>,
    votes: DashMap<[u8; 32], Vec<Vote>>, // proposal_id → votes
    results: DashMap<[u8; 32], ProposalResult>,
}

impl ProposalStore {
    pub fn new() -> Self {
        Self {
            proposals: DashMap::new(),
            votes: DashMap::new(),
            results: DashMap::new(),
        }
    }

    pub fn store_proposal(&self, proposal: SocialProposal) {
        self.proposals.insert(proposal.proposal_id, proposal);
    }

    pub fn get_proposal(&self, id: &[u8; 32]) -> Option<SocialProposal> {
        self.proposals.get(id).map(|e| e.value().clone())
    }

    pub fn cast_vote(&self, vote: Vote) -> BleepConnectResult<()> {
        let id = vote.proposal_id;
        // Check proposal exists and is open
        let proposal = self
            .proposals
            .get(&id)
            .ok_or_else(|| BleepConnectError::InternalError("Proposal not found".into()))?;

        if now() > proposal.voting_deadline {
            return Err(BleepConnectError::InternalError(
                "Voting period has ended".into(),
            ));
        }

        // Prevent double-voting
        let mut votes = self.votes.entry(id).or_insert_with(Vec::new);
        if votes.iter().any(|v| v.voter == vote.voter) {
            return Err(BleepConnectError::InternalError("Already voted".into()));
        }

        votes.push(vote);
        Ok(())
    }

    pub fn get_votes(&self, proposal_id: &[u8; 32]) -> Vec<Vote> {
        self.votes
            .get(proposal_id)
            .map(|e| e.value().clone())
            .unwrap_or_default()
    }

    pub fn store_result(&self, result: ProposalResult) {
        self.results.insert(result.proposal_id, result);
    }

    pub fn get_result(&self, id: &[u8; 32]) -> Option<ProposalResult> {
        self.results.get(id).map(|e| e.value().clone())
    }
}

impl Default for ProposalStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ARBITRATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

pub struct ArbitrationEngine;

impl ArbitrationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Tally votes and determine outcome.
    pub async fn tally(
        &self,
        proposal: &SocialProposal,
        votes: &[Vote],
        registry: &VoterRegistry,
    ) -> ProposalResult {
        let mut for_votes = 0u128;
        let mut against_votes = 0u128;
        let mut abstain_votes = 0u128;

        for vote in votes {
            // Verify signature
            let addr = vote.voter.to_string();
            let voter = match registry.get(&addr) {
                Some(v) => v,
                None => continue,
            };

            // Verify vote signature: sign over (proposal_id || vote_choice || voting_power)
            let mut msg = proposal.proposal_id.to_vec();
            msg.push(vote.vote as u8);
            msg.extend_from_slice(&vote.voting_power.to_be_bytes());

            if !ClassicalKeyPair::verify(&voter.public_key, &sha256(&msg), &vote.signature)
                .unwrap_or(false)
            {
                warn!("Invalid signature from voter {}", addr);
                continue;
            }

            let power = vote.voting_power.min(voter.voting_power); // clamp to registered power
            match vote.vote {
                VoteChoice::Approve => for_votes += power,
                VoteChoice::Reject => against_votes += power,
                VoteChoice::Abstain => abstain_votes += power,
            }
        }

        let total = registry.total_power().await;
        let counted = for_votes + against_votes + abstain_votes;
        let threshold = self.get_threshold(proposal);
        let approval_pct = if counted > 0 {
            for_votes as f64 / counted as f64
        } else {
            0.0
        };

        let outcome = if now() > proposal.voting_deadline {
            if approval_pct >= threshold {
                ProposalOutcome::Approved
            } else {
                ProposalOutcome::Expired
            }
        } else if approval_pct >= threshold {
            ProposalOutcome::Approved
        } else {
            ProposalOutcome::Pending
        };

        info!(
            "Tally for proposal {}: for={}, against={}, abstain={}, approval={:.1}%, threshold={:.0}%, outcome={:?}",
            hex::encode(proposal.proposal_id),
            for_votes, against_votes, abstain_votes,
            approval_pct * 100.0, threshold * 100.0, outcome
        );

        ProposalResult {
            proposal_id: proposal.proposal_id,
            outcome,
            for_votes,
            against_votes,
            abstain_votes,
            total_voting_power: total,
            approval_percentage: approval_pct,
            decided_at: now(),
        }
    }

    fn get_threshold(&self, proposal: &SocialProposal) -> f64 {
        match &proposal.proposal_type {
            ProposalType::EmergencyPause { .. } => VOTING_THRESHOLD_EMERGENCY,
            ProposalType::StateRollback { .. } => VOTING_THRESHOLD_EMERGENCY,
            _ => VOTING_THRESHOLD_NORMAL,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EMERGENCY CONTROLLER
// ─────────────────────────────────────────────────────────────────────────────

pub struct EmergencyController {
    is_paused: Arc<RwLock<bool>>,
    pause_reason: Arc<RwLock<Option<String>>>,
}

impl EmergencyController {
    pub fn new() -> Self {
        Self {
            is_paused: Arc::new(RwLock::new(false)),
            pause_reason: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn pause(&self, reason: String) {
        *self.is_paused.write().await = true;
        *self.pause_reason.write().await = Some(reason.clone());
        error!("PROTOCOL PAUSED: {}", reason);
    }

    pub async fn resume(&self) {
        *self.is_paused.write().await = false;
        *self.pause_reason.write().await = None;
        info!("Protocol resumed");
    }

    pub async fn is_paused(&self) -> bool {
        *self.is_paused.read().await
    }

    pub async fn pause_reason(&self) -> Option<String> {
        self.pause_reason.read().await.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 1: MAIN COORDINATOR
// ─────────────────────────────────────────────────────────────────────────────

pub struct Layer1Social {
    proposals: Arc<ProposalStore>,
    voters: Arc<VoterRegistry>,
    arbitration: Arc<ArbitrationEngine>,
    emergency: Arc<EmergencyController>,
    commitment_chain: Arc<CommitmentChain>,
}

impl Layer1Social {
    pub fn new(commitment_chain: Arc<CommitmentChain>) -> Self {
        Self {
            proposals: Arc::new(ProposalStore::new()),
            voters: Arc::new(VoterRegistry::new()),
            arbitration: Arc::new(ArbitrationEngine::new()),
            emergency: Arc::new(EmergencyController::new()),
            commitment_chain,
        }
    }

    pub async fn register_voter(&self, voter: RegisteredVoter) {
        self.voters.register(voter).await;
    }

    /// Submit a governance proposal. Returns the proposal ID.
    pub async fn submit_proposal(
        &self,
        proposer: UniversalAddress,
        proposal_type: ProposalType,
        title: String,
        description: String,
        evidence: Vec<Evidence>,
    ) -> BleepConnectResult<[u8; 32]> {
        let is_emergency = matches!(
            &proposal_type,
            ProposalType::EmergencyPause { .. } | ProposalType::StateRollback { .. }
        );
        let period = if is_emergency {
            VOTING_PERIOD_EMERGENCY.as_secs()
        } else {
            VOTING_PERIOD_NORMAL.as_secs()
        };

        let ts = now();
        let proposal_id = {
            let mut data = proposer.to_string().into_bytes();
            data.extend_from_slice(title.as_bytes());
            data.extend_from_slice(&ts.to_be_bytes());
            sha256(&data)
        };

        let proposal = SocialProposal {
            proposal_id,
            proposal_type,
            proposer,
            title,
            description,
            evidence,
            created_at: ts,
            voting_deadline: ts + period,
        };

        self.proposals.store_proposal(proposal);

        // Anchor to commitment chain
        let mut commitment_data = Vec::new();
        commitment_data.extend_from_slice(b"L1-PROPOSAL");
        commitment_data.extend_from_slice(&proposal_id);
        let commitment = StateCommitment {
            commitment_id: sha256(&commitment_data),
            commitment_type: CommitmentType::SocialDecision,
            data_hash: proposal_id,
            layer: 1,
            created_at: ts,
        };
        self.commitment_chain.submit_commitment(commitment).await?;

        info!(
            "Proposal {} submitted; voting closes at {}",
            hex::encode(proposal_id),
            ts + period
        );
        Ok(proposal_id)
    }

    /// Cast a vote on a proposal.
    pub fn cast_vote(&self, vote: Vote) -> BleepConnectResult<()> {
        // Verify the voter is registered
        let addr = vote.voter.to_string();
        if self.voters.get(&addr).is_none() {
            return Err(BleepConnectError::InternalError(format!(
                "Voter {} not registered",
                addr
            )));
        }
        self.proposals.cast_vote(vote)
    }

    /// Tally votes and finalize a proposal. Can be called after voting deadline.
    pub async fn finalize_proposal(
        &self,
        proposal_id: [u8; 32],
    ) -> BleepConnectResult<ProposalResult> {
        let proposal = self
            .proposals
            .get_proposal(&proposal_id)
            .ok_or_else(|| BleepConnectError::InternalError("Proposal not found".into()))?;

        let votes = self.proposals.get_votes(&proposal_id);
        let result = self
            .arbitration
            .tally(&proposal, &votes, &self.voters)
            .await;

        // Execute approved proposals
        if result.outcome == ProposalOutcome::Approved {
            self.execute_proposal(&proposal, &result).await?;
        }

        self.proposals.store_result(result.clone());

        // Anchor decision to commitment chain
        let mut decision_id_data = Vec::new();
        decision_id_data.extend_from_slice(b"L1-DECISION");
        decision_id_data.extend_from_slice(&proposal_id);
        let mut data_hash_input = Vec::new();
        data_hash_input.extend_from_slice(&result.for_votes.to_be_bytes());
        data_hash_input.extend_from_slice(&result.against_votes.to_be_bytes());
        let commitment = StateCommitment {
            commitment_id: sha256(&decision_id_data),
            commitment_type: CommitmentType::SocialDecision,
            data_hash: sha256(&data_hash_input),
            layer: 1,
            created_at: now(),
        };
        self.commitment_chain.submit_commitment(commitment).await?;

        Ok(result)
    }

    pub async fn execute_proposal(
        &self,
        proposal: &SocialProposal,
        _result: &ProposalResult,
    ) -> BleepConnectResult<()> {
        match &proposal.proposal_type {
            ProposalType::EmergencyPause { reason } => {
                self.emergency.pause(reason.clone()).await;
            }
            ProposalType::StateRollback {
                target_block,
                affected_transfers,
            } => {
                warn!(
                    "State rollback approved to block {}, affecting {} transfers",
                    target_block,
                    affected_transfers.len()
                );
                // In production: trigger rollback on commitment chain
            }
            ProposalType::ProtocolUpgrade {
                upgrade_version,
                audit_report_hash,
            } => {
                info!(
                    "Protocol upgrade to {} approved (audit: {})",
                    upgrade_version,
                    hex::encode(audit_report_hash)
                );
                // In production: apply upgrade via governance multisig
            }
            ProposalType::ParameterChange {
                parameter,
                old_value,
                new_value,
            } => {
                info!(
                    "Parameter change: {} from {} to {} approved",
                    parameter, old_value, new_value
                );
                // In production: update parameter in configuration store
            }
            ProposalType::DisputeResolution {
                transfer_id,
                ruling,
            } => {
                info!(
                    "Dispute for transfer {} resolved: {}",
                    hex::encode(transfer_id),
                    ruling
                );
                // In production: apply ruling (slash, refund, release)
            }
        }
        Ok(())
    }

    pub fn get_proposal(&self, id: &[u8; 32]) -> Option<SocialProposal> {
        self.proposals.get_proposal(id)
    }

    pub fn get_result(&self, id: &[u8; 32]) -> Option<ProposalResult> {
        self.proposals.get_result(id)
    }

    pub async fn is_paused(&self) -> bool {
        self.emergency.is_paused().await
    }

    pub async fn resume(&self) {
        self.emergency.resume().await;
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_connect_commitment_chain::{CommitmentChain, Validator};
    use bleep_connect_types::AssetId;
    use tempfile::tempdir;

    async fn make_layer1() -> (Layer1Social, Vec<(RegisteredVoter, ClassicalKeyPair)>) {
        let dir = tempdir().unwrap();
        let kp = ClassicalKeyPair::generate();
        let v = Validator::new(kp.public_key_bytes(), 1_000_000);
        let chain = Arc::new(CommitmentChain::new(dir.path(), kp, vec![v]).unwrap());
        let layer1 = Layer1Social::new(chain);

        let mut voters = Vec::new();
        for (i, vtype) in [VoterType::Validator, VoterType::Developer, VoterType::User]
            .iter()
            .enumerate()
        {
            let kp = ClassicalKeyPair::generate();
            let voter = RegisteredVoter {
                address: UniversalAddress::new(ChainId::BLEEP, format!("voter{}", i)),
                voter_type: *vtype,
                voting_power: 1_000,
                public_key: kp.public_key_bytes(),
            };
            layer1.register_voter(voter.clone()).await;
            voters.push((voter, kp));
        }
        (layer1, voters)
    }

    #[tokio::test]
    async fn test_proposal_lifecycle() {
        let (layer1, voters) = make_layer1().await;

        let proposal_id = layer1
            .submit_proposal(
                voters[0].0.address.clone(),
                ProposalType::ParameterChange {
                    parameter: "auction_duration".into(),
                    old_value: "15".into(),
                    new_value: "20".into(),
                },
                "Increase auction duration".into(),
                "Give executors more time to bid".into(),
                vec![],
            )
            .await
            .unwrap();

        // All 3 voters approve
        for (voter, kp) in &voters {
            let mut msg = proposal_id.to_vec();
            msg.push(VoteChoice::Approve as u8);
            msg.extend_from_slice(&1000u128.to_be_bytes());
            let sig = kp.sign(&sha256(&msg));

            layer1
                .cast_vote(Vote {
                    voter: voter.address.clone(),
                    voter_type: voter.voter_type,
                    proposal_id,
                    vote: VoteChoice::Approve,
                    voting_power: 1_000,
                    voted_at: now(),
                    signature: sig,
                })
                .unwrap();
        }

        // Finalize (force as if deadline passed by checking tally)
        // Note: In test we can set the deadline to the past by injecting, but
        // for this test we just verify the approval percentage is correct
        let result = layer1.finalize_proposal(proposal_id).await.unwrap();
        // 3000 for / 3000 total = 100% approval > 66% threshold
        assert!(result.approval_percentage > 0.66);
        assert_eq!(result.for_votes, 3_000);
    }

    #[tokio::test]
    async fn test_emergency_pause() {
        let (layer1, _) = make_layer1().await;
        assert!(!layer1.is_paused().await);
        layer1
            .emergency
            .pause("Quantum attack detected".into())
            .await;
        assert!(layer1.is_paused().await);
        layer1.resume().await;
        assert!(!layer1.is_paused().await);
    }
}
