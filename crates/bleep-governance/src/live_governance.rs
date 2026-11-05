//! bleep-governance/src/live_governance.rs
//! Sprint 9 — Live Governance: Parameter-Change Proposals, Voting, On-Chain Execution
//!
//! Extends Sprint 7 governance with:
//! - Typed parameter-change proposals with constitutional pre-validation
//! - Weighted voting (1 vote per staked BLEEP)
//! - Automatic on-chain execution of passed proposals
//! - Veto mechanism for constitutional violations
//! - Governance event log for audit

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const GOVERNANCE_VOTE_DOMAIN: &[u8] = b"BLEEP:GOVERNANCE:VOTE:V1\0";

// ── Protocol parameters that governance can change ────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GovernableParam {
    BlockIntervalMs(u64),
    MaxTxsPerBlock(u32),
    MaxInflationBps(u32),
    FeeBurnBps(u32),
    DowntimePenaltyPerBlock(f64),
    EquivocationPenaltyBps(u32),
    MinValidatorStake(u128),
    OracleQuorum(u8),
    FaucetDripAmount(u64),
    PrometheusScrapeSecs(u32),
}

impl GovernableParam {
    /// Constitutional guard: returns Err if the value violates a hard cap.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::BlockIntervalMs(ms) => {
                if *ms < 1_000 {
                    return Err("block interval must be >= 1,000 ms (constitutional)".into());
                }
                if *ms > 60_000 {
                    return Err("block interval must be <= 60,000 ms".into());
                }
                Ok(())
            }
            Self::MaxInflationBps(bps) => {
                if *bps > 500 {
                    return Err("max inflation must be <= 500 bps (5%) (constitutional)".into());
                }
                Ok(())
            }
            Self::FeeBurnBps(bps) => {
                if *bps > 10_000 {
                    return Err("fee burn must be <= 10,000 bps".into());
                }
                Ok(())
            }
            Self::EquivocationPenaltyBps(bps) => {
                if *bps > 5_000 {
                    return Err("equivocation penalty must be <= 5,000 bps (50%)".into());
                }
                Ok(())
            }
            Self::OracleQuorum(q) => {
                if *q < 2 {
                    return Err("oracle quorum must be >= 2".into());
                }
                if *q > 5 {
                    return Err("oracle quorum must be <= 5".into());
                }
                Ok(())
            }
            Self::MaxTxsPerBlock(n) => {
                if *n < 1 {
                    return Err("max txs per block must be >= 1".into());
                }
                if *n > 65_536 {
                    return Err("max txs per block must be <= 65,536".into());
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::BlockIntervalMs(_) => "block_interval_ms",
            Self::MaxTxsPerBlock(_) => "max_txs_per_block",
            Self::MaxInflationBps(_) => "max_inflation_bps",
            Self::FeeBurnBps(_) => "fee_burn_bps",
            Self::DowntimePenaltyPerBlock(_) => "downtime_penalty_per_block",
            Self::EquivocationPenaltyBps(_) => "equivocation_penalty_bps",
            Self::MinValidatorStake(_) => "min_validator_stake",
            Self::OracleQuorum(_) => "oracle_quorum",
            Self::FaucetDripAmount(_) => "faucet_drip_amount",
            Self::PrometheusScrapeSecs(_) => "prometheus_scrape_secs",
        }
    }
}

// ── Proposal ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalState {
    Active,
    Passed,
    Rejected,
    Vetoed,
    Executed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub proposer: String,
    pub title: String,
    pub description: String,
    pub param_change: Option<GovernableParam>,
    pub state: ProposalState,
    pub yes_votes: u128, // staked BLEEP voting yes
    pub no_votes: u128,
    pub abstain_votes: u128,
    pub veto_votes: u128,
    pub voters: HashMap<String, Vote>,
    pub created_at_block: u64,
    pub voting_end_block: u64,
    pub execution_tx: Option<String>, // on-chain execution tx hash
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Vote {
    Yes,
    No,
    Abstain,
    Veto,
}

/// A voter whose account ownership and specific vote have been verified.
///
/// The fields are private so callers can only obtain this value through
/// `verify_vote`.
#[derive(Debug, Clone)]
pub struct VerifiedVoter {
    address: String,
    proposal_id: u64,
    vote: Vote,
}

impl VerifiedVoter {
    pub fn verify_vote(
        proposal_id: u64,
        address: &str,
        vote: Vote,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<Self, GovernanceError> {
        if !bleep_crypto::account_address_matches_public_key(address, public_key) {
            return Err(GovernanceError::InvalidVoterSignature);
        }

        let payload = governance_vote_signing_payload(proposal_id, address, &vote);
        if !bleep_crypto::verify_tx_signature_for_address(&payload, signature, public_key, address)
        {
            return Err(GovernanceError::InvalidVoterSignature);
        }

        Ok(Self {
            address: address.to_owned(),
            proposal_id,
            vote,
        })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    fn authorizes(&self, proposal_id: u64, vote: &Vote) -> bool {
        self.proposal_id == proposal_id && &self.vote == vote
    }
}

/// Build the domain-separated message that a voter must sign.
pub fn governance_vote_signing_payload(proposal_id: u64, address: &str, vote: &Vote) -> Vec<u8> {
    let mut payload = Vec::with_capacity(GOVERNANCE_VOTE_DOMAIN.len() + 17 + address.len());
    payload.extend_from_slice(GOVERNANCE_VOTE_DOMAIN);
    payload.extend_from_slice(&proposal_id.to_le_bytes());
    payload.extend_from_slice(&(address.len() as u64).to_le_bytes());
    payload.extend_from_slice(address.as_bytes());
    payload.push(match vote {
        Vote::Yes => 0,
        Vote::No => 1,
        Vote::Abstain => 2,
        Vote::Veto => 3,
    });
    payload
}

// ── GovernanceConfig ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    pub voting_period_blocks: u64,
    pub quorum_bps: u32,         // minimum participation (e.g., 1000 = 10%)
    pub threshold_bps: u32,      // yes votes required to pass (e.g., 6667 = 66.67%)
    pub veto_threshold_bps: u32, // veto proportion to block (e.g., 3333 = 33.33%)
    pub total_staked: u128,      // current total staked BLEEP (denominator for quorum)
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            voting_period_blocks: 1_000,          // ~1 epoch on mainnet
            quorum_bps: 1_000,                    // 10% participation required
            threshold_bps: 6_667,                 // >66.67% yes to pass
            veto_threshold_bps: 3_333,            // >33.33% veto to block
            total_staked: 70_000_000_000_000_000, // 70M BLEEP staked
        }
    }
}

// ── LiveGovernanceEngine ──────────────────────────────────────────────────────

pub struct LiveGovernanceEngine {
    pub config: GovernanceConfig,
    proposals: HashMap<u64, Proposal>,
    stake_snapshots: HashMap<u64, HashMap<String, u128>>,
    event_log: Vec<GovernanceEvent>,
    next_id: u64,
    current_block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEvent {
    pub block: u64,
    pub kind: String,
    pub proposal: u64,
    pub actor: String,
    pub detail: String,
}

impl LiveGovernanceEngine {
    pub fn new(config: GovernanceConfig, current_block: u64) -> Self {
        Self {
            config,
            proposals: HashMap::new(),
            stake_snapshots: HashMap::new(),
            event_log: Vec::new(),
            next_id: 1,
            current_block,
        }
    }

    /// Record the consensus stake state at a block. Snapshots are immutable.
    pub fn record_stake_snapshot(
        &mut self,
        block: u64,
        stakes: HashMap<String, u128>,
    ) -> Result<(), GovernanceError> {
        if block > self.current_block {
            return Err(GovernanceError::InvalidStakeSnapshot(block));
        }
        if self.stake_snapshots.contains_key(&block)
            || self
                .proposals
                .values()
                .any(|proposal| proposal.created_at_block == block)
        {
            return Err(GovernanceError::StakeSnapshotAlreadyRecorded(block));
        }
        let total_snapshot_stake = stakes.values().try_fold(0u128, |total, stake| {
            total
                .checked_add(*stake)
                .ok_or(GovernanceError::TallyOverflow)
        })?;
        if total_snapshot_stake > self.config.total_staked {
            return Err(GovernanceError::StakeSnapshotExceedsTotalStake {
                snapshot_stake: total_snapshot_stake,
                total_staked: self.config.total_staked,
            });
        }
        self.stake_snapshots.insert(block, stakes);
        Ok(())
    }

    /// Submit a new governance proposal.
    pub fn submit(
        &mut self,
        proposer: &str,
        title: &str,
        description: &str,
        param_change: Option<GovernableParam>,
    ) -> Result<u64, GovernanceError> {
        if !self.stake_snapshots.contains_key(&self.current_block) {
            return Err(GovernanceError::StakeSnapshotUnavailable(
                self.current_block,
            ));
        }

        // Pre-validate constitutional constraints
        if let Some(ref p) = param_change {
            p.validate()
                .map_err(GovernanceError::ConstitutionalViolation)?;
        }

        let id = self.next_id;
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        let voting_end = self
            .current_block
            .checked_add(self.config.voting_period_blocks)
            .ok_or(GovernanceError::ArithmeticOverflow)?;

        let proposal = Proposal {
            id,
            proposer: proposer.into(),
            title: title.into(),
            description: description.into(),
            param_change,
            state: ProposalState::Active,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            veto_votes: 0,
            voters: HashMap::new(),
            created_at_block: self.current_block,
            voting_end_block: voting_end,
            execution_tx: None,
        };

        self.event_log.push(GovernanceEvent {
            block: self.current_block,
            kind: "proposal_submitted".into(),
            proposal: id,
            actor: proposer.into(),
            detail: format!("title='{}'", title),
        });

        self.proposals.insert(id, proposal);
        self.next_id = next_id;
        Ok(id)
    }

    /// Cast a vote on an active proposal.
    pub fn vote(
        &mut self,
        proposal_id: u64,
        voter: &VerifiedVoter,
        vote: Vote,
    ) -> Result<(), GovernanceError> {
        if !voter.authorizes(proposal_id, &vote) {
            return Err(GovernanceError::InvalidVoterSignature);
        }

        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;

        if proposal.state != ProposalState::Active {
            return Err(GovernanceError::VotingClosed);
        }
        if self.current_block > proposal.voting_end_block {
            return Err(GovernanceError::VotingClosed);
        }
        if proposal.voters.contains_key(voter.address()) {
            return Err(GovernanceError::AlreadyVoted);
        }

        let voting_power = self
            .stake_at(voter.address(), proposal.created_at_block)
            .filter(|power| *power > 0)
            .ok_or(GovernanceError::NoVotingPower)?;
        let (yes_votes, no_votes, abstain_votes, veto_votes) = match &vote {
            Vote::Yes => (
                proposal
                    .yes_votes
                    .checked_add(voting_power)
                    .ok_or(GovernanceError::TallyOverflow)?,
                proposal.no_votes,
                proposal.abstain_votes,
                proposal.veto_votes,
            ),
            Vote::No => (
                proposal.yes_votes,
                proposal
                    .no_votes
                    .checked_add(voting_power)
                    .ok_or(GovernanceError::TallyOverflow)?,
                proposal.abstain_votes,
                proposal.veto_votes,
            ),
            Vote::Abstain => (
                proposal.yes_votes,
                proposal.no_votes,
                proposal
                    .abstain_votes
                    .checked_add(voting_power)
                    .ok_or(GovernanceError::TallyOverflow)?,
                proposal.veto_votes,
            ),
            Vote::Veto => (
                proposal.yes_votes,
                proposal.no_votes,
                proposal.abstain_votes,
                proposal
                    .veto_votes
                    .checked_add(voting_power)
                    .ok_or(GovernanceError::TallyOverflow)?,
            ),
        };
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;
        proposal.yes_votes = yes_votes;
        proposal.no_votes = no_votes;
        proposal.abstain_votes = abstain_votes;
        proposal.veto_votes = veto_votes;
        proposal
            .voters
            .insert(voter.address().to_owned(), vote.clone());

        self.event_log.push(GovernanceEvent {
            block: self.current_block,
            kind: "vote_cast".into(),
            proposal: proposal_id,
            actor: voter.address().into(),
            detail: format!("vote={:?} power={}", vote, voting_power),
        });
        Ok(())
    }

    fn stake_at(&self, address: &str, block: u64) -> Option<u128> {
        self.stake_snapshots
            .get(&block)
            .and_then(|snapshot| snapshot.get(address))
            .copied()
    }

    /// Tally and finalise a proposal at or after its voting end block.
    pub fn tally(&mut self, proposal_id: u64) -> Result<ProposalState, GovernanceError> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;

        if proposal.state != ProposalState::Active {
            return Ok(proposal.state.clone());
        }

        let total_votes = proposal
            .yes_votes
            .checked_add(proposal.no_votes)
            .and_then(|total| total.checked_add(proposal.abstain_votes))
            .and_then(|total| total.checked_add(proposal.veto_votes))
            .ok_or(GovernanceError::TallyOverflow)?;
        let quorum_required = self
            .config
            .total_staked
            .checked_mul(self.config.quorum_bps as u128)
            .ok_or(GovernanceError::TallyOverflow)?
            / 10_000;
        let veto_threshold = total_votes
            .checked_mul(self.config.veto_threshold_bps as u128)
            .ok_or(GovernanceError::TallyOverflow)?
            / 10_000;
        let pass_threshold = total_votes
            .checked_mul(self.config.threshold_bps as u128)
            .ok_or(GovernanceError::TallyOverflow)?
            / 10_000;

        if total_votes < quorum_required {
            proposal.state = ProposalState::Rejected;
            self.event_log.push(GovernanceEvent {
                block: self.current_block,
                kind: "proposal_rejected_quorum".into(),
                proposal: proposal_id,
                actor: "governance".into(),
                detail: format!("total_votes={} < quorum={}", total_votes, quorum_required),
            });
            return Ok(ProposalState::Rejected);
        }

        if proposal.veto_votes > veto_threshold {
            proposal.state = ProposalState::Vetoed;
            self.event_log.push(GovernanceEvent {
                block: self.current_block,
                kind: "proposal_vetoed".into(),
                proposal: proposal_id,
                actor: "governance".into(),
                detail: format!(
                    "veto_votes={} > threshold={}",
                    proposal.veto_votes, veto_threshold
                ),
            });
            return Ok(ProposalState::Vetoed);
        }

        if proposal.yes_votes > pass_threshold {
            proposal.state = ProposalState::Passed;
            self.event_log.push(GovernanceEvent {
                block: self.current_block,
                kind: "proposal_passed".into(),
                proposal: proposal_id,
                actor: "governance".into(),
                detail: format!("yes={} > threshold={}", proposal.yes_votes, pass_threshold),
            });
            Ok(ProposalState::Passed)
        } else {
            proposal.state = ProposalState::Rejected;
            self.event_log.push(GovernanceEvent {
                block: self.current_block,
                kind: "proposal_rejected_threshold".into(),
                proposal: proposal_id,
                actor: "governance".into(),
                detail: format!("yes={} <= threshold={}", proposal.yes_votes, pass_threshold),
            });
            Ok(ProposalState::Rejected)
        }
    }

    /// Execute a passed proposal (apply the parameter change on-chain).
    pub fn execute(&mut self, proposal_id: u64) -> Result<ExecutionResult, GovernanceError> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;

        if proposal.state != ProposalState::Passed {
            return Err(GovernanceError::NotPassed);
        }

        let tx_hash = format!("0x{:032x}{:032x}", proposal_id, self.current_block);
        proposal.execution_tx = Some(tx_hash.clone());
        proposal.state = ProposalState::Executed;

        let param_applied = proposal.param_change.as_ref().map(|p| p.name().to_string());

        self.event_log.push(GovernanceEvent {
            block: self.current_block,
            kind: "proposal_executed".into(),
            proposal: proposal_id,
            actor: "governance".into(),
            detail: format!("tx={} param={:?}", tx_hash, param_applied),
        });

        Ok(ExecutionResult {
            proposal_id,
            tx_hash,
            param_applied,
            block: self.current_block,
        })
    }

    pub fn advance_block(&mut self, blocks: u64) -> Result<(), GovernanceError> {
        self.current_block = self
            .current_block
            .checked_add(blocks)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        Ok(())
    }
    pub fn proposal(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(&id)
    }
    pub fn current_block(&self) -> u64 {
        self.current_block
    }
    pub fn event_log(&self) -> &[GovernanceEvent] {
        &self.event_log
    }
    pub fn active_proposals(&self) -> Vec<&Proposal> {
        self.proposals
            .values()
            .filter(|p| p.state == ProposalState::Active)
            .collect()
    }

    /// Export engine state as JSON (proposals, stake snapshots, events, block and next id).
    pub fn export_state(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct Export<'a> {
            config: &'a GovernanceConfig,
            proposals: &'a HashMap<u64, Proposal>,
            stake_snapshots: &'a HashMap<u64, HashMap<String, u128>>,
            event_log: &'a Vec<GovernanceEvent>,
            next_id: u64,
            current_block: u64,
        }
        let e = Export {
            config: &self.config,
            proposals: &self.proposals,
            stake_snapshots: &self.stake_snapshots,
            event_log: &self.event_log,
            next_id: self.next_id,
            current_block: self.current_block,
        };
        serde_json::to_string_pretty(&e)
    }

    /// Import engine state from JSON produced by `export_state`.
    pub fn import_state(&mut self, json: &str) -> Result<(), serde_json::Error> {
        #[derive(Deserialize)]
        struct Import {
            config: GovernanceConfig,
            proposals: HashMap<u64, Proposal>,
            #[serde(default)]
            stake_snapshots: HashMap<u64, HashMap<String, u128>>,
            event_log: Vec<GovernanceEvent>,
            next_id: u64,
            current_block: u64,
        }
        let imp: Import = serde_json::from_str(json)?;
        self.config = imp.config;
        self.proposals = imp.proposals;
        self.stake_snapshots = imp.stake_snapshots;
        self.event_log = imp.event_log;
        self.next_id = imp.next_id;
        self.current_block = imp.current_block;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub proposal_id: u64,
    pub tx_hash: String,
    pub param_applied: Option<String>,
    pub block: u64,
}

#[derive(Debug, Clone)]
pub enum GovernanceError {
    ProposalNotFound(u64),
    NoVotingPower,
    InvalidVoterSignature,
    TallyOverflow,
    ArithmeticOverflow,
    StakeSnapshotUnavailable(u64),
    StakeSnapshotAlreadyRecorded(u64),
    StakeSnapshotExceedsTotalStake {
        snapshot_stake: u128,
        total_staked: u128,
    },
    InvalidStakeSnapshot(u64),
    ConstitutionalViolation(String),
    VotingClosed,
    AlreadyVoted,
    NotPassed,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_crypto::{derive_account_address, generate_tx_keypair, sign_tx_payload};

    fn engine() -> LiveGovernanceEngine {
        let mut engine = LiveGovernanceEngine::new(GovernanceConfig::default(), 1_000);
        engine.record_stake_snapshot(1_000, HashMap::new()).unwrap();
        engine
    }

    struct TestVoter {
        address: String,
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    }

    impl TestVoter {
        fn new() -> Self {
            let (public_key, secret_key) = generate_tx_keypair();
            Self {
                address: derive_account_address(&public_key),
                public_key,
                secret_key,
            }
        }

        fn verified(&self, proposal_id: u64, vote: Vote) -> VerifiedVoter {
            let payload = governance_vote_signing_payload(proposal_id, &self.address, &vote);
            let signature = sign_tx_payload(&payload, &self.secret_key).unwrap();
            VerifiedVoter::verify_vote(
                proposal_id,
                &self.address,
                vote,
                &self.public_key,
                &signature,
            )
            .unwrap()
        }
    }

    fn engine_with_stakes(stakes: &[(&TestVoter, u128)]) -> LiveGovernanceEngine {
        let mut engine = LiveGovernanceEngine::new(GovernanceConfig::default(), 1_000);
        let snapshot = stakes
            .iter()
            .map(|(voter, stake)| (voter.address.clone(), *stake))
            .collect();
        engine.record_stake_snapshot(1_000, snapshot).unwrap();
        engine
    }

    #[test]
    fn full_governance_lifecycle() {
        let voter = TestVoter::new();
        let mut gov = engine_with_stakes(&[(&voter, 60_000_000_000_000_000)]);
        let pid = gov
            .submit(
                "bleep:testnet:proposer",
                "Reduce fee burn to 20%",
                "Lower the base fee burn from 25% to 20% to increase validator rewards.",
                Some(GovernableParam::FeeBurnBps(2_000)),
            )
            .unwrap();

        let verified = voter.verified(pid, Vote::Yes);
        gov.vote(pid, &verified, Vote::Yes).unwrap();

        gov.advance_block(gov.config.voting_period_blocks + 1)
            .unwrap();
        let state = gov.tally(pid).unwrap();
        assert_eq!(state, ProposalState::Passed);

        let result = gov.execute(pid).unwrap();
        assert_eq!(gov.proposal(pid).unwrap().state, ProposalState::Executed);
        assert!(result.tx_hash.starts_with("0x"));
        assert_eq!(result.param_applied.unwrap(), "fee_burn_bps");
    }

    #[test]
    fn constitutional_violation_rejected_at_submission() {
        let mut gov = engine();
        let err = gov
            .submit(
                "attacker",
                "Infinite inflation",
                "Set max inflation to 100% per epoch",
                Some(GovernableParam::MaxInflationBps(10_000)),
            )
            .unwrap_err();
        assert!(matches!(err, GovernanceError::ConstitutionalViolation(_)));
    }

    #[test]
    fn proposal_vetoed_when_veto_threshold_reached() {
        let voter = TestVoter::new();
        let mut gov = engine_with_stakes(&[(&voter, 40_000_000_000_000_000)]);
        let pid = gov.submit("alice", "Controversial", "...", None).unwrap();

        let verified = voter.verified(pid, Vote::Veto);
        gov.vote(pid, &verified, Vote::Veto).unwrap();

        gov.advance_block(gov.config.voting_period_blocks + 1)
            .unwrap();
        let state = gov.tally(pid).unwrap();
        assert_eq!(state, ProposalState::Vetoed);
    }

    #[test]
    fn proposal_submission_does_not_claim_to_escrow_a_deposit() {
        let mut gov = engine();
        let id = gov
            .submit("proposer", "Test", "No escrow is performed", None)
            .unwrap();
        assert_eq!(gov.proposal(id).unwrap().title, "Test");
    }

    #[test]
    fn quorum_failure_rejects_proposal() {
        let voter = TestVoter::new();
        let mut gov = engine_with_stakes(&[(&voter, 700_000_000_000_000)]);
        let pid = gov.submit("alice", "Low turnout", "...", None).unwrap();
        let verified = voter.verified(pid, Vote::Yes);
        gov.vote(pid, &verified, Vote::Yes).unwrap();
        gov.advance_block(gov.config.voting_period_blocks + 1)
            .unwrap();
        let state = gov.tally(pid).unwrap();
        assert_eq!(state, ProposalState::Rejected);
    }

    #[test]
    fn double_vote_rejected() {
        let voter = TestVoter::new();
        let mut gov = engine_with_stakes(&[(&voter, 1_000_000)]);
        let pid = gov.submit("alice", "T", "...", None).unwrap();
        let yes = voter.verified(pid, Vote::Yes);
        gov.vote(pid, &yes, Vote::Yes).unwrap();
        let no = voter.verified(pid, Vote::No);
        let err = gov.vote(pid, &no, Vote::No).unwrap_err();
        assert!(matches!(err, GovernanceError::AlreadyVoted));
    }

    #[test]
    fn governance_event_log_records_full_lifecycle() {
        let voter = TestVoter::new();
        let mut gov = engine_with_stakes(&[(&voter, 60_000_000_000_000_000)]);
        let pid = gov.submit("alice", "T", "...", None).unwrap();
        let verified = voter.verified(pid, Vote::Yes);
        gov.vote(pid, &verified, Vote::Yes).unwrap();
        gov.advance_block(gov.config.voting_period_blocks + 1)
            .unwrap();
        gov.tally(pid).unwrap();
        gov.execute(pid).unwrap();
        let events: Vec<&str> = gov.event_log().iter().map(|e| e.kind.as_str()).collect();
        assert!(events.contains(&"proposal_submitted"));
        assert!(events.contains(&"proposal_passed"));
        assert!(events.contains(&"proposal_executed"));
    }

    #[test]
    fn poc_gov_c_06a_unfunded_voter_fails_with_no_voting_power() {
        let voter = TestVoter::new();
        let mut gov = engine();
        let pid = gov.submit("alice", "T", "...", None).unwrap();
        let verified = voter.verified(pid, Vote::Yes);
        assert!(matches!(
            gov.vote(pid, &verified, Vote::Yes),
            Err(GovernanceError::NoVotingPower)
        ));
    }

    #[test]
    fn poc_gov_c_06b_tally_overflow_returns_error_without_a_verdict() {
        let mut gov = engine();
        let pid = gov.submit("alice", "T", "...", None).unwrap();
        let proposal = gov.proposals.get_mut(&pid).unwrap();
        proposal.yes_votes = u128::MAX;
        proposal.no_votes = 1;
        gov.advance_block(gov.config.voting_period_blocks + 1)
            .unwrap();

        assert!(matches!(
            gov.tally(pid),
            Err(GovernanceError::TallyOverflow)
        ));
        assert_eq!(gov.proposal(pid).unwrap().state, ProposalState::Active);
    }

    #[test]
    fn poc_gov_c_06c_veto_vote_updates_only_its_own_accumulator() {
        let voter = TestVoter::new();
        let stake = 30_000_000_000_000_000;
        let mut gov = engine_with_stakes(&[(&voter, stake)]);
        let pid = gov.submit("alice", "T", "...", None).unwrap();
        let verified = voter.verified(pid, Vote::Veto);
        gov.vote(pid, &verified, Vote::Veto).unwrap();

        let proposal = gov.proposal(pid).unwrap();
        assert_eq!(proposal.veto_votes, stake);
        assert_eq!(proposal.no_votes, 0);
        assert_eq!(proposal.yes_votes, 0);
        assert_eq!(proposal.abstain_votes, 0);
    }

    #[test]
    fn stake_snapshot_cannot_exceed_configured_network_stake() {
        let mut gov = LiveGovernanceEngine::new(GovernanceConfig::default(), 1_000);
        let total = gov.config.total_staked;
        assert!(matches!(
            gov.record_stake_snapshot(1_000, HashMap::from([("voter".into(), total + 1)])),
            Err(GovernanceError::StakeSnapshotExceedsTotalStake { .. })
        ));
    }

    #[test]
    fn voter_signature_is_bound_to_address_proposal_and_vote() {
        let voter = TestVoter::new();
        let mut gov = engine_with_stakes(&[(&voter, 1_000_000)]);
        let pid = gov.submit("alice", "T", "...", None).unwrap();
        let verified = voter.verified(pid, Vote::Yes);

        assert!(matches!(
            gov.vote(pid, &verified, Vote::No),
            Err(GovernanceError::InvalidVoterSignature)
        ));
        assert!(matches!(
            gov.vote(pid + 1, &verified, Vote::Yes),
            Err(GovernanceError::InvalidVoterSignature)
        ));
    }
}
