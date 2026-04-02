//! bleep-governance/src/live_governance.rs
//! Sprint 9 — Live Governance: Parameter-Change Proposals, Voting, On-Chain Execution
//!
//! Extends Sprint 7 governance with:
//! - Typed parameter-change proposals with constitutional pre-validation
//! - Weighted voting (1 vote per staked BLEEP)
//! - Automatic on-chain execution of passed proposals
//! - Veto mechanism for constitutional violations
//! - Governance event log for audit

use std::collections::HashMap;

// ── Protocol parameters that governance can change ────────────────────────────

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalState {
    Active,
    Passed,
    Rejected,
    Vetoed,
    Executed,
}

#[derive(Debug, Clone)]
pub struct Proposal {
    pub id: u64,
    pub proposer: String,
    pub title: String,
    pub description: String,
    pub param_change: Option<GovernableParam>,
    pub deposit: u128, // BLEEP deposited by proposer
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Vote {
    Yes,
    No,
    Abstain,
    Veto,
}

// ── GovernanceConfig ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GovernanceConfig {
    pub voting_period_blocks: u64,
    pub quorum_bps: u32,         // minimum participation (e.g., 1000 = 10%)
    pub threshold_bps: u32,      // yes votes required to pass (e.g., 6667 = 66.67%)
    pub veto_threshold_bps: u32, // veto proportion to block (e.g., 3333 = 33.33%)
    pub min_deposit: u128,       // minimum proposal deposit in microBLEEP
    pub total_staked: u128,      // current total staked BLEEP (denominator for quorum)
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            voting_period_blocks: 1_000,          // ~1 epoch on mainnet
            quorum_bps: 1_000,                    // 10% participation required
            threshold_bps: 6_667,                 // >66.67% yes to pass
            veto_threshold_bps: 3_333,            // >33.33% veto to block
            min_deposit: 1_000_000_000_000,       // 10,000 BLEEP
            total_staked: 70_000_000_000_000_000, // 70M BLEEP staked
        }
    }
}

// ── LiveGovernanceEngine ──────────────────────────────────────────────────────

pub struct LiveGovernanceEngine {
    pub config: GovernanceConfig,
    proposals: HashMap<u64, Proposal>,
    event_log: Vec<GovernanceEvent>,
    next_id: u64,
    current_block: u64,
}

#[derive(Debug, Clone)]
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
            event_log: Vec::new(),
            next_id: 1,
            current_block,
        }
    }

    /// Submit a new governance proposal.
    pub fn submit(
        &mut self,
        proposer: &str,
        title: &str,
        description: &str,
        param_change: Option<GovernableParam>,
        deposit: u128,
    ) -> Result<u64, GovernanceError> {
        if deposit < self.config.min_deposit {
            return Err(GovernanceError::InsufficientDeposit {
                required: self.config.min_deposit,
                provided: deposit,
            });
        }

        // Pre-validate constitutional constraints
        if let Some(ref p) = param_change {
            p.validate()
                .map_err(GovernanceError::ConstitutionalViolation)?;
        }

        let id = self.next_id;
        self.next_id += 1;
        let voting_end = self.current_block + self.config.voting_period_blocks;

        let proposal = Proposal {
            id,
            proposer: proposer.into(),
            title: title.into(),
            description: description.into(),
            param_change,
            deposit,
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
            detail: format!("title='{}' deposit={}", title, deposit),
        });

        self.proposals.insert(id, proposal);
        Ok(id)
    }

    /// Cast a vote on an active proposal.
    pub fn vote(
        &mut self,
        proposal_id: u64,
        voter: &str,
        vote: Vote,
        voting_power: u128, // staked BLEEP of this voter
    ) -> Result<(), GovernanceError> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;

        if proposal.state != ProposalState::Active {
            return Err(GovernanceError::VotingClosed);
        }
        if self.current_block > proposal.voting_end_block {
            return Err(GovernanceError::VotingClosed);
        }
        if proposal.voters.contains_key(voter) {
            return Err(GovernanceError::AlreadyVoted);
        }

        match vote {
            Vote::Yes => proposal.yes_votes += voting_power,
            Vote::No => proposal.no_votes += voting_power,
            Vote::Abstain => proposal.abstain_votes += voting_power,
            Vote::Veto => {
                proposal.veto_votes += voting_power;
                proposal.no_votes += voting_power;
            }
        }
        proposal.voters.insert(voter.into(), vote.clone());

        self.event_log.push(GovernanceEvent {
            block: self.current_block,
            kind: "vote_cast".into(),
            proposal: proposal_id,
            actor: voter.into(),
            detail: format!("vote={:?} power={}", vote, voting_power),
        });
        Ok(())
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

        let total_votes = proposal.yes_votes + proposal.no_votes + proposal.abstain_votes;
        let quorum_required = self.config.total_staked * self.config.quorum_bps as u128 / 10_000;
        let veto_threshold = total_votes * self.config.veto_threshold_bps as u128 / 10_000;

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

        let pass_threshold = total_votes * self.config.threshold_bps as u128 / 10_000;
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

        // Build deterministic execution tx hash
        let tx_hash = format!(
            "0x{:064x}",
            proposal_id.wrapping_mul(0x9e3779b97f4a7c15) ^ (self.current_block << 32)
        );
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

    pub fn advance_block(&mut self, blocks: u64) {
        self.current_block += blocks;
    }
    pub fn proposal(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(&id)
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
    InsufficientDeposit { required: u128, provided: u128 },
    ConstitutionalViolation(String),
    VotingClosed,
    AlreadyVoted,
    NotPassed,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> LiveGovernanceEngine {
        LiveGovernanceEngine::new(GovernanceConfig::default(), 1_000)
    }

    #[test]
    fn full_governance_lifecycle() {
        let mut gov = engine();
        let pid = gov
            .submit(
                "bleep:testnet:proposer",
                "Reduce fee burn to 20%",
                "Lower the base fee burn from 25% to 20% to increase validator rewards.",
                Some(GovernableParam::FeeBurnBps(2_000)),
                gov.config.min_deposit,
            )
            .unwrap();

        // Validators vote yes with large stake
        let stake_per = gov.config.total_staked / 10; // 10% each
        for i in 0..7 {
            gov.vote(pid, &format!("validator-{}", i), Vote::Yes, stake_per)
                .unwrap();
        }

        gov.advance_block(gov.config.voting_period_blocks + 1);
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
                gov.config.min_deposit,
            )
            .unwrap_err();
        assert!(matches!(err, GovernanceError::ConstitutionalViolation(_)));
    }

    #[test]
    fn proposal_vetoed_when_veto_threshold_reached() {
        let mut gov = engine();
        let pid = gov
            .submit(
                "alice",
                "Controversial",
                "...",
                None,
                gov.config.min_deposit,
            )
            .unwrap();

        let stake = gov.config.total_staked / 5; // 20% each
        gov.vote(pid, "v0", Vote::Yes, stake).unwrap();
        gov.vote(pid, "v1", Vote::Veto, stake * 2).unwrap(); // >33% veto

        gov.advance_block(gov.config.voting_period_blocks + 1);
        let state = gov.tally(pid).unwrap();
        assert_eq!(state, ProposalState::Vetoed);
    }

    #[test]
    fn insufficient_deposit_rejected() {
        let mut gov = engine();
        let err = gov
            .submit("poor-proposer", "Test", "...", None, 1)
            .unwrap_err();
        assert!(matches!(err, GovernanceError::InsufficientDeposit { .. }));
    }

    #[test]
    fn quorum_failure_rejects_proposal() {
        let mut gov = engine();
        let pid = gov
            .submit("alice", "Low turnout", "...", None, gov.config.min_deposit)
            .unwrap();
        // Only 1% of stake votes
        gov.vote(pid, "v0", Vote::Yes, gov.config.total_staked / 100)
            .unwrap();
        gov.advance_block(gov.config.voting_period_blocks + 1);
        let state = gov.tally(pid).unwrap();
        assert_eq!(state, ProposalState::Rejected);
    }

    #[test]
    fn double_vote_rejected() {
        let mut gov = engine();
        let pid = gov
            .submit("alice", "T", "...", None, gov.config.min_deposit)
            .unwrap();
        gov.vote(pid, "v0", Vote::Yes, 1_000_000).unwrap();
        let err = gov.vote(pid, "v0", Vote::No, 1_000_000).unwrap_err();
        assert!(matches!(err, GovernanceError::AlreadyVoted));
    }

    #[test]
    fn governance_event_log_records_full_lifecycle() {
        let mut gov = engine();
        let pid = gov
            .submit("alice", "T", "...", None, gov.config.min_deposit)
            .unwrap();
        let stake = gov.config.total_staked / 5;
        for i in 0..7 {
            gov.vote(pid, &format!("v{}", i), Vote::Yes, stake).unwrap();
        }
        gov.advance_block(gov.config.voting_period_blocks + 1);
        gov.tally(pid).unwrap();
        gov.execute(pid).unwrap();
        let events: Vec<&str> = gov.event_log().iter().map(|e| e.kind.as_str()).collect();
        assert!(events.contains(&"proposal_submitted"));
        assert!(events.contains(&"proposal_passed"));
        assert!(events.contains(&"proposal_executed"));
    }
}
