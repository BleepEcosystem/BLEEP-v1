// PHASE 2: ON-CHAIN GOVERNANCE CORE
pub mod deterministic_executor;
pub mod governance_core;

// PHASE 4: CONSTITUTIONAL GOVERNANCE LAYER
pub mod constitution;
pub mod forkless_upgrades;
pub mod governance_binding;
pub mod proposal_lifecycle;
pub mod zk_voting;

// PHASE 5: AI-Driven Protocol Evolution Layer
pub mod ai_hooks;
pub mod ai_reputation;
pub mod apip;
pub mod deterministic_activation;
pub mod governance_engine;
pub mod governance_voting;
pub mod invariant_monitoring;
pub mod protocol_evolution;
pub mod protocol_rules;
pub mod safety_constraints;

#[cfg(test)]
mod phase5_integration_tests;

#[cfg(test)]
mod phase5_comprehensive_tests;

#[cfg(test)]
mod phase4_governance_tests;

pub use governance_core::{
    GovernanceEngine, GovernanceError, GovernancePayload, Proposal, ProposalState, ProposalType,
    SanctionAction, Vote, VoteTally, VotingWindow,
};

pub use deterministic_executor::{
    DeterministicExecutor, ExecutionError, ExecutionLogEntry, ExecutionRecord, ExecutionStatus,
};

pub use constitution::{
    BLEEPConstitution, ConstitutionalConstraint, ConstitutionalScope, ConstraintRule,
    GovernanceAction, RuleType, ValidationResult,
};

pub use zk_voting::{
    EligibilityProof, EncryptedBallot, TallyProof, VoteCommitment, VoteTally as ZKVoteTally,
    VoterRole, VotingBallot, ZKVotingEngine, ZKVotingError,
};

pub use proposal_lifecycle::{
    ProposalArchive, ProposalError, ProposalLifecycleManager, ProposalRecord,
    ProposalState as LifecycleProposalState, ProposalStateTransition,
};

pub use forkless_upgrades::{
    ApprovedUpgrade, MigrationType, ProtocolUpgradeManager, StateMigration, UpgradeCheckpoint,
    UpgradeError, UpgradePayload, UpgradePreconditions, UpgradeStatus, Version,
};

pub use governance_binding::{ActivationRecord, GovernanceConsensusBinding, ProposalOutcome};

pub use protocol_rules::{
    ProtocolRule, ProtocolRuleSet, ProtocolRuleSetFactory, RuleBounds, RuleValue, RuleVersion,
};

pub use apip::{
    AIModelMetadata, APIPBuilder, APIPStatus, RiskLevel, RuleChange, SafetyBounds, APIP,
};

pub use safety_constraints::{
    CheckSeverity, ConstraintCheckResult, SafetyConstraintsEngine, ValidationReport,
};

pub use ai_reputation::{
    AIReputation, AIReputationTracker, ProposalOutcome as ReputationProposalOutcome,
    ReputationRecord,
};

pub use protocol_evolution::{
    ActivationRecord as EvolutionActivationRecord, ProtocolEvolutionOrchestrator, VotingResult,
};

pub use ai_hooks::{
    AIHooks, AIHooksValidator, AdvisoryScore, HistoricalAnalysis, OptimizationSuggestion,
    SimulationResult,
};

pub use invariant_monitoring::{
    GlobalHealth, GlobalInvariantMonitor, HealthStatus, InvariantMonitor, InvariantSeverity,
    InvariantThreshold, InvariantType, ViolationRecord,
};

pub use governance_voting::{
    GovernanceVotingEngine, ProposalVotingState, ValidatorVote, VotingError,
    VotingResult as GovernanceVotingResult, VotingWindow as GovernanceVotingWindow,
};

pub use deterministic_activation::{
    ActivationError, ActivationPlan, ActivationState, DeterministicActivationManager,
};

/// Initialize BLEEP governance with Phase 5 protocol evolution layer
///
/// SAFETY: Creates deterministic protocol state with genesis rules,
/// configures AI-driven evolution system, and initializes AI reputation tracking.
pub fn init_governance() -> Result<ProtocolEvolutionOrchestrator, Box<dyn std::error::Error>> {
    let genesis_ruleset = ProtocolRuleSetFactory::create_genesis()?;
    let orchestrator = ProtocolEvolutionOrchestrator::new(genesis_ruleset);
    Ok(orchestrator)
}

// ── Sprint 9 modules ──────────────────────────────────────────────────────────
pub mod live_governance;

pub use live_governance::{GovernanceConfig, LiveGovernanceEngine};
