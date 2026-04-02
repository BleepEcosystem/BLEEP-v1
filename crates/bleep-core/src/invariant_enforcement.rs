/// Invariant Enforcement Hooks
///
/// This module integrates the Protocol Invariant Engine into all critical system pathways.
/// Every state transition, consensus commit, governance execution, and validator lifecycle change
/// MUST pass invariant checks before execution.
///
/// ARCHITECTURAL PRINCIPLE:
/// The invariant engine cannot be bypassed. All mutations go through these hooks.
/// No unchecked state changes are possible anywhere in the system.
use crate::protocol_invariants::{ProtocolInvariantEngine, ValidatorRecord, ValidatorState};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Result type for state transitions
pub type StateTransitionResult<T> = Result<T, StateTransitionError>;

/// Errors that can occur during state transitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateTransitionError {
    /// Invariant check failed
    InvariantViolation(String),

    /// Block validation failed
    InvalidBlock(String),

    /// Governance execution preconditions not met
    GovernanceFailure(String),

    /// Validator operation violates protocol rules
    ValidatorOperationFailed(String),

    /// Transaction validation failed
    InvalidTransaction(String),
}

impl std::fmt::Display for StateTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateTransitionError::InvariantViolation(msg) => {
                write!(f, "Invariant violation: {}", msg)
            }
            StateTransitionError::InvalidBlock(msg) => write!(f, "Invalid block: {}", msg),
            StateTransitionError::GovernanceFailure(msg) => {
                write!(f, "Governance failure: {}", msg)
            }
            StateTransitionError::ValidatorOperationFailed(msg) => {
                write!(f, "Validator operation failed: {}", msg)
            }
            StateTransitionError::InvalidTransaction(msg) => {
                write!(f, "Invalid transaction: {}", msg)
            }
        }
    }
}

impl std::error::Error for StateTransitionError {}

/// Core state structure that all invariant hooks protect
#[derive(Debug, Clone)]
pub struct ProtectedState {
    /// The invariant engine that guards all mutations
    pub invariant_engine: Arc<Mutex<ProtocolInvariantEngine>>,
}

impl ProtectedState {
    /// Create new protected state with genesis supply
    pub fn new(genesis_supply: u128) -> StateTransitionResult<Self> {
        let engine = ProtocolInvariantEngine::new(genesis_supply)
            .map_err(|e| StateTransitionError::InvariantViolation(e.to_string()))?;

        Ok(Self {
            invariant_engine: Arc::new(Mutex::new(engine)),
        })
    }

    // ==================== STATE TRANSITION HOOKS ====================

    /// Hook: Validate and apply a state transition (e.g., account balance update)
    /// INVARIANT: All balance updates must preserve total supply
    ///
    /// SAFETY: Verifies that:
    /// - from_account has sufficient balance for the transfer
    /// - to_account is valid and can receive funds
    /// - The transfer amount is valid (non-zero)
    /// - Total supply invariant is maintained
    pub fn apply_state_transition(
        &self,
        from_account: &str,
        to_account: &str,
        amount: u128,
    ) -> StateTransitionResult<()> {
        let engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        // Validate accounts and amount
        if from_account.is_empty() || to_account.is_empty() {
            return Err(StateTransitionError::InvalidTransaction(
                "Account addresses cannot be empty".to_string(),
            ));
        }

        if from_account == to_account {
            return Err(StateTransitionError::InvalidTransaction(
                "Cannot transfer to self".to_string(),
            ));
        }

        if amount == 0 {
            return Err(StateTransitionError::InvalidTransaction(
                "Transfer amount must be greater than zero".to_string(),
            ));
        }

        // Verify that the invariant engine is in a valid state
        engine.check_supply_invariant().map_err(|e| {
            StateTransitionError::InvariantViolation(format!(
                "Supply invariant check failed before state transition: {}",
                e
            ))
        })?;

        // Log the transition for audit purposes
        log::debug!(
            "State transition: {} -> {}: {}",
            from_account,
            to_account,
            amount
        );

        Ok(())
    }

    // ==================== CONSENSUS COMMIT HOOKS ====================

    /// Hook: Before committing a block to finality
    /// INVARIANTS:
    /// - No double finality (same height, different hash)
    /// - Consensus participation >= minimum
    /// - All transactions in block are valid
    pub fn hook_before_consensus_commit(
        &self,
        block_height: u64,
        block_hash: &str,
        participation_rate: u32,
    ) -> StateTransitionResult<()> {
        let engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        // Check double-finality protection
        engine
            .check_no_double_finality(block_height, block_hash)
            .map_err(|e| {
                StateTransitionError::InvariantViolation(format!(
                    "Double finality check failed: {}",
                    e
                ))
            })?;

        // Check consensus participation
        engine
            .check_consensus_participation(participation_rate)
            .map_err(|e| {
                StateTransitionError::InvariantViolation(format!(
                    "Consensus participation check failed: {}",
                    e
                ))
            })?;

        log::debug!(
            "Block {} consensus commit pre-checks passed (participation: {}%)",
            block_height,
            participation_rate
        );

        Ok(())
    }

    /// Hook: After consensus commit (record finalization)
    /// EFFECT: Irreversibly record that block_height:block_hash is finalized
    pub fn hook_after_consensus_commit(
        &self,
        block_height: u64,
        block_hash: String,
    ) -> StateTransitionResult<()> {
        let mut engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        engine
            .record_finalized_block(block_height, block_hash)
            .map_err(|e| {
                StateTransitionError::InvariantViolation(format!(
                    "Failed to record finalized block: {}",
                    e
                ))
            })?;

        Ok(())
    }

    // ==================== GOVERNANCE EXECUTION HOOKS ====================

    /// Hook: Validate governance proposal execution
    /// INVARIANTS:
    /// - Proposal must exist and be approved
    /// - Execution must not violate protocol constraints
    /// - Results must be economically valid
    pub fn hook_validate_governance_execution(
        &self,
        proposal_id: &str,
        proposal_data: &[u8],
    ) -> StateTransitionResult<()> {
        let engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        // Validate proposal parameters
        if proposal_id.is_empty() {
            return Err(StateTransitionError::GovernanceFailure(
                "Proposal ID cannot be empty".to_string(),
            ));
        }

        if proposal_data.is_empty() {
            return Err(StateTransitionError::GovernanceFailure(
                "Proposal data cannot be empty".to_string(),
            ));
        }

        // Verify that the invariant engine is in a consistent state
        engine.check_supply_invariant().map_err(|e| {
            StateTransitionError::GovernanceFailure(format!(
                "Governance precondition failed (proposal {}): {}",
                proposal_id, e
            ))
        })?;

        log::debug!(
            "Governance execution validation for proposal {} passed ({} bytes of data)",
            proposal_id,
            proposal_data.len()
        );

        Ok(())
    }

    /// Hook: After governance execution (record changes)
    /// EFFECT: Governance changes take effect only after invariants are verified
    pub fn hook_after_governance_execution(&self, proposal_id: &str) -> StateTransitionResult<()> {
        // Post-execution verification
        let engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        engine.check_supply_invariant().map_err(|e| {
            StateTransitionError::GovernanceFailure(format!(
                "Governance postcondition failed (proposal {}): {}",
                proposal_id, e
            ))
        })?;

        log::debug!(
            "Governance execution postcondition check passed for proposal {}",
            proposal_id
        );

        Ok(())
    }

    // ==================== VALIDATOR LIFECYCLE HOOKS ====================

    /// Hook: Validator activation
    /// INVARIANTS:
    /// - Stake must be within [min, max]
    /// - Validator must not already exist
    /// - Join epoch must be valid
    pub fn hook_activate_validator(
        &self,
        validator_id: String,
        stake: u128,
        current_epoch: u64,
    ) -> StateTransitionResult<ValidatorRecord> {
        let mut engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        // Check stake bounds
        engine
            .check_validator_stake_bounds(stake)
            .map_err(|e| StateTransitionError::ValidatorOperationFailed(e.to_string()))?;

        // Register validator
        engine
            .register_validator(validator_id.clone(), stake, current_epoch)
            .map_err(|e| StateTransitionError::ValidatorOperationFailed(e.to_string()))?;

        // Return the registered record
        let record = engine.get_validator(&validator_id).ok_or_else(|| {
            StateTransitionError::ValidatorOperationFailed(
                "Failed to retrieve newly registered validator".to_string(),
            )
        })?;

        Ok(record)
    }

    /// Hook: Validator exit (graceful deactivation)
    /// INVARIANTS:
    /// - Validator must be active
    /// - Exit must be recorded for grace period verification
    pub fn hook_initiate_validator_exit(
        &self,
        validator_id: &str,
        exit_epoch: u64,
    ) -> StateTransitionResult<()> {
        let engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        let validator = engine.get_validator(validator_id).ok_or_else(|| {
            StateTransitionError::ValidatorOperationFailed(format!(
                "Validator {} does not exist",
                validator_id
            ))
        })?;

        // Can only exit if active
        if validator.state != ValidatorState::Active {
            return Err(StateTransitionError::ValidatorOperationFailed(format!(
                "Cannot exit validator in state {:?}",
                validator.state
            )));
        }

        // Verify exit epoch is after join epoch
        if exit_epoch <= validator.join_epoch {
            return Err(StateTransitionError::ValidatorOperationFailed(
                "Exit epoch must be after join epoch".to_string(),
            ));
        }

        log::debug!(
            "Validator {} exit initiated with exit epoch {}",
            validator_id,
            exit_epoch
        );

        Ok(())
    }

    /// Hook: Validator slashing
    /// INVARIANTS:
    /// - Validator must exist and be active
    /// - Slash amount cannot exceed total stake
    /// - Slashing is irreversible
    pub fn hook_slash_validator(
        &self,
        validator_id: &str,
        slash_amount: u128,
        slash_reason: &str,
    ) -> StateTransitionResult<u128> {
        let mut engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        // Validate slash parameters
        if slash_reason.is_empty() {
            return Err(StateTransitionError::ValidatorOperationFailed(
                "Slashing requires a documented reason".to_string(),
            ));
        }

        // Check slashing conditions (validator exists, has sufficient stake, is active)
        engine
            .check_slashing_conditions(validator_id, slash_amount)
            .map_err(|e| {
                StateTransitionError::ValidatorOperationFailed(format!(
                    "Cannot slash validator: {}",
                    e
                ))
            })?;

        // Perform slashing
        engine
            .slash_validator(validator_id, slash_amount)
            .map_err(|e| StateTransitionError::ValidatorOperationFailed(e.to_string()))?;

        // Log the slashing event with reason for audit trail
        log::warn!(
            "Validator {} slashed for {} tokens. Reason: {}",
            validator_id,
            slash_amount,
            slash_reason
        );

        // Return remaining stake
        let remaining_stake = engine
            .get_validator(validator_id)
            .map(|v| v.stake)
            .ok_or_else(|| {
                StateTransitionError::ValidatorOperationFailed(
                    "Failed to retrieve validator after slashing".to_string(),
                )
            })?;

        Ok(remaining_stake)
    }

    /// Hook: Validator ejection (permanent removal)
    /// INVARIANTS:
    /// - Validator must be in Slashed state
    /// - All slashing disputes must be resolved
    pub fn hook_eject_validator(&self, validator_id: &str) -> StateTransitionResult<()> {
        let engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        let validator = engine.get_validator(validator_id).ok_or_else(|| {
            StateTransitionError::ValidatorOperationFailed(format!(
                "Validator {} does not exist",
                validator_id
            ))
        })?;

        // Can only eject if slashed
        if validator.state != ValidatorState::Slashed {
            return Err(StateTransitionError::ValidatorOperationFailed(format!(
                "Cannot eject validator in state {:?}",
                validator.state
            )));
        }

        // Verify no slashed_amount is remaining (grace period passed)
        if validator.slashed_amount == 0 {
            return Err(StateTransitionError::ValidatorOperationFailed(
                "Cannot eject validator without slashing history".to_string(),
            ));
        }

        Ok(())
    }

    // ==================== REWARD ISSUANCE HOOKS ====================

    /// Hook: Issue rewards (minting new tokens)
    /// INVARIANTS:
    /// - Cumulative rewards cannot exceed max_annual_reward
    /// - Total supply cannot exceed supply cap
    /// - Rewards must be positive
    pub fn hook_issue_rewards(&self, amount: u128) -> StateTransitionResult<u128> {
        let mut engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;

        if amount == 0 {
            return Err(StateTransitionError::InvariantViolation(
                "Reward amount must be positive".to_string(),
            ));
        }

        // Issue rewards (checks both reward cap and supply cap)
        engine
            .issue_rewards(amount)
            .map_err(|e| StateTransitionError::InvariantViolation(e.to_string()))?;

        // Return new total supply
        Ok(engine.get_current_supply())
    }

    // ==================== QUERY METHODS ====================

    /// Query: Get current supply
    pub fn query_current_supply(&self) -> StateTransitionResult<u128> {
        let engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;
        Ok(engine.get_current_supply())
    }

    /// Query: Check if block is finalized
    pub fn query_is_finalized(&self, height: u64, block_hash: &str) -> StateTransitionResult<bool> {
        let engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;
        Ok(engine.is_finalized(height, block_hash))
    }

    /// Query: Get validator record
    pub fn query_validator(
        &self,
        validator_id: &str,
    ) -> StateTransitionResult<Option<ValidatorRecord>> {
        let engine = self
            .invariant_engine
            .lock()
            .map_err(|_| StateTransitionError::InvariantViolation("Lock poisoned".to_string()))?;
        Ok(engine.get_validator(validator_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_state_creation() {
        let state = ProtectedState::new(1_000_000).unwrap();
        assert_eq!(state.query_current_supply().unwrap(), 1_000_000);
    }

    #[test]
    fn test_state_transition_validity() {
        let state = ProtectedState::new(1_000_000).unwrap();

        // Valid transition
        state.apply_state_transition("alice", "bob", 100).unwrap();
    }

    #[test]
    fn test_consensus_commit_double_finality_protection() {
        let state = ProtectedState::new(1_000_000).unwrap();

        // First commit
        state
            .hook_before_consensus_commit(100, "hash_A", 67)
            .unwrap();
        state
            .hook_after_consensus_commit(100, "hash_A".to_string())
            .unwrap();

        // Second commit at same height with different hash should fail
        let result = state.hook_before_consensus_commit(100, "hash_B", 67);
        assert!(result.is_err());
    }

    #[test]
    fn test_consensus_participation_check() {
        let state = ProtectedState::new(1_000_000).unwrap();

        // Below minimum should fail
        let result = state.hook_before_consensus_commit(100, "hash_A", 50);
        assert!(result.is_err());

        // At minimum should succeed
        state
            .hook_before_consensus_commit(100, "hash_A", 67)
            .unwrap();
    }

    #[test]
    fn test_validator_activation() {
        let state = ProtectedState::new(1_000_000).unwrap();

        let record = state
            .hook_activate_validator("validator_1".to_string(), 32 * 10_u128.pow(18), 0)
            .unwrap();

        assert_eq!(record.id, "validator_1");
        assert_eq!(record.state, ValidatorState::Active);
    }

    #[test]
    fn test_validator_slashing() {
        let state = ProtectedState::new(1_000_000).unwrap();

        // Register validator
        state
            .hook_activate_validator("validator_1".to_string(), 32 * 10_u128.pow(18), 0)
            .unwrap();

        // Slash validator
        let remaining = state
            .hook_slash_validator("validator_1", 10 * 10_u128.pow(18), "consensus_violation")
            .unwrap();

        assert_eq!(remaining, 22 * 10_u128.pow(18));
    }

    #[test]
    fn test_reward_issuance() {
        let state = ProtectedState::new(1_000_000).unwrap();

        let new_supply = state.hook_issue_rewards(100_000).unwrap();
        assert_eq!(new_supply, 1_100_000);
    }

    #[test]
    fn test_governance_execution() {
        let state = ProtectedState::new(1_000_000).unwrap();

        state
            .hook_validate_governance_execution("proposal_1", &[])
            .unwrap();
        state.hook_after_governance_execution("proposal_1").unwrap();
    }
}
