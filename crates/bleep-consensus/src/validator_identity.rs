// PHASE 1: VALIDATOR IDENTITY & POST-QUANTUM SECURITY
// Each validator has a persistent, post-quantum-secure identity
//
// SAFETY INVARIANTS:
// 1. Each validator has a unique on-chain identifier
// 2. Validator keys are cryptographically derived from post-quantum primitives
// 3. Validator identity includes reputation and slashing history
// 4. Double-signing is impossible: same key cannot sign two conflicting blocks
// 5. Validator lifecycle is enforced via state machine

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt;

/// Validator identity using post-quantum cryptography.
///
/// SAFETY: This structure holds the authoritative validator record.
/// All validator operations must reference this identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorIdentity {
    /// Unique on-chain validator ID (typically derived from public key)
    pub id: String,

    /// Kyber-1024 public key for key encapsulation (post-quantum security)
    pub kyber_public_key: Vec<u8>,

    /// Ed25519-style deterministic signing key for protocol messages
    pub signing_key_id: String,

    /// Stake amount in microBLEEP
    pub stake: u128,

    /// Current state of the validator
    pub state: ValidatorState,

    /// Reputation score (0.0 to 1.0)
    pub reputation: f64,

    /// Number of double-signing incidents (PERMANENT RECORD)
    pub double_sign_count: u32,

    /// Number of equivocation incidents (PERMANENT RECORD)
    pub equivocation_count: u32,

    /// Number of downtime incidents
    pub downtime_count: u32,

    /// Epoch when validator joined
    pub joined_epoch: u64,

    /// Epoch when validator exited (if applicable)
    pub exited_epoch: Option<u64>,

    /// Total slashed amount (cumulative across all incidents)
    pub total_slashed: u128,
}

impl ValidatorIdentity {
    /// Create a new validator identity.
    ///
    /// SAFETY: This is the only way to register a new validator.
    /// The validator's identity is immutable after registration.
    pub fn new(
        id: String,
        kyber_public_key: Vec<u8>,
        signing_key_id: String,
        stake: u128,
        joined_epoch: u64,
    ) -> Result<Self, String> {
        if id.is_empty() {
            return Err("Validator ID cannot be empty".to_string());
        }
        if stake == 0 {
            return Err("Validator stake must be > 0".to_string());
        }
        if kyber_public_key.len() != 1568 {
            return Err("Kyber-1024 public key must be 1568 bytes".to_string());
        }

        Ok(ValidatorIdentity {
            id,
            kyber_public_key,
            signing_key_id,
            stake,
            state: ValidatorState::Inactive,
            reputation: 1.0,
            double_sign_count: 0,
            equivocation_count: 0,
            downtime_count: 0,
            joined_epoch,
            exited_epoch: None,
            total_slashed: 0,
        })
    }

    /// Activate this validator for consensus participation.
    ///
    /// SAFETY: Can only transition from Inactive → Active
    pub fn activate(&mut self) -> Result<(), String> {
        match self.state {
            ValidatorState::Inactive => {
                self.state = ValidatorState::Active;
                Ok(())
            }
            _ => Err(format!(
                "Cannot activate validator in state {:?}",
                self.state
            )),
        }
    }

    /// Mark validator for exit (pending epoch end).
    ///
    /// SAFETY: Can transition from Active → PendingExit
    pub fn mark_for_exit(&mut self) -> Result<(), String> {
        match self.state {
            ValidatorState::Active => {
                self.state = ValidatorState::PendingExit;
                Ok(())
            }
            _ => Err(format!(
                "Cannot mark validator for exit in state {:?}",
                self.state
            )),
        }
    }

    /// Finalize exit (after pending epoch ends).
    ///
    /// SAFETY: Transitions PendingExit → Exited
    pub fn finalize_exit(&mut self, exit_epoch: u64) -> Result<(), String> {
        match self.state {
            ValidatorState::PendingExit => {
                self.state = ValidatorState::Exited;
                self.exited_epoch = Some(exit_epoch);
                Ok(())
            }
            _ => Err(format!(
                "Cannot finalize exit for validator in state {:?}",
                self.state
            )),
        }
    }

    /// Record a double-signing incident and slash the validator.
    ///
    /// SAFETY: This incident is permanent and irreversible.
    /// The validator is immediately ejected and heavily slashed.
    pub fn slash_for_double_signing(&mut self, slash_amount: u128) -> Result<(), String> {
        if slash_amount > self.stake {
            return Err(format!(
                "Slash amount {} exceeds stake {}",
                slash_amount, self.stake
            ));
        }

        self.double_sign_count += 1;
        self.stake = self.stake.saturating_sub(slash_amount);
        self.total_slashed = self.total_slashed.saturating_add(slash_amount);
        self.reputation *= 0.5; // Halve reputation
        self.state = ValidatorState::Slashed;

        Ok(())
    }

    /// Record an equivocation incident and slash the validator.
    pub fn slash_for_equivocation(&mut self, slash_amount: u128) -> Result<(), String> {
        if slash_amount > self.stake {
            return Err(format!(
                "Slash amount {} exceeds stake {}",
                slash_amount, self.stake
            ));
        }

        self.equivocation_count += 1;
        self.stake = self.stake.saturating_sub(slash_amount);
        self.total_slashed = self.total_slashed.saturating_add(slash_amount);
        self.reputation *= 0.75;
        self.state = ValidatorState::Slashed;

        Ok(())
    }

    /// Record downtime and apply light penalty.
    pub fn record_downtime(&mut self, slash_amount: u128) -> Result<(), String> {
        if slash_amount > self.stake {
            return Err(format!(
                "Slash amount {} exceeds stake {}",
                slash_amount, self.stake
            ));
        }

        self.downtime_count += 1;
        self.stake = self.stake.saturating_sub(slash_amount);
        self.total_slashed = self.total_slashed.saturating_add(slash_amount);
        self.reputation *= 0.95; // Light penalty

        Ok(())
    }

    /// Check if this validator can participate in consensus.
    ///
    /// SAFETY: Only Active validators with positive reputation can participate
    pub fn can_participate(&self) -> bool {
        matches!(self.state, ValidatorState::Active)
            && self.reputation > 0.0
            && self.stake > 0
            && self.double_sign_count == 0
    }

    /// Check if this validator has been permanently ejected.
    pub fn is_ejected(&self) -> bool {
        matches!(
            self.state,
            ValidatorState::Slashed | ValidatorState::Ejected
        ) || self.double_sign_count > 0
    }

    /// Get the effective stake (accounting for slashing).
    pub fn effective_stake(&self) -> u128 {
        if self.is_ejected() {
            0
        } else {
            self.stake
        }
    }
}

impl fmt::Display for ValidatorIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Validator {} (state={:?}, stake={}, reputation={:.2}%)",
            self.id,
            self.state,
            self.stake,
            self.reputation * 100.0
        )
    }
}

/// Validator lifecycle state machine.
///
/// SAFETY: Transitions are strictly defined. Invalid transitions fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorState {
    /// Validator is registered but not active
    Inactive,

    /// Validator is participating in consensus
    Active,

    /// Validator has requested exit; pending epoch end
    PendingExit,

    /// Validator has exited and is no longer active
    Exited,

    /// Validator has been slashed and permanently removed
    Slashed,

    /// Validator has been ejected (extreme case)
    Ejected,
}

impl fmt::Display for ValidatorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidatorState::Inactive => write!(f, "INACTIVE"),
            ValidatorState::Active => write!(f, "ACTIVE"),
            ValidatorState::PendingExit => write!(f, "PENDING_EXIT"),
            ValidatorState::Exited => write!(f, "EXITED"),
            ValidatorState::Slashed => write!(f, "SLASHED"),
            ValidatorState::Ejected => write!(f, "EJECTED"),
        }
    }
}

/// Registry of all validators on the chain.
///
/// SAFETY: This is the authoritative validator set.
/// All consensus operations reference this registry.
pub struct ValidatorRegistry {
    /// Map of validator ID to validator identity
    validators: HashMap<String, ValidatorIdentity>,

    /// Set of currently active validator IDs (cached for performance)
    active_validators: BTreeSet<String>,

    /// Total stake of all active validators (cached for performance)
    total_active_stake: u128,
}

impl ValidatorRegistry {
    /// Create a new validator registry.
    pub fn new() -> Self {
        ValidatorRegistry {
            validators: HashMap::new(),
            active_validators: BTreeSet::new(),
            total_active_stake: 0,
        }
    }

    /// Register a new validator.
    ///
    /// SAFETY: Validator ID must be globally unique.
    pub fn register_validator(&mut self, validator: ValidatorIdentity) -> Result<(), String> {
        if self.validators.contains_key(&validator.id) {
            return Err(format!("Validator {} already registered", validator.id));
        }

        self.validators.insert(validator.id.clone(), validator);
        Ok(())
    }

    /// Get a validator by ID (immutable reference).
    pub fn get(&self, id: &str) -> Option<&ValidatorIdentity> {
        self.validators.get(id)
    }

    /// Get a validator by ID (mutable reference).
    ///
    /// SAFETY: Used when modifying validator state (slashing, status changes)
    pub fn get_mut(&mut self, id: &str) -> Option<&mut ValidatorIdentity> {
        self.validators.get_mut(id)
    }

    /// Activate a validator for consensus participation.
    ///
    /// SAFETY: Updates the active validator set and total stake.
    pub fn activate_validator(&mut self, id: &str) -> Result<(), String> {
        let validator_stake = {
            let validator = self
                .get_mut(id)
                .ok_or_else(|| format!("Validator {} not found", id))?;
            validator.activate()?;
            validator.stake
        };

        self.active_validators.insert(id.to_string());
        self.total_active_stake = self.total_active_stake.saturating_add(validator_stake);

        Ok(())
    }

    /// Mark a validator for exit.
    ///
    /// SAFETY: Removes from active set but doesn't finalize exit yet.
    pub fn mark_validator_for_exit(&mut self, id: &str) -> Result<(), String> {
        let stake = {
            let validator = self
                .get_mut(id)
                .ok_or_else(|| format!("Validator {} not found", id))?;

            validator.mark_for_exit()?;
            validator.stake
        };

        self.active_validators.remove(id);
        self.total_active_stake = self.total_active_stake.saturating_sub(stake);

        Ok(())
    }

    /// Finalize validator exit.
    pub fn finalize_validator_exit(&mut self, id: &str, epoch: u64) -> Result<(), String> {
        let validator = self
            .get_mut(id)
            .ok_or_else(|| format!("Validator {} not found", id))?;

        validator.finalize_exit(epoch)
    }

    /// Slash a validator for double-signing.
    ///
    /// SAFETY: This action is irreversible.
    pub fn slash_validator_double_sign(
        &mut self,
        id: &str,
        slash_amount: u128,
    ) -> Result<(), String> {
        let validator = self
            .get_mut(id)
            .ok_or_else(|| format!("Validator {} not found", id))?;

        validator.slash_for_double_signing(slash_amount)?;

        self.active_validators.remove(id);
        self.total_active_stake = self.total_active_stake.saturating_sub(slash_amount);

        Ok(())
    }

    /// Slash a validator for equivocation.
    pub fn slash_validator_equivocation(
        &mut self,
        id: &str,
        slash_amount: u128,
    ) -> Result<(), String> {
        let validator = self
            .get_mut(id)
            .ok_or_else(|| format!("Validator {} not found", id))?;

        validator.slash_for_equivocation(slash_amount)?;

        self.active_validators.remove(id);
        self.total_active_stake = self.total_active_stake.saturating_sub(slash_amount);

        Ok(())
    }

    /// Record downtime for a validator.
    pub fn record_validator_downtime(
        &mut self,
        id: &str,
        slash_amount: u128,
    ) -> Result<(), String> {
        let validator = self
            .get_mut(id)
            .ok_or_else(|| format!("Validator {} not found", id))?;

        validator.record_downtime(slash_amount)
    }

    /// Get all active validators.
    pub fn get_active_validators(&self) -> Vec<&ValidatorIdentity> {
        self.active_validators
            .iter()
            .filter_map(|id| self.validators.get(id))
            .collect()
    }

    /// Get total stake of all active validators.
    pub fn total_active_stake(&self) -> u128 {
        self.total_active_stake
    }

    /// Get a validator's voting power (effective stake).
    pub fn get_voting_power(&self, id: &str) -> u128 {
        self.get(id).map(|v| v.effective_stake()).unwrap_or(0)
    }

    /// Get the count of active validators.
    pub fn active_count(&self) -> usize {
        self.active_validators.len()
    }

    /// Check if validator can participate.
    pub fn can_participate(&self, id: &str) -> bool {
        self.get(id).map(|v| v.can_participate()).unwrap_or(false)
    }
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity(id: &str) -> ValidatorIdentity {
        ValidatorIdentity::new(
            id.to_string(),
            vec![0u8; 1568], // Mock Kyber key
            format!("{}_signing_key", id),
            1000000,
            0,
        )
        .unwrap()
    }

    #[test]
    fn test_validator_identity_creation() {
        let v = create_test_identity("v1");
        assert_eq!(v.id, "v1");
        assert_eq!(v.stake, 1000000);
        assert_eq!(v.state, ValidatorState::Inactive);
    }

    #[test]
    fn test_validator_activation() {
        let mut v = create_test_identity("v1");
        assert_eq!(v.state, ValidatorState::Inactive);

        v.activate().unwrap();
        assert_eq!(v.state, ValidatorState::Active);
        assert!(v.can_participate());
    }

    #[test]
    fn test_validator_state_transition() {
        let mut v = create_test_identity("v1");
        v.activate().unwrap();
        v.mark_for_exit().unwrap();
        assert_eq!(v.state, ValidatorState::PendingExit);

        v.finalize_exit(1).unwrap();
        assert_eq!(v.state, ValidatorState::Exited);
        assert!(!v.can_participate());
    }

    #[test]
    fn test_validator_double_sign_slashing() {
        let mut v = create_test_identity("v1");
        v.activate().unwrap();

        v.slash_for_double_signing(100000).unwrap();
        assert_eq!(v.stake, 900000);
        assert_eq!(v.double_sign_count, 1);
        assert!(!v.can_participate());
    }

    #[test]
    fn test_validator_registry_activation() {
        let mut registry = ValidatorRegistry::new();
        let v = create_test_identity("v1");

        registry.register_validator(v).unwrap();
        registry.activate_validator("v1").unwrap();

        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.total_active_stake(), 1000000);
    }

    #[test]
    fn test_validator_registry_slashing() {
        let mut registry = ValidatorRegistry::new();
        let v = create_test_identity("v1");

        registry.register_validator(v).unwrap();
        registry.activate_validator("v1").unwrap();

        registry.slash_validator_double_sign("v1", 100000).unwrap();

        assert_eq!(registry.active_count(), 0);
        let validator = registry.get("v1").unwrap();
        assert_eq!(validator.stake, 900000);
    }

    #[test]
    fn test_validator_registry_voting_power() {
        let mut registry = ValidatorRegistry::new();
        let v = create_test_identity("v1");

        registry.register_validator(v).unwrap();
        registry.activate_validator("v1").unwrap();

        assert_eq!(registry.get_voting_power("v1"), 1000000);

        registry.slash_validator_equivocation("v1", 100000).unwrap();
        assert_eq!(registry.get_voting_power("v1"), 0); // Slashed = no power
    }
}
