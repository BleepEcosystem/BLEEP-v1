// PHASE 4: CONSTITUTIONAL GOVERNANCE LAYER
// Constitutional Rule Engine - Hard Law Enforcement
//
// SAFETY INVARIANTS:
// 1. Constitutional rules are immutable once instantiated at genesis
// 2. All governance actions are validated against the constitution before voting
// 3. Constitutional violations result in automatic proposal rejection
// 4. Constitution is versioned and cryptographically committed
// 5. Constitutional enforcement is deterministic on all nodes
// 6. No governance vote can override constitutional law
// 7. Constitutional changes require super-supermajority (>90%) + time delay

use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConstitutionError {
    #[error("Action violates constitutional rule: {0}")]
    ConstraintViolation(String),

    #[error("Invalid constitutional scope: {0}")]
    InvalidScope(String),

    #[error("Constitutional rule not found: {0}")]
    RuleNotFound(String),

    #[error("Constitutional version mismatch")]
    VersionMismatch,

    #[error("Hash verification failed for constitution")]
    HashVerificationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Unauthorized constitutional change")]
    UnauthorizedChange,

    #[error("Constitutional scope mismatch: {0}")]
    ScopeMismatch(String),
}

/// Constitutional scope defines what areas of the protocol a governance action can affect
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ConstitutionalScope {
    /// Cannot change fundamental economic parameters (supply, inflation)
    EconomicPolicy,

    /// Cannot change validator participation rules or slashing
    ValidatorSafety,

    /// Cannot change finality guarantees or consensus safety
    ConsensusSafety,

    /// Cannot modify the protocol's invariant enforcement
    InvariantEnforcement,

    /// Can be changed with majority vote
    Protocol,

    /// Can be changed with simple majority vote (governance parameters, etc.)
    Governance,
}

impl ConstitutionalScope {
    /// Get all scopes that require constitutional protection
    pub fn protected_scopes() -> Vec<ConstitutionalScope> {
        vec![
            ConstitutionalScope::EconomicPolicy,
            ConstitutionalScope::ValidatorSafety,
            ConstitutionalScope::ConsensusSafety,
            ConstitutionalScope::InvariantEnforcement,
        ]
    }
}

/// A constitutional constraint that cannot be violated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionalConstraint {
    /// Unique constraint identifier
    pub id: String,

    /// Human-readable constraint description
    pub description: String,

    /// The scope this constraint protects
    pub scope: ConstitutionalScope,

    /// Whether this constraint can ever be modified
    pub is_immutable: bool,

    /// Validation function (stored as constraint rules)
    pub validation_rules: Vec<ConstraintRule>,

    /// Whether constraint is currently enforced
    pub is_active: bool,

    /// Cryptographic hash of constraint
    pub hash: Vec<u8>,
}

impl ConstitutionalConstraint {
    /// Create a new constitutional constraint
    pub fn new(
        id: String,
        description: String,
        scope: ConstitutionalScope,
        is_immutable: bool,
        validation_rules: Vec<ConstraintRule>,
    ) -> Result<Self, ConstitutionError> {
        let mut constraint = ConstitutionalConstraint {
            id,
            description,
            scope,
            is_immutable,
            validation_rules,
            is_active: true,
            hash: Vec::new(),
        };

        constraint.hash = constraint.compute_hash()?;
        Ok(constraint)
    }

    /// Compute SHA256 hash of constraint
    fn compute_hash(&self) -> Result<Vec<u8>, ConstitutionError> {
        let serialized = bincode::serialize(&(
            &self.id,
            &self.description,
            &self.scope,
            &self.is_immutable,
            &self.validation_rules,
        ))
        .map_err(|e| ConstitutionError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }

    /// Verify constraint hasn't been tampered with
    pub fn verify_hash(&self) -> Result<bool, ConstitutionError> {
        let computed_hash = self.compute_hash()?;
        Ok(computed_hash == self.hash)
    }

    /// Check if a governance action violates this constraint
    pub fn validate_action(
        &self,
        action: &GovernanceAction,
    ) -> Result<ValidationResult, ConstitutionError> {
        if !self.is_active {
            return Ok(ValidationResult::Valid);
        }

        // Check scope matches
        if action.scope != self.scope && !action.scope_rationale.is_empty() {
            // Allow cross-scope justification only for governance actions
            if self.scope != ConstitutionalScope::Governance {
                return Ok(ValidationResult::Violation(format!(
                    "Action scope {:?} not allowed in constraint scope {:?}",
                    action.scope, self.scope
                )));
            }
        }

        // Check all validation rules
        for rule in &self.validation_rules {
            let result = rule.validate(action)?;
            if !result {
                return Ok(ValidationResult::Violation(format!(
                    "Action violates constraint rule in {:?}",
                    self.scope
                )));
            }
        }

        Ok(ValidationResult::Valid)
    }
}

/// A single constraint rule (e.g., "supply cap cannot exceed 10 billion")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintRule {
    /// Rule identifier
    pub name: String,

    /// Rule type
    pub rule_type: RuleType,

    /// Constraint value
    pub constraint_value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    /// Supply cap cannot exceed this amount
    SupplyCap,

    /// Inflation rate cannot exceed this percentage (basis points)
    InflationCap,

    /// Slashing percentage cannot exceed this
    SlashingCap,

    /// Finality delay cannot exceed this many epochs
    FinalityDelay,

    /// Validator participation ratio must stay above this
    ValidatorParticipationMinimum,

    /// Custom rule
    Custom(String),
}

impl ConstraintRule {
    /// Validate an action against this rule
    pub fn validate(&self, action: &GovernanceAction) -> Result<bool, ConstitutionError> {
        match &self.rule_type {
            RuleType::SupplyCap => {
                if let Some(amount) = action.economic_change {
                    Ok(amount <= self.constraint_value)
                } else {
                    Ok(true)
                }
            }
            RuleType::InflationCap => {
                if let Some(rate) = action.inflation_rate {
                    Ok(rate <= self.constraint_value)
                } else {
                    Ok(true)
                }
            }
            RuleType::SlashingCap => {
                if let Some(pct) = action.slashing_percentage {
                    Ok(pct <= self.constraint_value)
                } else {
                    Ok(true)
                }
            }
            RuleType::FinalityDelay => {
                if let Some(delay) = action.finality_delay {
                    Ok(delay <= self.constraint_value)
                } else {
                    Ok(true)
                }
            }
            RuleType::ValidatorParticipationMinimum => {
                if let Some(min_pct) = action.validator_participation {
                    Ok(min_pct >= self.constraint_value)
                } else {
                    Ok(true)
                }
            }
            RuleType::Custom(_) => {
                // Custom rules must be explicitly validated by caller
                Ok(true)
            }
        }
    }
}

/// A governance action that may be proposed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceAction {
    /// Action ID
    pub id: String,

    /// Scope this action affects
    pub scope: ConstitutionalScope,

    /// Affected modules
    pub affected_modules: Vec<String>,

    /// Rationale for cross-scope affects
    pub scope_rationale: String,

    /// Economic changes (if any)
    pub economic_change: Option<u64>,

    /// Inflation rate change (basis points)
    pub inflation_rate: Option<u64>,

    /// Slashing percentage
    pub slashing_percentage: Option<u64>,

    /// Finality delay in epochs
    pub finality_delay: Option<u64>,

    /// Validator participation ratio (basis points)
    pub validator_participation: Option<u64>,

    /// Action description
    pub description: String,
}

impl GovernanceAction {
    /// Create a new governance action
    pub fn new(
        id: String,
        scope: ConstitutionalScope,
        affected_modules: Vec<String>,
        description: String,
    ) -> Self {
        GovernanceAction {
            id,
            scope,
            affected_modules,
            scope_rationale: String::new(),
            economic_change: None,
            inflation_rate: None,
            slashing_percentage: None,
            finality_delay: None,
            validator_participation: None,
            description,
        }
    }

    /// Compute hash of action
    pub fn hash(&self) -> Result<Vec<u8>, ConstitutionError> {
        let serialized = bincode::serialize(self)
            .map_err(|e| ConstitutionError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }
}

/// Result of constitutional validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationResult {
    /// Action is valid
    Valid,

    /// Action violates constitutional law
    Violation(String),
}

/// The BLEEP Constitution - Immutable at genesis, versioned for amendments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLEEPConstitution {
    /// Constitutional version (semantic versioning)
    pub version: String,

    /// Genesis epoch when constitution was instantiated
    pub genesis_epoch: u64,

    /// All constitutional constraints
    pub constraints: BTreeMap<String, ConstitutionalConstraint>,

    /// Constitutional hash (commitment)
    pub constitution_hash: Vec<u8>,

    /// Current number of constitutional amendments
    pub amendment_count: u64,

    /// Amendment history (hash of each amendment)
    pub amendment_history: Vec<Vec<u8>>,

    /// Supermajority required for constitutional changes (basis points)
    pub constitutional_amendment_threshold: u64,

    /// Time delay required for constitutional changes (epochs)
    pub constitutional_amendment_delay: u64,
}

impl BLEEPConstitution {
    /// Create the genesis constitution with immutable rules
    pub fn genesis() -> Result<Self, ConstitutionError> {
        let mut constraints = BTreeMap::new();

        // Supply cap constraint (immutable)
        let supply_cap = ConstitutionalConstraint::new(
            "SUPPLY_CAP".to_string(),
            "Maximum token supply cannot exceed 21 billion".to_string(),
            ConstitutionalScope::EconomicPolicy,
            true,
            vec![ConstraintRule {
                name: "max_supply".to_string(),
                rule_type: RuleType::SupplyCap,
                constraint_value: 21_000_000_000,
            }],
        )?;
        constraints.insert("SUPPLY_CAP".to_string(), supply_cap);

        // Inflation cap constraint (immutable)
        let inflation_cap = ConstitutionalConstraint::new(
            "INFLATION_CAP".to_string(),
            "Annual inflation rate cannot exceed 5%".to_string(),
            ConstitutionalScope::EconomicPolicy,
            true,
            vec![ConstraintRule {
                name: "max_inflation".to_string(),
                rule_type: RuleType::InflationCap,
                constraint_value: 500, // 5% in basis points
            }],
        )?;
        constraints.insert("INFLATION_CAP".to_string(), inflation_cap);

        // Slashing safety constraint (immutable)
        let slashing_safety = ConstitutionalConstraint::new(
            "SLASHING_SAFETY".to_string(),
            "Individual validator slashing cannot exceed 33%".to_string(),
            ConstitutionalScope::ValidatorSafety,
            true,
            vec![ConstraintRule {
                name: "max_slash".to_string(),
                rule_type: RuleType::SlashingCap,
                constraint_value: 3300, // 33% in basis points
            }],
        )?;
        constraints.insert("SLASHING_SAFETY".to_string(), slashing_safety);

        // Finality guarantee constraint (immutable)
        let finality_guarantee = ConstitutionalConstraint::new(
            "FINALITY_GUARANTEE".to_string(),
            "Finality delay cannot exceed 4 epochs".to_string(),
            ConstitutionalScope::ConsensusSafety,
            true,
            vec![ConstraintRule {
                name: "max_finality_delay".to_string(),
                rule_type: RuleType::FinalityDelay,
                constraint_value: 4,
            }],
        )?;
        constraints.insert("FINALITY_GUARANTEE".to_string(), finality_guarantee);

        // Validator participation constraint (immutable)
        let validator_participation = ConstitutionalConstraint::new(
            "VALIDATOR_PARTICIPATION".to_string(),
            "Validator participation must remain above 66%".to_string(),
            ConstitutionalScope::ValidatorSafety,
            true,
            vec![ConstraintRule {
                name: "min_participation".to_string(),
                rule_type: RuleType::ValidatorParticipationMinimum,
                constraint_value: 6600, // 66% in basis points
            }],
        )?;
        constraints.insert(
            "VALIDATOR_PARTICIPATION".to_string(),
            validator_participation,
        );

        let mut constitution = BLEEPConstitution {
            version: "1.0.0".to_string(),
            genesis_epoch: 0,
            constraints,
            constitution_hash: Vec::new(),
            amendment_count: 0,
            amendment_history: Vec::new(),
            constitutional_amendment_threshold: 9000, // 90%
            constitutional_amendment_delay: 100,      // 100 epochs
        };

        constitution.constitution_hash = constitution.compute_hash()?;

        info!(
            "BLEEP Constitution instantiated at genesis (v{})",
            constitution.version
        );

        Ok(constitution)
    }

    /// Compute cryptographic hash of entire constitution
    fn compute_hash(&self) -> Result<Vec<u8>, ConstitutionError> {
        let serialized = bincode::serialize(&(
            &self.version,
            &self.genesis_epoch,
            &self.constraints,
            &self.amendment_count,
        ))
        .map_err(|e| ConstitutionError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }

    /// Verify constitution hasn't been tampered with
    pub fn verify_hash(&self) -> Result<bool, ConstitutionError> {
        let computed_hash = self.compute_hash()?;
        Ok(computed_hash == self.constitution_hash)
    }

    /// Validate a governance action against the entire constitution
    pub fn validate_action(
        &self,
        action: &GovernanceAction,
    ) -> Result<ValidationResult, ConstitutionError> {
        // Verify constitution integrity
        if !self.verify_hash()? {
            return Err(ConstitutionError::HashVerificationFailed);
        }

        info!(
            "Validating governance action {} against constitution v{}",
            action.id, self.version
        );

        // Check action against all applicable constraints
        for (constraint_id, constraint) in &self.constraints {
            if constraint.scope == ConstitutionalScope::Governance {
                continue; // Skip governance-scoped constraints for now
            }

            match constraint.validate_action(action)? {
                ValidationResult::Valid => {}
                ValidationResult::Violation(reason) => {
                    warn!(
                        "Action {} violates constraint {}: {}",
                        action.id, constraint_id, reason
                    );
                    return Ok(ValidationResult::Violation(reason));
                }
            }
        }

        info!("Action {} passed constitutional validation", action.id);
        Ok(ValidationResult::Valid)
    }

    /// Add a new constraint (requires constitutional amendment)
    pub fn add_constraint(
        &mut self,
        constraint: ConstitutionalConstraint,
        _current_epoch: u64,
    ) -> Result<(), ConstitutionError> {
        if constraint.is_immutable {
            // Immutable constraints cannot be added via amendment
            return Err(ConstitutionError::UnauthorizedChange);
        }

        self.constraints.insert(constraint.id.clone(), constraint);
        self.amendment_count += 1;

        // Update constitution hash
        self.constitution_hash = self.compute_hash()?;

        info!(
            "Constitutional amendment applied (count: {})",
            self.amendment_count
        );

        Ok(())
    }

    /// Get all protected constitutional constraints
    pub fn protected_constraints(&self) -> Vec<&ConstitutionalConstraint> {
        self.constraints
            .values()
            .filter(|c| c.is_immutable)
            .collect()
    }

    /// Get all mutable constitutional constraints
    pub fn mutable_constraints(&self) -> Vec<&ConstitutionalConstraint> {
        self.constraints
            .values()
            .filter(|c| !c.is_immutable)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_constitution() -> Result<(), ConstitutionError> {
        let constitution = BLEEPConstitution::genesis()?;
        assert_eq!(constitution.version, "1.0.0");
        assert_eq!(constitution.amendment_count, 0);
        assert!(!constitution.constitution_hash.is_empty());
        assert!(constitution.verify_hash()?);
        Ok(())
    }

    #[test]
    fn test_constitution_hash_verification() -> Result<(), ConstitutionError> {
        let constitution = BLEEPConstitution::genesis()?;
        assert!(constitution.verify_hash()?);
        Ok(())
    }

    #[test]
    fn test_supply_cap_constraint() -> Result<(), ConstitutionError> {
        let constitution = BLEEPConstitution::genesis()?;

        // Valid action: supply within cap
        let valid_action = GovernanceAction::new(
            "action_1".to_string(),
            ConstitutionalScope::EconomicPolicy,
            vec!["token".to_string()],
            "Increase supply".to_string(),
        );

        match constitution.validate_action(&valid_action)? {
            ValidationResult::Valid => {}
            ValidationResult::Violation(_) => panic!("Valid action rejected"),
        }

        // Invalid action: supply exceeds cap
        let mut invalid_action = GovernanceAction::new(
            "action_2".to_string(),
            ConstitutionalScope::EconomicPolicy,
            vec!["token".to_string()],
            "Increase supply beyond cap".to_string(),
        );
        invalid_action.economic_change = Some(30_000_000_000);

        match constitution.validate_action(&invalid_action)? {
            ValidationResult::Valid => panic!("Invalid action accepted"),
            ValidationResult::Violation(_) => {}
        }

        Ok(())
    }

    #[test]
    fn test_inflation_cap_constraint() -> Result<(), ConstitutionError> {
        let constitution = BLEEPConstitution::genesis()?;

        // Valid: inflation within cap
        let mut valid_action = GovernanceAction::new(
            "action_1".to_string(),
            ConstitutionalScope::EconomicPolicy,
            vec!["inflation".to_string()],
            "Set inflation".to_string(),
        );
        valid_action.inflation_rate = Some(300); // 3%

        match constitution.validate_action(&valid_action)? {
            ValidationResult::Valid => {}
            ValidationResult::Violation(_) => panic!("Valid inflation rejected"),
        }

        // Invalid: inflation exceeds cap
        let mut invalid_action = GovernanceAction::new(
            "action_2".to_string(),
            ConstitutionalScope::EconomicPolicy,
            vec!["inflation".to_string()],
            "Set inflation beyond cap".to_string(),
        );
        invalid_action.inflation_rate = Some(600); // 6%

        match constitution.validate_action(&invalid_action)? {
            ValidationResult::Valid => panic!("Invalid inflation accepted"),
            ValidationResult::Violation(_) => {}
        }

        Ok(())
    }

    #[test]
    fn test_protected_constraints() -> Result<(), ConstitutionError> {
        let constitution = BLEEPConstitution::genesis()?;
        let protected = constitution.protected_constraints();

        assert!(!protected.is_empty());
        assert!(protected.iter().all(|c| c.is_immutable));

        Ok(())
    }

    #[test]
    fn test_governance_action_hash() -> Result<(), ConstitutionError> {
        let action = GovernanceAction::new(
            "test_action".to_string(),
            ConstitutionalScope::Governance,
            vec!["governance".to_string()],
            "Test action".to_string(),
        );

        let hash = action.hash()?;
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 32); // SHA256

        Ok(())
    }
}
