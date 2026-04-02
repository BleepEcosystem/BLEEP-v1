// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// Protocol Rules Abstraction - Versioned, hash-committed protocol parameters
//
// SAFETY INVARIANTS:
// 1. All protocol parameters are versioned and immutable once committed
// 2. Rule changes are bounded and validated before activation
// 3. Rule versions are deterministically included in block headers
// 4. Fork safety is maintained through protocol version tracking
// 5. No hard-coded magic values remain in consensus logic
// 6. All rules must satisfy invariant constraints before use

use log::info;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolRuleError {
    #[error("Rule value out of bounds: {0}")]
    ValueOutOfBounds(String),

    #[error("Invalid rule constraint: {0}")]
    InvalidConstraint(String),

    #[error("Rule version mismatch")]
    VersionMismatch,

    #[error("Hash verification failed")]
    HashVerificationFailed,

    #[error("Unknown rule: {0}")]
    UnknownRule(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Type for all numeric protocol rule values
pub type RuleValue = u64;

/// Bounded range constraint for rule values
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleBounds {
    /// Minimum allowed value (inclusive)
    pub min: RuleValue,

    /// Maximum allowed value (inclusive)
    pub max: RuleValue,
}

impl RuleBounds {
    /// Create new bounds
    pub fn new(min: RuleValue, max: RuleValue) -> Result<Self, ProtocolRuleError> {
        if min > max {
            return Err(ProtocolRuleError::InvalidConstraint(format!(
                "min ({}) must be <= max ({})",
                min, max
            )));
        }
        Ok(RuleBounds { min, max })
    }

    /// Verify a value is within bounds
    pub fn contains(&self, value: RuleValue) -> bool {
        value >= self.min && value <= self.max
    }

    /// Clamp a value to the bounds
    pub fn clamp(&self, value: RuleValue) -> RuleValue {
        value.max(self.min).min(self.max)
    }
}

/// Represents a single protocol rule with versioning and constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolRule {
    /// Unique rule identifier (e.g., "SHARD_SPLIT_THRESHOLD")
    pub name: String,

    /// Current rule value
    pub value: RuleValue,

    /// Semantic version of this rule
    pub version: RuleVersion,

    /// Bounds that constrain valid values
    pub bounds: RuleBounds,

    /// Human-readable description
    pub description: String,

    /// Whether this rule can be changed via governance
    pub is_mutable: bool,

    /// The epoch at which this rule was activated
    pub epoch_activated: u64,
}

impl ProtocolRule {
    /// Create a new protocol rule
    pub fn new(
        name: String,
        initial_value: RuleValue,
        bounds: RuleBounds,
        description: String,
        is_mutable: bool,
        epoch_activated: u64,
    ) -> Result<Self, ProtocolRuleError> {
        if !bounds.contains(initial_value) {
            return Err(ProtocolRuleError::ValueOutOfBounds(format!(
                "Initial value {} not in bounds [{}, {}]",
                initial_value, bounds.min, bounds.max
            )));
        }

        Ok(ProtocolRule {
            name,
            value: initial_value,
            version: RuleVersion::new(0, 0, 0),
            bounds,
            description,
            is_mutable,
            epoch_activated,
        })
    }

    /// Update the rule value with validation
    pub fn update(
        &mut self,
        new_value: RuleValue,
        new_version: RuleVersion,
    ) -> Result<(), ProtocolRuleError> {
        if !self.is_mutable {
            return Err(ProtocolRuleError::InvalidConstraint(format!(
                "Rule {} is immutable",
                self.name
            )));
        }

        if !self.bounds.contains(new_value) {
            return Err(ProtocolRuleError::ValueOutOfBounds(format!(
                "New value {} not in bounds [{}, {}]",
                new_value, self.bounds.min, self.bounds.max
            )));
        }

        if new_version <= self.version {
            return Err(ProtocolRuleError::VersionMismatch);
        }

        self.value = new_value;
        self.version = new_version;
        Ok(())
    }
}

/// Semantic versioning for protocol rules
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct RuleVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl RuleVersion {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        RuleVersion {
            major,
            minor,
            patch,
        }
    }

    pub fn increment_major(&self) -> Self {
        RuleVersion {
            major: self.major + 1,
            minor: 0,
            patch: 0,
        }
    }

    pub fn increment_minor(&self) -> Self {
        RuleVersion {
            major: self.major,
            minor: self.minor + 1,
            patch: 0,
        }
    }

    pub fn increment_patch(&self) -> Self {
        RuleVersion {
            major: self.major,
            minor: self.minor,
            patch: self.patch + 1,
        }
    }
}

/// Immutable snapshot of protocol rules at a specific point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolRuleSet {
    /// Global rules identified by name
    pub rules: BTreeMap<String, ProtocolRule>,

    /// Version of the entire rule set
    pub version: u32,

    /// Epoch when this rule set was activated
    pub epoch_activated: u64,

    /// Hash commitment to the rule set (deterministic)
    pub commitment_hash: Vec<u8>,
}

impl ProtocolRuleSet {
    /// Create a new empty rule set
    pub fn new(version: u32, epoch_activated: u64) -> Self {
        ProtocolRuleSet {
            rules: BTreeMap::new(),
            version,
            epoch_activated,
            commitment_hash: vec![],
        }
    }

    /// Add a rule to the set
    pub fn add_rule(&mut self, rule: ProtocolRule) -> Result<(), ProtocolRuleError> {
        if self.rules.contains_key(&rule.name) {
            return Err(ProtocolRuleError::InvalidConstraint(format!(
                "Rule {} already exists",
                rule.name
            )));
        }
        self.rules.insert(rule.name.clone(), rule);
        Ok(())
    }

    /// Get a rule by name
    pub fn get_rule(&self, name: &str) -> Result<&ProtocolRule, ProtocolRuleError> {
        self.rules
            .get(name)
            .ok_or_else(|| ProtocolRuleError::UnknownRule(name.to_string()))
    }

    /// Get a rule value by name
    pub fn get_rule_value(&self, name: &str) -> Result<RuleValue, ProtocolRuleError> {
        Ok(self.get_rule(name)?.value)
    }

    /// Compute the deterministic commitment hash for this rule set
    ///
    /// SAFETY: This hash is deterministic and identical on all nodes
    /// for the same rule set content.
    pub fn compute_commitment_hash(&mut self) -> Result<Vec<u8>, ProtocolRuleError> {
        let serialized = serde_json::to_string(&self.rules)
            .map_err(|e| ProtocolRuleError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let hash = hasher.finalize().to_vec();

        self.commitment_hash = hash.clone();
        Ok(hash)
    }

    /// Verify the commitment hash matches the current rules
    pub fn verify_commitment(&self) -> Result<bool, ProtocolRuleError> {
        if self.commitment_hash.is_empty() {
            return Ok(false);
        }

        let serialized = serde_json::to_string(&self.rules)
            .map_err(|e| ProtocolRuleError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let computed_hash = hasher.finalize().to_vec();

        Ok(computed_hash == self.commitment_hash)
    }

    /// Create a complete copy with new version
    pub fn fork(&self, new_version: u32, epoch_activated: u64) -> Self {
        ProtocolRuleSet {
            rules: self.rules.clone(),
            version: new_version,
            epoch_activated,
            commitment_hash: self.commitment_hash.clone(),
        }
    }
}

/// Factory for creating genesis protocol rule sets
pub struct ProtocolRuleSetFactory;

impl ProtocolRuleSetFactory {
    /// Create the genesis rule set with all initial parameters
    ///
    /// SAFETY: These are the canonical genesis parameters that will be
    /// identical on all nodes.
    pub fn create_genesis() -> Result<ProtocolRuleSet, ProtocolRuleError> {
        let mut rules = ProtocolRuleSet::new(1, 0);

        // SHARDING RULES
        rules.add_rule(ProtocolRule::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000, // 1M state bytes
            RuleBounds::new(100_000, 10_000_000)?,
            "Threshold in state bytes for shard splitting".to_string(),
            true,
            0,
        )?)?;

        rules.add_rule(ProtocolRule::new(
            "SHARD_MERGE_THRESHOLD".to_string(),
            100_000, // 100K state bytes
            RuleBounds::new(10_000, 1_000_000)?,
            "Threshold for merging underutilized shards".to_string(),
            true,
            0,
        )?)?;

        // VALIDATOR RULES
        rules.add_rule(ProtocolRule::new(
            "VALIDATOR_ROTATION_CADENCE".to_string(),
            10, // Every 10 epochs
            RuleBounds::new(1, 100)?,
            "Number of epochs between validator set changes".to_string(),
            true,
            0,
        )?)?;

        rules.add_rule(ProtocolRule::new(
            "MIN_VALIDATOR_STAKE".to_string(),
            1000 * 10_u64.pow(18), // 1000 BLP with 18 decimals
            RuleBounds::new(100 * 10_u64.pow(18), 10_000 * 10_u64.pow(18))?,
            "Minimum stake to become a validator".to_string(),
            true,
            0,
        )?)?;

        // CROSS-SHARD RULES
        rules.add_rule(ProtocolRule::new(
            "CROSS_SHARD_TIMEOUT".to_string(),
            100, // 100 blocks
            RuleBounds::new(10, 1_000)?,
            "Blocks to wait for cross-shard transaction completion".to_string(),
            true,
            0,
        )?)?;

        // SLASHING RULES
        rules.add_rule(ProtocolRule::new(
            "SLASHING_PROPORTION".to_string(),
            5, // 5% of stake
            RuleBounds::new(1, 100)?,
            "Percentage of validator stake slashed for Byzantine behavior".to_string(),
            true,
            0,
        )?)?;

        // CHECKPOINT RULES
        rules.add_rule(ProtocolRule::new(
            "CHECKPOINT_FREQUENCY".to_string(),
            100, // Every 100 blocks
            RuleBounds::new(10, 1_000)?,
            "Number of blocks between mandatory checkpoints".to_string(),
            true,
            0,
        )?)?;

        // FINALITY RULES
        rules.add_rule(ProtocolRule::new(
            "FINALITY_THRESHOLD".to_string(),
            67, // 2/3 + 1
            RuleBounds::new(51, 99)?,
            "Percentage of validators required for finality".to_string(),
            false, // Immutable: critical for safety
            0,
        )?)?;

        // AI GOVERNANCE RULES
        rules.add_rule(ProtocolRule::new(
            "AI_PROPOSAL_MIN_CONFIDENCE".to_string(),
            70, // 70% confidence
            RuleBounds::new(50, 99)?,
            "Minimum AI confidence score for proposal consideration".to_string(),
            true,
            0,
        )?)?;

        rules.add_rule(ProtocolRule::new(
            "AI_REPUTATION_DECAY_RATE".to_string(),
            95, // 95% = 5% decay per epoch
            RuleBounds::new(50, 100)?,
            "Percentage retained for old AI decisions (100 = no decay)".to_string(),
            true,
            0,
        )?)?;

        // Compute commitment hash
        rules.compute_commitment_hash()?;

        info!(
            "Genesis protocol rule set created with {} rules",
            rules.rules.len()
        );
        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_bounds_validation() {
        let bounds = RuleBounds::new(100, 1000).unwrap();
        assert!(bounds.contains(500));
        assert!(!bounds.contains(50));
        assert!(!bounds.contains(1001));
    }

    #[test]
    fn test_rule_update() {
        let mut rule = ProtocolRule::new(
            "TEST_RULE".to_string(),
            500,
            RuleBounds::new(100, 1000).unwrap(),
            "Test rule".to_string(),
            true,
            0,
        )
        .unwrap();

        rule.update(600, RuleVersion::new(0, 1, 0)).unwrap();
        assert_eq!(rule.value, 600);
        assert_eq!(rule.version, RuleVersion::new(0, 1, 0));
    }

    #[test]
    fn test_immutable_rule_rejection() {
        let rule = ProtocolRule::new(
            "IMMUTABLE_RULE".to_string(),
            500,
            RuleBounds::new(100, 1000).unwrap(),
            "Immutable test rule".to_string(),
            false,
            0,
        )
        .unwrap();

        // Try to update - should fail
        let mut rule = rule;
        let result = rule.update(600, RuleVersion::new(0, 1, 0));
        assert!(result.is_err());
    }

    #[test]
    fn test_ruleset_hash_commitment() {
        let mut ruleset = ProtocolRuleSetFactory::create_genesis().unwrap();

        // Verify hash is computed
        assert!(!ruleset.commitment_hash.is_empty());

        // Verify hash matches on re-verification
        let verified = ruleset.verify_commitment().unwrap();
        assert!(verified);
    }

    #[test]
    fn test_genesis_ruleset_creation() {
        let ruleset = ProtocolRuleSetFactory::create_genesis().unwrap();

        // Check expected rules exist
        assert!(ruleset.get_rule("SHARD_SPLIT_THRESHOLD").is_ok());
        assert!(ruleset.get_rule("VALIDATOR_ROTATION_CADENCE").is_ok());
        assert!(ruleset.get_rule("FINALITY_THRESHOLD").is_ok());
        assert!(ruleset.get_rule("AI_PROPOSAL_MIN_CONFIDENCE").is_ok());
    }

    #[test]
    fn test_version_ordering() {
        let v1 = RuleVersion::new(1, 0, 0);
        let v2 = RuleVersion::new(1, 1, 0);
        let v3 = RuleVersion::new(2, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }
}
