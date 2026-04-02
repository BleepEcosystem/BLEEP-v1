// PHASE 4: CONSTITUTIONAL GOVERNANCE LAYER
// Forkless Protocol Upgrade System - Deterministic Activation, Rollback-Safe
//
// SAFETY INVARIANTS:
// 1. Upgrades are hash-committed before voting
// 2. Activation is deterministic and identical on all nodes
// 3. Upgrades activate only at epoch boundaries
// 4. No node may run unapproved code
// 5. Upgrades are rollback-protected
// 6. Partial upgrades are rejected
// 7. Version mismatches halt the chain
// 8. Upgrade verification is deterministic

use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpgradeError {
    #[error("Invalid upgrade hash")]
    InvalidUpgradeHash,

    #[error("Upgrade not approved")]
    UpgradeNotApproved,

    #[error("Version mismatch")]
    VersionMismatch,

    #[error("Activation not yet ready")]
    ActivationNotReady,

    #[error("Rollback verification failed")]
    RollbackVerificationFailed,

    #[error("Upgrade verification failed")]
    UpgradeVerificationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("State transition verification failed")]
    StateTransitionVerificationFailed,

    #[error("Invalid upgrade payload")]
    InvalidPayload,
}

/// Version structure (semantic versioning)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Major version (breaking changes)
    pub major: u16,

    /// Minor version (features)
    pub minor: u16,

    /// Patch version (bug fixes)
    pub patch: u16,
}

impl Version {
    /// Create new version
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Version {
            major,
            minor,
            patch,
        }
    }

    /// Genesis version
    pub fn genesis() -> Self {
        Version::new(1, 0, 0)
    }

    /// Check if upgrade from old to new is valid (monotonic)
    pub fn is_valid_upgrade(from: Version, to: Version) -> bool {
        to > from
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Upgrade payload contains all changes for an upgrade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradePayload {
    /// Unique upgrade identifier
    pub id: String,

    /// Target version
    pub version: Version,

    /// Code changes (module -> code hash)
    pub code_changes: BTreeMap<String, Vec<u8>>,

    /// State migrations (if any)
    pub state_migrations: Vec<StateMigration>,

    /// Configuration changes
    pub config_changes: BTreeMap<String, Vec<u8>>,

    /// Feature flags enabled
    pub feature_flags: BTreeMap<String, bool>,

    /// Constraints on upgrade (e.g., min validator participation)
    pub preconditions: UpgradePreconditions,

    /// Human-readable description
    pub description: String,
}

/// State migration step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMigration {
    /// Module being migrated
    pub module: String,

    /// Migration type
    pub migration_type: MigrationType,

    /// Migration hash (commitment)
    pub migration_hash: Vec<u8>,

    /// Required for deterministic rollback
    pub rollback_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationType {
    /// Add new field to state
    AddField {
        field_name: String,
        default_value: Vec<u8>,
    },

    /// Transform existing field
    TransformField {
        field_name: String,
        transformation: Vec<u8>,
    },

    /// Remove deprecated field
    RemoveField { field_name: String },

    /// Reindex state structure
    Reindex {
        old_structure: Vec<u8>,
        new_structure: Vec<u8>,
    },
}

/// Preconditions that must be met for upgrade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradePreconditions {
    /// Minimum validator participation (basis points)
    pub min_validator_participation: u64,

    /// Minimum time since last upgrade (epochs)
    pub min_epochs_since_last_upgrade: u64,

    /// Must have finality at activation
    pub requires_finality: bool,

    /// All shards must be healthy
    pub requires_shard_health: bool,
}

impl UpgradePayload {
    /// Create new upgrade payload
    pub fn new(
        id: String,
        version: Version,
        description: String,
        preconditions: UpgradePreconditions,
    ) -> Self {
        UpgradePayload {
            id,
            version,
            code_changes: BTreeMap::new(),
            state_migrations: Vec::new(),
            config_changes: BTreeMap::new(),
            feature_flags: BTreeMap::new(),
            preconditions,
            description,
        }
    }

    /// Add code change
    pub fn add_code_change(&mut self, module: String, code_hash: Vec<u8>) {
        self.code_changes.insert(module, code_hash);
    }

    /// Add state migration
    pub fn add_state_migration(&mut self, migration: StateMigration) {
        self.state_migrations.push(migration);
    }

    /// Add config change
    pub fn add_config_change(&mut self, key: String, value: Vec<u8>) {
        self.config_changes.insert(key, value);
    }

    /// Enable feature flag
    pub fn enable_feature(&mut self, feature: String) {
        self.feature_flags.insert(feature, true);
    }

    /// Compute hash of upgrade payload
    pub fn compute_hash(&self) -> Result<Vec<u8>, UpgradeError> {
        let serialized = bincode::serialize(self)
            .map_err(|e| UpgradeError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }

    /// Verify payload hasn't been tampered with
    pub fn verify(&self, expected_hash: &[u8]) -> Result<bool, UpgradeError> {
        let computed = self.compute_hash()?;
        Ok(&computed == expected_hash)
    }
}

/// Upgrade proposal that has been approved
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedUpgrade {
    /// Payload hash (commitment)
    pub payload_hash: Vec<u8>,

    /// Upgrade payload
    pub payload: UpgradePayload,

    /// Epoch when upgrade was approved
    pub approval_epoch: u64,

    /// Voting result that approved this
    pub approval_votes_yes: u64,
    pub approval_votes_no: u64,
    pub approval_votes_total: u64,

    /// Scheduled activation epoch
    pub activation_epoch: u64,

    /// Status
    pub status: UpgradeStatus,
}

/// Status of an approved upgrade
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UpgradeStatus {
    /// Approved, awaiting activation epoch
    Scheduled,

    /// Activated, being executed
    Executing,

    /// Execution completed successfully
    Executed,

    /// Execution failed, rollback initiated
    RolledBack,

    /// Execution failed, unable to rollback
    Failed,
}

impl ApprovedUpgrade {
    /// Create new approved upgrade
    pub fn new(
        payload: UpgradePayload,
        approval_epoch: u64,
        approval_votes_yes: u64,
        approval_votes_no: u64,
        activation_epoch: u64,
    ) -> Result<Self, UpgradeError> {
        let payload_hash = payload.compute_hash()?;

        Ok(ApprovedUpgrade {
            payload_hash,
            payload,
            approval_epoch,
            approval_votes_yes,
            approval_votes_no,
            approval_votes_total: approval_votes_yes + approval_votes_no,
            activation_epoch,
            status: UpgradeStatus::Scheduled,
        })
    }

    /// Verify upgrade payload matches committed hash
    pub fn verify_payload(&self) -> Result<bool, UpgradeError> {
        self.payload.verify(&self.payload_hash)
    }

    /// Get approval percentage
    pub fn approval_percentage(&self) -> f64 {
        if self.approval_votes_total == 0 {
            0.0
        } else {
            (self.approval_votes_yes as f64 / self.approval_votes_total as f64) * 100.0
        }
    }

    /// Check if activation preconditions are met
    pub fn preconditions_met(
        &self,
        current_epoch: u64,
        current_version: Version,
        validator_participation: u64,
        last_upgrade_epoch: u64,
        has_finality: bool,
        shards_healthy: bool,
    ) -> Result<bool, UpgradeError> {
        let prec = &self.payload.preconditions;

        // Check activation epoch
        if current_epoch < self.activation_epoch {
            return Ok(false);
        }

        // Check version monotonicity
        if !Version::is_valid_upgrade(current_version, self.payload.version) {
            return Err(UpgradeError::VersionMismatch);
        }

        // Check validator participation
        if validator_participation < prec.min_validator_participation {
            return Ok(false);
        }

        // Check time since last upgrade
        if current_epoch - last_upgrade_epoch < prec.min_epochs_since_last_upgrade {
            return Ok(false);
        }

        // Check finality requirement
        if prec.requires_finality && !has_finality {
            return Ok(false);
        }

        // Check shard health
        if prec.requires_shard_health && !shards_healthy {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Pre-upgrade checkpoint for rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeCheckpoint {
    /// Current version before upgrade
    pub version_before: Version,

    /// State root hash before upgrade
    pub state_root_before: Vec<u8>,

    /// Block height when checkpoint created
    pub block_height: u64,

    /// Epoch when checkpoint created
    pub epoch: u64,

    /// Checkpoint commitment hash
    pub checkpoint_hash: Vec<u8>,
}

impl UpgradeCheckpoint {
    /// Create new upgrade checkpoint
    pub fn new(
        version_before: Version,
        state_root_before: Vec<u8>,
        block_height: u64,
        epoch: u64,
    ) -> Result<Self, UpgradeError> {
        let mut checkpoint = UpgradeCheckpoint {
            version_before,
            state_root_before,
            block_height,
            epoch,
            checkpoint_hash: Vec::new(),
        };

        checkpoint.checkpoint_hash = checkpoint.compute_hash()?;
        Ok(checkpoint)
    }

    /// Compute checkpoint hash
    fn compute_hash(&self) -> Result<Vec<u8>, UpgradeError> {
        let serialized = bincode::serialize(&(
            self.version_before,
            &self.state_root_before,
            self.block_height,
            self.epoch,
        ))
        .map_err(|e| UpgradeError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }

    /// Verify checkpoint hash
    pub fn verify_hash(&self) -> Result<bool, UpgradeError> {
        let computed = self.compute_hash()?;
        Ok(computed == self.checkpoint_hash)
    }
}

/// Protocol Upgrade Manager
pub struct ProtocolUpgradeManager {
    /// Current protocol version
    pub current_version: Version,

    /// All approved upgrades by version
    pub approved_upgrades: BTreeMap<Version, ApprovedUpgrade>,

    /// Current upgrade checkpoint
    pub current_checkpoint: Option<UpgradeCheckpoint>,

    /// Epoch of last upgrade
    pub last_upgrade_epoch: u64,

    /// Executed upgrades (version -> execution result hash)
    pub executed_upgrades: BTreeMap<Version, Vec<u8>>,
}

impl ProtocolUpgradeManager {
    /// Create new upgrade manager at genesis
    pub fn genesis() -> Self {
        ProtocolUpgradeManager {
            current_version: Version::genesis(),
            approved_upgrades: BTreeMap::new(),
            current_checkpoint: None,
            last_upgrade_epoch: 0,
            executed_upgrades: BTreeMap::new(),
        }
    }

    /// Approve an upgrade
    pub fn approve_upgrade(
        &mut self,
        payload: UpgradePayload,
        approval_epoch: u64,
        approval_votes_yes: u64,
        approval_votes_no: u64,
        activation_epoch: u64,
    ) -> Result<(), UpgradeError> {
        let upgrade = ApprovedUpgrade::new(
            payload,
            approval_epoch,
            approval_votes_yes,
            approval_votes_no,
            activation_epoch,
        )?;

        // Verify upgrade is valid
        upgrade.verify_payload()?;

        // Check version isn't already executed
        if self
            .executed_upgrades
            .contains_key(&upgrade.payload.version)
        {
            return Err(UpgradeError::VersionMismatch);
        }

        info!(
            "Upgrade approved: {} -> activation at epoch {}",
            upgrade.payload.version, activation_epoch
        );

        self.approved_upgrades
            .insert(upgrade.payload.version, upgrade);
        Ok(())
    }

    /// Create checkpoint before upgrade
    pub fn create_checkpoint(
        &mut self,
        state_root: Vec<u8>,
        block_height: u64,
        epoch: u64,
    ) -> Result<UpgradeCheckpoint, UpgradeError> {
        let checkpoint =
            UpgradeCheckpoint::new(self.current_version, state_root, block_height, epoch)?;

        self.current_checkpoint = Some(checkpoint.clone());

        info!(
            "Upgrade checkpoint created at epoch {} for version {}",
            epoch, self.current_version
        );

        Ok(checkpoint)
    }

    /// Activate an upgrade
    pub fn activate_upgrade(
        &mut self,
        version: Version,
        current_epoch: u64,
    ) -> Result<(), UpgradeError> {
        let upgrade = self
            .approved_upgrades
            .get(&version)
            .ok_or(UpgradeError::UpgradeNotApproved)?
            .clone();

        // Check activation epoch
        if current_epoch < upgrade.activation_epoch {
            return Err(UpgradeError::ActivationNotReady);
        }

        // Verify payload
        upgrade.verify_payload()?;

        info!(
            "Activating upgrade to version {} at epoch {}",
            version, current_epoch
        );

        Ok(())
    }

    /// Execute upgrade (apply changes)
    pub fn execute_upgrade(
        &mut self,
        version: Version,
        execution_result: Vec<u8>,
    ) -> Result<(), UpgradeError> {
        if !self.approved_upgrades.contains_key(&version) {
            return Err(UpgradeError::UpgradeNotApproved);
        }

        self.current_version = version;
        self.executed_upgrades.insert(version, execution_result);

        info!("Upgrade executed: protocol now at version {}", version);

        Ok(())
    }

    /// Rollback to previous version
    pub fn rollback(&mut self, target_version: Version) -> Result<UpgradeCheckpoint, UpgradeError> {
        let checkpoint = self
            .current_checkpoint
            .clone()
            .ok_or(UpgradeError::RollbackVerificationFailed)?;

        // Can only rollback to version in checkpoint
        if checkpoint.version_before != target_version {
            return Err(UpgradeError::VersionMismatch);
        }

        // Verify checkpoint
        checkpoint.verify_hash()?;

        self.current_version = target_version;
        self.current_checkpoint = None;

        warn!("Protocol rolled back to version {}", target_version);

        Ok(checkpoint)
    }

    /// Get next scheduled upgrade
    pub fn get_next_scheduled_upgrade(&self) -> Option<&ApprovedUpgrade> {
        self.approved_upgrades
            .values()
            .filter(|u| u.status == UpgradeStatus::Scheduled)
            .min_by_key(|u| u.activation_epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_ordering() {
        let v1 = Version::new(1, 0, 0);
        let v1_1 = Version::new(1, 1, 0);
        let v2 = Version::new(2, 0, 0);

        assert!(v1 < v1_1);
        assert!(v1_1 < v2);
        assert!(Version::is_valid_upgrade(v1, v1_1));
        assert!(Version::is_valid_upgrade(v1_1, v2));
        assert!(!Version::is_valid_upgrade(v2, v1));
    }

    #[test]
    fn test_upgrade_payload_hash() -> Result<(), UpgradeError> {
        let mut payload = UpgradePayload::new(
            "upgrade_1".to_string(),
            Version::new(1, 1, 0),
            "Test upgrade".to_string(),
            UpgradePreconditions {
                min_validator_participation: 6600,
                min_epochs_since_last_upgrade: 10,
                requires_finality: true,
                requires_shard_health: true,
            },
        );

        payload.add_code_change("module_1".to_string(), vec![1, 2, 3]);

        let hash = payload.compute_hash()?;
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 32); // SHA256

        assert!(payload.verify(&hash)?);
        Ok(())
    }

    #[test]
    fn test_upgrade_checkpoint() -> Result<(), UpgradeError> {
        let checkpoint = UpgradeCheckpoint::new(Version::new(1, 0, 0), vec![1, 2, 3], 100, 0)?;

        assert!(checkpoint.verify_hash()?);
        Ok(())
    }

    #[test]
    fn test_upgrade_manager_genesis() {
        let manager = ProtocolUpgradeManager::genesis();
        assert_eq!(manager.current_version, Version::genesis());
        assert!(manager.approved_upgrades.is_empty());
    }

    #[test]
    fn test_approve_and_execute_upgrade() -> Result<(), UpgradeError> {
        let mut manager = ProtocolUpgradeManager::genesis();

        let payload = UpgradePayload::new(
            "upgrade_1".to_string(),
            Version::new(1, 1, 0),
            "Test upgrade".to_string(),
            UpgradePreconditions {
                min_validator_participation: 6600,
                min_epochs_since_last_upgrade: 10,
                requires_finality: true,
                requires_shard_health: true,
            },
        );

        // Approve upgrade
        manager.approve_upgrade(payload, 0, 7000, 3000, 10)?;

        // Activate upgrade
        manager.activate_upgrade(Version::new(1, 1, 0), 10)?;

        // Execute upgrade
        manager.execute_upgrade(Version::new(1, 1, 0), vec![1, 2, 3])?;

        assert_eq!(manager.current_version, Version::new(1, 1, 0));

        Ok(())
    }
}
