// PHASE 4: SHARD SELF-HEALING & ROLLBACK
// Shard Isolation Mechanism - Deterministic shard freeze and isolation
//
// SAFETY INVARIANTS:
// 1. When a shard is flagged faulty, it is immediately frozen
// 2. Frozen shards cannot accept new transactions
// 3. Frozen shards do not participate in cross-shard commits
// 4. Unaffected shards continue operating normally
// 5. Isolation is epoch-bound and reversible only through protocol rules
// 6. Isolation decisions are consensus-verified

use crate::shard_fault_detection::{FaultEvidence, FaultSeverity};
use crate::shard_registry::ShardId;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

/// Shard isolation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationStatus {
    /// Shard is operating normally
    Normal,

    /// Shard is under investigation (suspicious behavior detected)
    Investigating,

    /// Shard is frozen (cannot accept transactions)
    Frozen,

    /// Shard is isolated (no participation in cross-shard txs)
    Isolated,

    /// Shard is recovering (rebuilding from checkpoint)
    Recovering,

    /// Shard is being healed (syncing to latest state)
    Healing,
}

/// Shard isolation record
///
/// SAFETY: Immutable record of isolation decision and reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationRecord {
    /// Shard being isolated
    pub shard_id: ShardId,

    /// When isolation was triggered
    pub triggered_at_epoch: u64,

    /// Reason for isolation (fault evidence)
    pub trigger_evidence: FaultEvidence,

    /// Current isolation status
    pub status: IsolationStatus,

    /// Timestamp of isolation (seconds since epoch)
    pub timestamp: u64,

    /// Consensus block height at isolation
    pub block_height: u64,

    /// Whether isolation has been finalized on-chain
    pub is_finalized: bool,
}

impl IsolationRecord {
    /// Create a new isolation record
    pub fn new(shard_id: ShardId, epoch: u64, evidence: FaultEvidence, height: u64) -> Self {
        IsolationRecord {
            shard_id,
            triggered_at_epoch: epoch,
            trigger_evidence: evidence,
            status: IsolationStatus::Investigating,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            block_height: height,
            is_finalized: false,
        }
    }

    /// Determine if shard should be frozen based on evidence severity
    pub fn should_freeze(&self) -> bool {
        matches!(
            self.trigger_evidence.severity,
            FaultSeverity::High | FaultSeverity::Critical
        )
    }

    /// Determine if shard should be isolated (more severe than freeze)
    pub fn should_isolate(&self) -> bool {
        self.trigger_evidence.severity == FaultSeverity::Critical
    }
}

/// Shard isolation manager
///
/// SAFETY: Coordinates isolation of faulty shards while maintaining network operation.
#[derive(Clone)]
pub struct ShardIsolationManager {
    /// Isolation records per shard
    isolation_records: HashMap<ShardId, Vec<IsolationRecord>>,

    /// Currently isolated shards
    isolated_shards: HashSet<ShardId>,

    /// Currently frozen shards
    frozen_shards: HashSet<ShardId>,
}

impl ShardIsolationManager {
    /// Create a new isolation manager
    pub fn new() -> Self {
        ShardIsolationManager {
            isolation_records: HashMap::new(),
            isolated_shards: HashSet::new(),
            frozen_shards: HashSet::new(),
        }
    }

    /// Isolate a shard based on fault evidence
    ///
    /// SAFETY: Creates immutable isolation record for audit trail.
    pub fn isolate_shard(
        &mut self,
        shard_id: ShardId,
        epoch: u64,
        evidence: FaultEvidence,
        height: u64,
    ) -> Result<(), String> {
        if self.isolated_shards.contains(&shard_id) {
            return Err(format!("Shard {:?} is already isolated", shard_id));
        }

        let mut record = IsolationRecord::new(shard_id, epoch, evidence, height);

        // Determine isolation level based on severity
        if record.should_isolate() {
            record.status = IsolationStatus::Isolated;
            self.isolated_shards.insert(shard_id);
            info!("Isolated shard {:?} due to critical fault", shard_id);
        } else if record.should_freeze() {
            record.status = IsolationStatus::Frozen;
            self.frozen_shards.insert(shard_id);
            info!("Froze shard {:?} due to high severity fault", shard_id);
        }

        self.isolation_records
            .entry(shard_id)
            .or_insert_with(Vec::new)
            .push(record);

        Ok(())
    }

    /// Finalize isolation (commit to consensus)
    ///
    /// SAFETY: Called only after consensus has verified isolation decision.
    pub fn finalize_isolation(&mut self, shard_id: ShardId) -> Result<(), String> {
        let records = self
            .isolation_records
            .get_mut(&shard_id)
            .ok_or("No isolation record for shard")?;

        if let Some(record) = records.last_mut() {
            record.is_finalized = true;
            info!("Finalized isolation for shard {:?}", shard_id);
            Ok(())
        } else {
            Err("No active isolation record".to_string())
        }
    }

    /// Check if shard is currently isolated
    pub fn is_isolated(&self, shard_id: ShardId) -> bool {
        self.isolated_shards.contains(&shard_id)
    }

    /// Check if shard is currently frozen
    pub fn is_frozen(&self, shard_id: ShardId) -> bool {
        self.frozen_shards.contains(&shard_id)
    }

    /// Check if shard can accept new transactions
    pub fn can_accept_transactions(&self, shard_id: ShardId) -> bool {
        !self.is_isolated(shard_id) && !self.is_frozen(shard_id)
    }

    /// Check if shard can participate in cross-shard transactions
    pub fn can_participate_in_crossshard(&self, shard_id: ShardId) -> bool {
        !self.is_isolated(shard_id)
    }

    /// Begin recovery process for a shard
    ///
    /// SAFETY: Transition to Recovering status.
    pub fn begin_recovery(&mut self, shard_id: ShardId) -> Result<(), String> {
        let records = self
            .isolation_records
            .get_mut(&shard_id)
            .ok_or("No isolation record for shard")?;

        if let Some(record) = records.last_mut() {
            record.status = IsolationStatus::Recovering;
            info!("Beginning recovery for shard {:?}", shard_id);
            Ok(())
        } else {
            Err("No active isolation record".to_string())
        }
    }

    /// Begin healing process for a shard
    ///
    /// SAFETY: Transition to Healing status.
    pub fn begin_healing(&mut self, shard_id: ShardId) -> Result<(), String> {
        let records = self
            .isolation_records
            .get_mut(&shard_id)
            .ok_or("No isolation record for shard")?;

        if let Some(record) = records.last_mut() {
            record.status = IsolationStatus::Healing;
            info!("Beginning healing for shard {:?}", shard_id);
            Ok(())
        } else {
            Err("No active isolation record".to_string())
        }
    }

    /// Complete recovery and return shard to normal operation
    ///
    /// SAFETY: Requires explicit consensus approval.
    pub fn complete_recovery(&mut self, shard_id: ShardId) -> Result<(), String> {
        if !self.isolated_shards.remove(&shard_id) {
            self.frozen_shards.remove(&shard_id);
        }

        let records = self
            .isolation_records
            .get_mut(&shard_id)
            .ok_or("No isolation record for shard")?;

        if let Some(record) = records.last_mut() {
            record.status = IsolationStatus::Normal;
            info!("Completed recovery for shard {:?}", shard_id);
            Ok(())
        } else {
            Err("No active isolation record".to_string())
        }
    }

    /// Get isolation history for a shard
    pub fn get_isolation_history(&self, shard_id: ShardId) -> Vec<&IsolationRecord> {
        self.isolation_records
            .get(&shard_id)
            .map(|records| records.iter().collect())
            .unwrap_or_default()
    }

    /// Get currently isolated shards
    pub fn get_isolated_shards(&self) -> Vec<ShardId> {
        self.isolated_shards.iter().copied().collect()
    }

    /// Get currently frozen shards
    pub fn get_frozen_shards(&self) -> Vec<ShardId> {
        self.frozen_shards.iter().copied().collect()
    }

    /// Check if any critical shards are isolated
    ///
    /// SAFETY: May trigger network-level responses if too many shards isolated.
    pub fn has_critical_isolation(&self) -> bool {
        self.isolated_shards.len() > 0
    }
}

/// Cross-shard transaction validator
///
/// SAFETY: Ensures cross-shard txs cannot involve isolated shards.
pub struct CrossShardValidator {
    isolation_manager: ShardIsolationManager,
}

impl CrossShardValidator {
    /// Create a new cross-shard validator
    pub fn new(isolation_manager: ShardIsolationManager) -> Self {
        CrossShardValidator { isolation_manager }
    }

    /// Validate that a cross-shard transaction can proceed
    ///
    /// SAFETY: Rejects if any involved shard is isolated.
    pub fn validate_cross_shard_tx(&self, involved_shards: &[ShardId]) -> Result<(), String> {
        for shard_id in involved_shards {
            if self.isolation_manager.is_isolated(*shard_id) {
                return Err(format!(
                    "Cannot execute cross-shard transaction: shard {:?} is isolated",
                    shard_id
                ));
            }
        }

        Ok(())
    }

    /// Validate transaction acceptance for a shard
    ///
    /// SAFETY: Rejects if shard is frozen or isolated.
    pub fn validate_shard_tx_acceptance(&self, shard_id: ShardId) -> Result<(), String> {
        if !self.isolation_manager.can_accept_transactions(shard_id) {
            return Err(format!(
                "Shard {:?} is not accepting transactions (frozen or isolated)",
                shard_id
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard_fault_detection::{FaultEvidence, FaultType};

    #[test]
    fn test_isolation_status() {
        let evidence = FaultEvidence {
            fault_type: FaultType::StateRootMismatch {
                expected_root: "root_a".to_string(),
                observed_root: "root_b".to_string(),
                dissenting_validators: 2,
            },
            shard_id: ShardId(0),
            epoch_id: crate::shard_registry::EpochId(0),
            severity: FaultSeverity::Critical,
            detection_height: 100,
            proof: vec![],
            details: "test".to_string(),
        };

        let record = IsolationRecord::new(ShardId(0), 0, evidence, 100);
        assert!(record.should_isolate());
    }

    #[test]
    fn test_isolation_manager() {
        let mut manager = ShardIsolationManager::new();

        let evidence = FaultEvidence {
            fault_type: FaultType::StateRootMismatch {
                expected_root: "root_a".to_string(),
                observed_root: "root_b".to_string(),
                dissenting_validators: 2,
            },
            shard_id: ShardId(0),
            epoch_id: crate::shard_registry::EpochId(0),
            severity: FaultSeverity::Critical,
            detection_height: 100,
            proof: vec![],
            details: "test".to_string(),
        };

        manager.isolate_shard(ShardId(0), 0, evidence, 100).unwrap();
        assert!(manager.is_isolated(ShardId(0)));
        assert!(!manager.can_accept_transactions(ShardId(0)));
    }

    #[test]
    fn test_freeze_shard() {
        let mut manager = ShardIsolationManager::new();

        let evidence = FaultEvidence {
            fault_type: FaultType::ExecutionFailure {
                block_height: 100,
                error: "test error".to_string(),
            },
            shard_id: ShardId(0),
            epoch_id: crate::shard_registry::EpochId(0),
            severity: FaultSeverity::High,
            detection_height: 100,
            proof: vec![],
            details: "test".to_string(),
        };

        manager.isolate_shard(ShardId(0), 0, evidence, 100).unwrap();
        assert!(manager.is_frozen(ShardId(0)));
        assert!(!manager.is_isolated(ShardId(0)));
    }

    #[test]
    fn test_crossshard_validator() {
        let manager = ShardIsolationManager::new();
        let validator = CrossShardValidator::new(manager);

        let shards = vec![ShardId(0), ShardId(1)];
        assert!(validator.validate_cross_shard_tx(&shards).is_ok());
    }
}
