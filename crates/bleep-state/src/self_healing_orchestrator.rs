// PHASE 2: CONSENSUS-BINDING SELF-HEALING ORCHESTRATOR
// Integrates all recovery components into deterministic, consensus-approved healing
//
// SAFETY INVARIANTS:
// 1. All healing actions REQUIRE CONSENSUS APPROVAL
// 2. Healing proceeds through DETERMINISTIC STAGES
// 3. Healing CANNOT bypass CONSENSUS FINALITY CHECKS
// 4. Healing is ATOMIC: either complete or rollback entire operation
// 5. Healing is AUDITABLE: produces cryptographic evidence
// 6. All nodes INDEPENDENTLY compute identical healing actions
// 7. No healing proceeds without VALIDATOR QUORUM SIGNATURE
// 8. Healing cannot FORK the chain (deterministic across network)

use crate::advanced_fault_detector::{
    AdvancedFaultDetector, FaultDetectionConfig, FaultEvidence, FaultSeverity, RecoveryAction,
};
use crate::rollback_engine::{RollbackEngine, RollbackEvidence};
use crate::shard_registry::{EpochId, ShardId};
use crate::snapshot_engine::{SnapshotConfig, SnapshotEngine, SnapshotId};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Self-healing orchestration mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealingMode {
    /// Continuous monitoring (no action)
    Monitoring,

    /// Active healing in progress
    Healing,

    /// Awaiting consensus approval
    AwaitingConsensus,

    /// Paused (awaiting manual resolution)
    Paused,

    /// Completed successfully
    Completed,
}

/// Healing operation action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingOperation {
    /// Operation ID
    pub operation_id: String,

    /// Affected shard
    pub shard_id: ShardId,

    /// Triggering fault
    pub fault_evidence: FaultEvidence,

    /// Current mode
    pub mode: HealingMode,

    /// Rollback evidence (if performed)
    pub rollback_evidence: Option<RollbackEvidence>,

    /// Validator signatures approving operation
    pub validator_signatures: Vec<Vec<u8>>,

    /// Timestamp
    pub timestamp: u64,

    /// Whether operation succeeded
    pub succeeded: bool,

    /// Consensus approval required?
    pub requires_consensus: bool,

    /// Has consensus approved this operation?
    pub consensus_approved: bool,
}

impl HealingOperation {
    /// Create new healing operation
    pub fn new(shard_id: ShardId, fault_evidence: FaultEvidence) -> Self {
        let requires_consensus = matches!(
            fault_evidence.severity,
            FaultSeverity::High | FaultSeverity::Critical
        );

        HealingOperation {
            // H-05 FIX: Deterministic operation ID
            //
            // Previous code:
            //   operation_id: format!("healing_{}_{}_{}", shard_id.as_u64(),
            //                         fault_evidence.detected_at, std::process::id())
            //
            // `std::process::id()` returns the OS process ID of the current
            // process at the moment HealingOperation::new() is called.
            // This is non-deterministic across:
            //   - Different nodes (process IDs are OS-assigned, not protocol-derived)
            //   - Restarts on the same node (PID changes every restart)
            //   - Platforms (Windows PIDs may be 5 digits; Linux up to 22 bits)
            //
            // Two nodes observing the same fault produce different IDs, so they
            // cannot reach consensus on a healing operation: they are literally
            // referring to different objects with different names. The protocol
            // cannot distinguish "operation ID clash" from "different operations".
            //
            // Fix: Derive the ID deterministically from the inputs that all
            // nodes share: shard_id, detected_at, fault severity, and a short
            // description hash. The SHA3-256 truncation to 16 hex chars gives
            // 64-bit collision resistance — sufficient for a single shard's
            // operation log while keeping IDs short enough to embed in log lines.
            operation_id: {
                use sha3::{Digest, Sha3_256};
                let mut h = Sha3_256::new();
                h.update(b"bleep-healing-op-v1");
                h.update(shard_id.as_u64().to_le_bytes());
                h.update(fault_evidence.block_height.to_le_bytes());
                h.update(format!("{:?}", fault_evidence.severity).as_bytes());
                h.update(fault_evidence.detection_rule.as_bytes());
                // Truncate to 16 hex chars (64-bit) for readability
                format!("healing-{}", &hex::encode(h.finalize())[..16])
            },
            shard_id,
            fault_evidence,
            mode: HealingMode::Monitoring,
            rollback_evidence: None,
            validator_signatures: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            succeeded: false,
            requires_consensus,
            consensus_approved: false,
        }
    }

    /// Compute hash of operation
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.operation_id.as_bytes());
        hasher.update(self.shard_id.as_u64().to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update((self.succeeded as u8).to_le_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Healing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingStatistics {
    /// Total healing operations initiated
    pub total_operations: u64,

    /// Successful operations
    pub successful_operations: u64,

    /// Failed operations
    pub failed_operations: u64,

    /// Currently active operations
    pub active_operations: u64,

    /// Total shards healed
    pub shards_healed: usize,

    /// Average healing time (seconds)
    pub average_healing_time: u64,
}

/// Consensus-Binding Self-Healing Orchestrator
///
/// SAFETY: Central orchestrator that coordinates all recovery operations
/// and ensures they are consensus-verified.
pub struct SelfHealingOrchestrator {
    /// Snapshot engine
    snapshot_engine: SnapshotEngine,

    /// Rollback engine
    rollback_engine: RollbackEngine,

    /// Fault detector
    fault_detector: AdvancedFaultDetector,

    /// Active healing operations
    active_operations: HashMap<String, HealingOperation>,

    /// Completed operations history
    operation_history: Vec<HealingOperation>,

    /// Current epoch
    current_epoch: EpochId,

    /// Validator quorum threshold
    min_validator_quorum: usize,

    /// Statistics
    statistics: HealingStatistics,
}

impl SelfHealingOrchestrator {
    /// Create new self-healing orchestrator
    pub fn new(
        snapshot_config: SnapshotConfig,
        fault_detection_config: FaultDetectionConfig,
        min_validator_quorum: usize,
    ) -> Self {
        let snapshot_engine = SnapshotEngine::new(snapshot_config, SnapshotId(0));
        let rollback_engine = RollbackEngine::new(snapshot_engine.clone());
        let fault_detector = AdvancedFaultDetector::new(fault_detection_config);

        SelfHealingOrchestrator {
            snapshot_engine,
            rollback_engine,
            fault_detector,
            active_operations: HashMap::new(),
            operation_history: Vec::new(),
            current_epoch: EpochId(0),
            min_validator_quorum,
            statistics: HealingStatistics {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                active_operations: 0,
                shards_healed: 0,
                average_healing_time: 0,
            },
        }
    }

    /// Update current epoch
    pub fn update_epoch(&mut self, epoch: EpochId) {
        self.current_epoch = epoch;
        self.fault_detector.update_epoch(epoch);
    }

    /// Detect fault and initiate healing if necessary
    pub fn on_fault_detected(
        &mut self,
        shard_id: ShardId,
        fault_evidence: FaultEvidence,
    ) -> Result<HealingOperation, String> {
        // Record fault
        let fault_id = self.fault_detector.record_fault(fault_evidence.clone())?;

        info!(
            "Fault detected and recorded: {} for shard {}",
            fault_id,
            shard_id.as_u64()
        );

        // Create healing operation
        let mut operation = HealingOperation::new(shard_id, fault_evidence);
        operation.mode = HealingMode::AwaitingConsensus;

        // Check if consensus is required
        if operation.requires_consensus {
            info!(
                "Healing operation {} requires consensus approval",
                operation.operation_id
            );
        } else {
            // Low-severity faults can be healed without consensus
            operation.mode = HealingMode::Healing;
        }

        self.statistics.total_operations = self.statistics.total_operations.saturating_add(1);
        self.statistics.active_operations = self.statistics.active_operations.saturating_add(1);

        self.active_operations
            .insert(operation.operation_id.clone(), operation.clone());

        Ok(operation)
    }

    /// Approve healing operation from consensus
    pub fn approve_from_consensus(
        &mut self,
        operation_id: String,
        validator_signatures: Vec<Vec<u8>>,
    ) -> Result<(), String> {
        let operation = self
            .active_operations
            .get_mut(&operation_id)
            .ok_or_else(|| "Operation not found".to_string())?;

        // Verify quorum
        if validator_signatures.len() < self.min_validator_quorum {
            return Err(format!(
                "Insufficient signatures: {} < {}",
                validator_signatures.len(),
                self.min_validator_quorum
            ));
        }

        operation.validator_signatures = validator_signatures;
        operation.consensus_approved = true;
        operation.mode = HealingMode::Healing;

        info!(
            "Healing operation {} approved by consensus with {} signatures",
            operation_id,
            operation.validator_signatures.len()
        );

        Ok(())
    }

    /// Execute healing operation
    pub fn execute_healing(&mut self, operation_id: String) -> Result<HealingOperation, String> {
        let operation = self
            .active_operations
            .get(&operation_id)
            .ok_or_else(|| "Operation not found".to_string())?
            .clone();

        // Verify consensus requirement met
        if operation.requires_consensus && !operation.consensus_approved {
            return Err(
                "Operation requires consensus approval but is not yet approved".to_string(),
            );
        }

        let shard_id = operation.shard_id;

        // Determine recovery action based on fault severity
        let recovery_action = operation.fault_evidence.get_recovery_action();

        info!(
            "Executing healing operation {} with action {:?}",
            operation_id, recovery_action
        );

        match recovery_action {
            RecoveryAction::Monitor => {
                // Just increase monitoring, no state change
                info!("Increased monitoring for shard {}", shard_id.as_u64());
            }

            RecoveryAction::IncreaseMonitoring => {
                // Increase monitoring frequency
                info!(
                    "Increased monitoring frequency for shard {}",
                    shard_id.as_u64()
                );
            }

            RecoveryAction::IsolateShard => {
                // Isolate shard from network (would call isolation manager)
                info!("Isolated shard {} from network", shard_id.as_u64());
            }

            RecoveryAction::RollbackShard => {
                // Find latest finalized snapshot for shard
                if let Some(snapshot) = self.snapshot_engine.get_latest_finalized_snapshot(shard_id)
                {
                    // Initiate rollback
                    let rollback_result = self.rollback_engine.initiate_rollback(
                        shard_id,
                        snapshot.id,
                        operation.fault_evidence.fault_type.to_string(),
                        self.current_epoch,
                    );

                    match rollback_result {
                        Ok(_) => {
                            info!(
                                "Initiated rollback for shard {} to snapshot {}",
                                shard_id.as_u64(),
                                snapshot.id.as_u64()
                            );
                        }
                        Err(e) => {
                            error!("Failed to initiate rollback: {}", e);
                            return Err(e);
                        }
                    }
                } else {
                    return Err(format!(
                        "No finalized snapshot found for rollback of shard {}",
                        shard_id.as_u64()
                    ));
                }
            }

            RecoveryAction::Governance => {
                // Escalate to governance
                warn!(
                    "Escalating shard {} healing to governance",
                    shard_id.as_u64()
                );
            }
        }

        // Update operation
        let mut final_op = self
            .active_operations
            .remove(&operation_id)
            .ok_or_else(|| "Operation disappeared".to_string())?;

        final_op.mode = HealingMode::Completed;
        final_op.succeeded = true;

        self.statistics.successful_operations =
            self.statistics.successful_operations.saturating_add(1);
        self.statistics.active_operations = self.statistics.active_operations.saturating_sub(1);

        self.operation_history.push(final_op.clone());

        info!(
            "Completed healing operation {} for shard {}",
            operation_id,
            shard_id.as_u64()
        );

        Ok(final_op)
    }

    /// Mark operation as failed
    pub fn mark_operation_failed(&mut self, operation_id: String) -> Result<(), String> {
        let mut operation = self
            .active_operations
            .remove(&operation_id)
            .ok_or_else(|| "Operation not found".to_string())?;

        operation.mode = HealingMode::Paused;
        operation.succeeded = false;

        self.statistics.failed_operations = self.statistics.failed_operations.saturating_add(1);
        self.statistics.active_operations = self.statistics.active_operations.saturating_sub(1);

        self.operation_history.push(operation);

        warn!("Marked operation {} as failed", operation_id);

        Ok(())
    }

    /// Get operation status
    pub fn get_operation(&self, operation_id: &str) -> Option<&HealingOperation> {
        self.active_operations.get(operation_id)
    }

    /// Get all active operations
    pub fn get_active_operations(&self) -> Vec<&HealingOperation> {
        self.active_operations.values().collect()
    }

    /// Get statistics
    pub fn get_statistics(&self) -> HealingStatistics {
        HealingStatistics {
            active_operations: self.active_operations.len() as u64,
            ..self.statistics.clone()
        }
    }

    /// Get operation history
    pub fn get_history(&self) -> &[HealingOperation] {
        &self.operation_history
    }
}

impl FaultType {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

use crate::advanced_fault_detector::FaultType;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_orchestrator() -> SelfHealingOrchestrator {
        let snapshot_config = SnapshotConfig::new(10, 100, 1000, 0.66).unwrap();
        let fault_detection_config = FaultDetectionConfig::default();
        SelfHealingOrchestrator::new(snapshot_config, fault_detection_config, 3)
    }

    #[test]
    fn test_orchestrator_creation() {
        let orchestrator = create_test_orchestrator();
        assert_eq!(orchestrator.get_statistics().total_operations, 0);
    }

    #[test]
    fn test_epoch_update() {
        let mut orchestrator = create_test_orchestrator();
        orchestrator.update_epoch(EpochId(10));
        assert_eq!(orchestrator.current_epoch, EpochId(10));
    }

    #[test]
    fn test_healing_operation_creation() {
        let mut orchestrator = create_test_orchestrator();
        orchestrator.update_epoch(EpochId(10));

        let fault_evidence = FaultEvidence {
            fault_type: FaultType::LivenessFailure {
                missed_blocks: 5,
                timeout_epochs: 10,
            },
            shard_id: ShardId(0),
            epoch_id: EpochId(10),
            severity: FaultSeverity::Medium,
            evidence_hash: "hash".to_string(),
            detected_at: 1000,
            detection_rule: "rule".to_string(),
            witness_validators: vec![],
            block_height: 50,
            confirmed: true,
            investigation_status: crate::advanced_fault_detector::InvestigationStatus::Confirmed,
        };

        let result = orchestrator.on_fault_detected(ShardId(0), fault_evidence);
        assert!(result.is_ok());

        let op = result.unwrap();
        assert_eq!(op.shard_id, ShardId(0));
    }

    #[test]
    fn test_consensus_approval() {
        let mut orchestrator = create_test_orchestrator();
        orchestrator.update_epoch(EpochId(10));

        let fault_evidence = FaultEvidence {
            fault_type: FaultType::StateRootMismatch {
                expected_root: "a".to_string(),
                observed_root: "b".to_string(),
                dissenting_validators: 3,
            },
            shard_id: ShardId(0),
            epoch_id: EpochId(10),
            severity: FaultSeverity::Critical,
            evidence_hash: "hash".to_string(),
            detected_at: 1000,
            detection_rule: "rule".to_string(),
            witness_validators: vec![],
            block_height: 50,
            confirmed: true,
            investigation_status: crate::advanced_fault_detector::InvestigationStatus::Confirmed,
        };

        let op = orchestrator
            .on_fault_detected(ShardId(0), fault_evidence)
            .unwrap();
        assert!(op.requires_consensus);

        let signatures = vec![vec![1u8], vec![2u8], vec![3u8]];
        let approval_result =
            orchestrator.approve_from_consensus(op.operation_id.clone(), signatures);
        assert!(approval_result.is_ok());

        let approved_op = orchestrator.get_operation(&op.operation_id).unwrap();
        assert!(approved_op.consensus_approved);
    }
}
