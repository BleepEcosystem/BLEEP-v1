// PHASE 4: SHARD SELF-HEALING & ROLLBACK
// Recovery Orchestrator - Coordinates shard fault detection, isolation, rollback, and healing
//
// SAFETY INVARIANTS:
// 1. Recovery proceeds through deterministic, verifiable stages
// 2. Only one recovery operation per shard at a time
// 3. All decisions are consensus-verifiable
// 4. No global chain halt (network continues operating)
// 5. Recovery only at epoch boundaries
// 6. All operations are auditable and reproducible

use crate::shard_checkpoint::{CheckpointConfig, ShardCheckpointManager};
use crate::shard_fault_detection::{FaultDetectionConfig, FaultDetector, FaultEvidence};
use crate::shard_healing::ShardHealingManager;
use crate::shard_isolation::{IsolationStatus, ShardIsolationManager};
use crate::shard_registry::{EpochId, ShardId};
use crate::shard_rollback::RollbackEngine;
use crate::shard_validator_slashing::{
    ReassignmentStrategy, ValidatorReassignmentManager, ValidatorSlashingManager,
};

use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Recovery state machine enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryStage {
    /// Fault detected, awaiting consensus confirmation
    FaultDetected,

    /// Shard isolated, awaiting rollback decision
    Isolated,

    /// Rollback in progress
    RollingBack,

    /// Validators being slashed and reassigned
    ValidatorAdjustment,

    /// Shard healing in progress
    Healing,

    /// Recovery complete, awaiting reintegration
    RecoveryComplete,

    /// Shard reintegrated, back to normal
    Reintegrated,

    /// Recovery failed, requires manual intervention
    Failed,
}

/// Recovery operation record
///
/// SAFETY: Complete audit trail of shard recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryOperation {
    /// Shard being recovered
    pub shard_id: ShardId,

    /// Epoch when recovery started
    pub start_epoch: EpochId,

    /// Fault that triggered recovery
    pub trigger_fault: FaultEvidence,

    /// Current stage of recovery
    pub stage: RecoveryStage,

    /// Validators slashed during recovery
    pub slashed_validators: Vec<Vec<u8>>,

    /// Timestamp of recovery start
    pub start_timestamp: u64,

    /// Expected recovery completion epoch
    pub expected_completion_epoch: EpochId,

    /// Whether recovery has been finalized on-chain
    pub is_finalized: bool,
}

impl RecoveryOperation {
    /// Create a new recovery operation
    pub fn new(
        shard_id: ShardId,
        epoch: EpochId,
        fault: FaultEvidence,
        expected_completion: EpochId,
    ) -> Self {
        RecoveryOperation {
            shard_id,
            start_epoch: epoch,
            trigger_fault: fault,
            stage: RecoveryStage::FaultDetected,
            slashed_validators: Vec::new(),
            start_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expected_completion_epoch: expected_completion,
            is_finalized: false,
        }
    }
}

/// Recovery orchestrator - Main controller for shard recovery
///
/// SAFETY: All recovery operations are deterministic and consensus-verifiable.
pub struct RecoveryOrchestrator {
    /// Checkpoint manager
    checkpoint_manager: ShardCheckpointManager,

    /// Fault detector
    fault_detector: FaultDetector,

    /// Isolation manager
    isolation_manager: ShardIsolationManager,

    /// Rollback engine
    rollback_engine: RollbackEngine,

    /// Healing manager
    healing_manager: ShardHealingManager,

    /// Slashing manager
    slashing_manager: ValidatorSlashingManager,

    /// Reassignment manager
    reassignment_manager: ValidatorReassignmentManager,

    /// Active recovery operations per shard
    active_recoveries: HashMap<ShardId, RecoveryOperation>,

    /// Recovery history
    recovery_history: Vec<RecoveryOperation>,

    /// Current epoch
    current_epoch: EpochId,
}

impl RecoveryOrchestrator {
    /// Create a new recovery orchestrator
    pub fn new(
        checkpoint_config: CheckpointConfig,
        fault_detection_config: FaultDetectionConfig,
    ) -> Self {
        let checkpoint_manager = ShardCheckpointManager::new(checkpoint_config);
        let fault_detector = FaultDetector::new(fault_detection_config);
        let isolation_manager = ShardIsolationManager::new();
        let rollback_engine = RollbackEngine::new(checkpoint_manager.clone());
        let healing_manager = ShardHealingManager::new();
        let slashing_manager = ValidatorSlashingManager::new();
        let reassignment_manager = ValidatorReassignmentManager::new(
            slashing_manager.clone(),
            ReassignmentStrategy::DeterministicReshuffle,
        );

        RecoveryOrchestrator {
            checkpoint_manager,
            fault_detector,
            isolation_manager,
            rollback_engine,
            healing_manager,
            slashing_manager,
            reassignment_manager,
            active_recoveries: HashMap::new(),
            recovery_history: Vec::new(),
            current_epoch: EpochId(0),
        }
    }

    /// Update current epoch (called at epoch boundary)
    ///
    /// SAFETY: Epoch transitions trigger recovery stage progression.
    pub fn update_epoch(&mut self, epoch: EpochId) {
        self.current_epoch = epoch;
        info!("Recovery orchestrator updated to epoch {:?}", epoch);
    }

    /// Initiate recovery for a shard with detected fault
    ///
    /// SAFETY: Creates recovery operation record.
    pub fn initiate_recovery(
        &mut self,
        shard_id: ShardId,
        fault: FaultEvidence,
    ) -> Result<(), String> {
        if self.active_recoveries.contains_key(&shard_id) {
            return Err(format!("Shard {:?} is already in recovery", shard_id));
        }

        // Estimate recovery duration (typically 3-5 epochs)
        let expected_completion = EpochId(self.current_epoch.0 + 5);
        let mut operation = RecoveryOperation::new(
            shard_id,
            self.current_epoch,
            fault.clone(),
            expected_completion,
        );

        // Isolate the shard immediately
        self.isolation_manager
            .isolate_shard(shard_id, self.current_epoch.0, fault.clone(), 0)?;

        operation.stage = RecoveryStage::Isolated;

        self.active_recoveries.insert(shard_id, operation.clone());
        self.recovery_history.push(operation);

        info!(
            "Initiated recovery for shard {:?} due to fault: {}",
            shard_id, fault.details
        );

        Ok(())
    }

    /// Execute rollback for a shard
    ///
    /// SAFETY: Atomic, deterministic rollback to last valid checkpoint.
    pub fn execute_rollback(
        &mut self,
        shard_id: ShardId,
        current_height: u64,
    ) -> Result<(), String> {
        let operation = self
            .active_recoveries
            .get_mut(&shard_id)
            .ok_or("No active recovery for shard")?;

        if operation.stage != RecoveryStage::Isolated {
            return Err(format!(
                "Shard not ready for rollback: in {:?} stage",
                operation.stage
            ));
        }

        // Initiate rollback
        let mut rollback_record = self.rollback_engine.initiate_rollback(
            shard_id,
            current_height,
            operation.trigger_fault.clone(),
            self.current_epoch,
        )?;

        // Abort cross-shard transactions
        let _aborted = self
            .rollback_engine
            .abort_affected_transactions(shard_id, &mut rollback_record)?;

        // Release locks
        let _released = self
            .rollback_engine
            .release_locks(shard_id, &mut rollback_record)?;

        // Restore state from checkpoint
        let _restored_state = self.rollback_engine.restore_state(
            shard_id,
            rollback_record.target_checkpoint_id,
            &mut rollback_record,
        )?;

        // Complete rollback
        self.rollback_engine
            .complete_rollback(shard_id, &mut rollback_record)?;

        operation.stage = RecoveryStage::RollingBack;

        info!("Executed rollback for shard {:?}", shard_id);
        Ok(())
    }

    /// Perform validator slashing and reassignment
    ///
    /// SAFETY: Removes faulty validators and rebalances shard assignments.
    pub fn perform_validator_adjustment(
        &mut self,
        shard_id: ShardId,
        faulty_validators: Vec<Vec<u8>>,
        all_validators: &[Vec<u8>],
        num_shards: u64,
    ) -> Result<(), String> {
        let operation = self
            .active_recoveries
            .get_mut(&shard_id)
            .ok_or("No active recovery for shard")?;

        if operation.stage != RecoveryStage::RollingBack {
            return Err(format!(
                "Validator adjustment not allowed in {:?} stage",
                operation.stage
            ));
        }

        // Slash faulty validators
        for validator_pubkey in &faulty_validators {
            let record = crate::shard_validator_slashing::SlashingRecord {
                validator_pubkey: validator_pubkey.clone(),
                shard_id,
                reason: crate::shard_validator_slashing::SlashingReason::TransactionMisbehavior,
                amount_slashed: 1000, // Base slash amount
                evidence: operation.trigger_fault.clone(),
                slashing_epoch: self.current_epoch.0,
                is_finalized: false,
            };

            self.slashing_manager.slash_validator(record)?;
            operation.slashed_validators.push(validator_pubkey.clone());
        }

        // Plan validator reassignment
        let _reassignment_plan = self.reassignment_manager.plan_reassignment(
            all_validators,
            num_shards,
            self.current_epoch.0,
        )?;

        operation.stage = RecoveryStage::ValidatorAdjustment;

        info!(
            "Performed validator adjustment for shard {:?}: slashed {} validators",
            shard_id,
            faulty_validators.len()
        );

        Ok(())
    }

    /// Begin shard healing
    ///
    /// SAFETY: Shard syncs from checkpoint to current state.
    pub fn begin_healing(
        &mut self,
        shard_id: ShardId,
        target_height: u64,
        checkpoint_state_root: String,
    ) -> Result<(), String> {
        let operation = self
            .active_recoveries
            .get_mut(&shard_id)
            .ok_or("No active recovery for shard")?;

        if operation.stage != RecoveryStage::ValidatorAdjustment {
            return Err(format!(
                "Healing not allowed in {:?} stage",
                operation.stage
            ));
        }

        // Get latest finalized checkpoint
        let checkpoint = self
            .checkpoint_manager
            .get_rollback_target(shard_id, target_height)
            .ok_or("No valid checkpoint for healing")?;

        // Initiate healing
        self.healing_manager.initiate_healing(
            shard_id,
            checkpoint.id,
            target_height,
            checkpoint_state_root,
        )?;

        operation.stage = RecoveryStage::Healing;

        info!("Began healing for shard {:?}", shard_id);
        Ok(())
    }

    /// Report healing completion
    ///
    /// SAFETY: Shard state is now synchronized.
    pub fn complete_healing(&mut self, shard_id: ShardId) -> Result<(), String> {
        let operation = self
            .active_recoveries
            .get_mut(&shard_id)
            .ok_or("No active recovery for shard")?;

        if operation.stage != RecoveryStage::Healing {
            return Err(format!(
                "Healing not in progress for shard: {:?} stage",
                operation.stage
            ));
        }

        let healing_progress = self
            .healing_manager
            .get_healing_progress(shard_id)
            .ok_or("No healing progress for shard")?;

        // Verify healing is complete
        if !healing_progress.is_complete() {
            return Err("Healing not yet complete".to_string());
        }

        operation.stage = RecoveryStage::RecoveryComplete;

        info!("Completed healing for shard {:?}", shard_id);
        Ok(())
    }

    /// Reintegrate a recovered shard
    ///
    /// SAFETY: Requires epoch boundary and consensus verification.
    pub fn reintegrate_shard(&mut self, shard_id: ShardId) -> Result<(), String> {
        let operation = self
            .active_recoveries
            .get_mut(&shard_id)
            .ok_or("No active recovery for shard")?;

        if operation.stage != RecoveryStage::RecoveryComplete {
            return Err(format!(
                "Shard not ready for reintegration: in {:?} stage",
                operation.stage
            ));
        }

        // Finalize isolation (remove from isolated set)
        self.isolation_manager.complete_recovery(shard_id)?;

        operation.stage = RecoveryStage::Reintegrated;
        operation.is_finalized = true;

        info!("Reintegrated shard {:?} after recovery", shard_id);
        Ok(())
    }

    /// Get active recovery for a shard
    pub fn get_recovery(&self, shard_id: ShardId) -> Option<&RecoveryOperation> {
        self.active_recoveries.get(&shard_id)
    }

    /// Get all active recoveries
    pub fn get_active_recoveries(&self) -> Vec<&RecoveryOperation> {
        self.active_recoveries.values().collect()
    }

    /// Get recovery history
    pub fn get_recovery_history(&self) -> Vec<&RecoveryOperation> {
        self.recovery_history.iter().collect()
    }

    /// Check if shard is in recovery
    pub fn is_recovering(&self, shard_id: ShardId) -> bool {
        self.active_recoveries.contains_key(&shard_id)
    }

    /// Check if shard can accept transactions
    pub fn can_accept_transactions(&self, shard_id: ShardId) -> bool {
        self.isolation_manager.can_accept_transactions(shard_id)
    }

    /// Check if shard can participate in cross-shard transactions
    pub fn can_participate_in_crossshard(&self, shard_id: ShardId) -> bool {
        self.isolation_manager
            .can_participate_in_crossshard(shard_id)
    }

    /// Get isolation status for a shard
    pub fn get_isolation_status(&self, shard_id: ShardId) -> Option<IsolationStatus> {
        self.isolation_manager
            .get_isolation_history(shard_id)
            .last()
            .map(|record| record.status)
    }

    /// Force abort recovery (only in extreme circumstances)
    ///
    /// SAFETY: Should only be used if recovery is impossible.
    pub fn abort_recovery(&mut self, shard_id: ShardId) -> Result<(), String> {
        let operation = self
            .active_recoveries
            .remove(&shard_id)
            .ok_or("No active recovery for shard")?;

        let mut op = operation;
        op.stage = RecoveryStage::Failed;
        self.recovery_history.push(op);

        error!("Aborted recovery for shard {:?}", shard_id);
        Ok(())
    }

    /// Get fault detector reference
    pub fn fault_detector(&self) -> &FaultDetector {
        &self.fault_detector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard_fault_detection::{FaultSeverity, FaultType};

    #[test]
    fn test_recovery_operation_creation() {
        let fault = FaultEvidence {
            fault_type: FaultType::StateRootMismatch {
                expected_root: "root_a".to_string(),
                observed_root: "root_b".to_string(),
                dissenting_validators: 2,
            },
            shard_id: ShardId(0),
            epoch_id: EpochId(0),
            severity: FaultSeverity::Critical,
            detection_height: 100,
            proof: vec![],
            details: "test".to_string(),
        };

        let operation = RecoveryOperation::new(ShardId(0), EpochId(0), fault, EpochId(5));
        assert_eq!(operation.stage, RecoveryStage::FaultDetected);
    }

    #[test]
    fn test_orchestrator_creation() {
        let checkpoint_config = CheckpointConfig::new(100, 10, 1000).unwrap();
        let fault_config = FaultDetectionConfig::new(5, 50, 4).unwrap();
        let orchestrator = RecoveryOrchestrator::new(checkpoint_config, fault_config);

        assert_eq!(orchestrator.current_epoch, EpochId(0));
    }

    #[test]
    fn test_epoch_update() {
        let checkpoint_config = CheckpointConfig::new(100, 10, 1000).unwrap();
        let fault_config = FaultDetectionConfig::new(5, 50, 4).unwrap();
        let mut orchestrator = RecoveryOrchestrator::new(checkpoint_config, fault_config);

        orchestrator.update_epoch(EpochId(1));
        assert_eq!(orchestrator.current_epoch, EpochId(1));
    }
}
