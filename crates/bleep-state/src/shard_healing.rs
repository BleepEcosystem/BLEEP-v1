// PHASE 4: SHARD SELF-HEALING & ROLLBACK
// Shard Healing & Reintegration Module - Recovery and return to service
//
// SAFETY INVARIANTS:
// 1. Healing proceeds through deterministic stages
// 2. Shard must sync state to latest epoch before reintegration
// 3. Reintegration is verified by consensus
// 4. No shortcuts or fast-forwarding allowed
// 5. Healing progress is auditable and reproducible

use crate::shard_checkpoint::CheckpointId;
use crate::shard_registry::{EpochId, ShardId};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Healing stage enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealingStage {
    /// Shard is initializing recovery
    Initializing,

    /// Shard is rebuilding from checkpoint
    Rebuilding,

    /// Shard is syncing blocks to current epoch
    SyncingBlocks,

    /// Shard is verifying state at each epoch boundary
    VerifyingState,

    /// Shard is ready for reintegration
    ReadyForReintegration,

    /// Shard has been reintegrated
    Reintegrated,
}

/// Healing progress record
///
/// SAFETY: Tracks healing progress for audit and recovery verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingProgress {
    /// Shard being healed
    pub shard_id: ShardId,

    /// Starting checkpoint
    pub start_checkpoint_id: CheckpointId,

    /// Current healing stage
    pub stage: HealingStage,

    /// Latest block height synced
    pub synced_height: u64,

    /// Target height (latest epoch)
    pub target_height: u64,

    /// Epochs verified since checkpoint
    pub epochs_verified: u64,

    /// Expected state root at current height
    pub expected_state_root: String,

    /// Actual reconstructed state root
    pub actual_state_root: String,

    /// Timestamp of healing start
    pub healing_start_timestamp: u64,
}

impl HealingProgress {
    /// Create a new healing progress record
    pub fn new(
        shard_id: ShardId,
        start_checkpoint_id: CheckpointId,
        target_height: u64,
        checkpoint_state_root: String,
    ) -> Self {
        HealingProgress {
            shard_id,
            start_checkpoint_id,
            stage: HealingStage::Initializing,
            synced_height: 0,
            target_height,
            epochs_verified: 0,
            expected_state_root: checkpoint_state_root.clone(),
            actual_state_root: checkpoint_state_root,
            healing_start_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Get healing progress percentage (0-100)
    pub fn progress_percent(&self) -> u8 {
        if self.target_height == 0 {
            return 0;
        }

        let progress = (self.synced_height * 100) / self.target_height;
        progress.min(100) as u8
    }

    /// Check if healing is complete
    pub fn is_complete(&self) -> bool {
        self.stage == HealingStage::Reintegrated
    }
}

/// Healing and reintegration manager
///
/// SAFETY: Orchestrates deterministic, verifiable shard healing.
#[derive(Clone)]
pub struct ShardHealingManager {
    /// Healing progress per shard
    healing_progress: HashMap<ShardId, HealingProgress>,
}

impl ShardHealingManager {
    /// Create a new healing manager
    pub fn new() -> Self {
        ShardHealingManager {
            healing_progress: HashMap::new(),
        }
    }

    /// Initiate healing for a shard
    ///
    /// SAFETY: Creates healing progress record and begins recovery.
    pub fn initiate_healing(
        &mut self,
        shard_id: ShardId,
        start_checkpoint_id: CheckpointId,
        target_height: u64,
        checkpoint_state_root: String,
    ) -> Result<(), String> {
        if self.healing_progress.contains_key(&shard_id) {
            return Err(format!("Shard {:?} is already being healed", shard_id));
        }

        let progress = HealingProgress::new(
            shard_id,
            start_checkpoint_id,
            target_height,
            checkpoint_state_root,
        );

        self.healing_progress.insert(shard_id, progress);

        info!("Initiated healing for shard {:?}", shard_id);
        Ok(())
    }

    /// Progress to rebuilding stage
    ///
    /// SAFETY: Shard is being rebuilt from checkpoint.
    pub fn begin_rebuilding(&mut self, shard_id: ShardId) -> Result<(), String> {
        let progress = self
            .healing_progress
            .get_mut(&shard_id)
            .ok_or("Shard not in healing")?;

        if progress.stage != HealingStage::Initializing {
            return Err(format!(
                "Cannot rebuild: shard in {:?} stage",
                progress.stage
            ));
        }

        progress.stage = HealingStage::Rebuilding;
        progress.synced_height = 0;

        info!("Beginning rebuild for shard {:?}", shard_id);
        Ok(())
    }

    /// Report rebuilding completion
    pub fn complete_rebuilding(&mut self, shard_id: ShardId) -> Result<(), String> {
        let progress = self
            .healing_progress
            .get_mut(&shard_id)
            .ok_or("Shard not in healing")?;

        if progress.stage != HealingStage::Rebuilding {
            return Err(format!("Shard not in rebuilding stage"));
        }

        progress.stage = HealingStage::SyncingBlocks;
        info!("Completed rebuild for shard {:?}, beginning sync", shard_id);
        Ok(())
    }

    /// Update syncing progress
    ///
    /// SAFETY: Reports blocks synced since checkpoint.
    pub fn update_sync_progress(
        &mut self,
        shard_id: ShardId,
        current_height: u64,
        current_state_root: String,
    ) -> Result<(), String> {
        let progress = self
            .healing_progress
            .get_mut(&shard_id)
            .ok_or("Shard not in healing")?;

        if progress.stage != HealingStage::SyncingBlocks {
            return Err(format!("Shard not in sync stage"));
        }

        if current_height <= progress.synced_height {
            return Err("Cannot sync backwards".to_string());
        }

        progress.synced_height = current_height;
        progress.actual_state_root = current_state_root;

        info!(
            "Shard {:?} synced to height {} ({}%)",
            shard_id,
            current_height,
            progress.progress_percent()
        );

        Ok(())
    }

    /// Verify state root at an epoch boundary
    ///
    /// SAFETY: Ensures state matches expected value.
    pub fn verify_epoch_state(
        &mut self,
        shard_id: ShardId,
        epoch_id: EpochId,
        expected_root: &str,
        actual_root: &str,
    ) -> Result<(), String> {
        let progress = self
            .healing_progress
            .get_mut(&shard_id)
            .ok_or("Shard not in healing")?;

        if expected_root != actual_root {
            error!(
                "State mismatch during healing for shard {:?} at epoch {:?}",
                shard_id, epoch_id
            );
            return Err(format!("State root mismatch at epoch {:?}", epoch_id));
        }

        progress.epochs_verified += 1;
        progress.expected_state_root = expected_root.to_string();
        progress.actual_state_root = actual_root.to_string();

        info!(
            "Verified epoch {:?} for shard {:?}, {} epochs verified total",
            epoch_id, shard_id, progress.epochs_verified
        );

        Ok(())
    }

    /// Complete syncing stage
    ///
    /// SAFETY: Shard has synced all blocks to current height.
    pub fn complete_syncing(&mut self, shard_id: ShardId) -> Result<(), String> {
        let progress = self
            .healing_progress
            .get_mut(&shard_id)
            .ok_or("Shard not in healing")?;

        if progress.stage != HealingStage::SyncingBlocks {
            return Err(format!("Shard not in sync stage"));
        }

        if progress.synced_height < progress.target_height {
            return Err(format!(
                "Shard not fully synced: {} < {}",
                progress.synced_height, progress.target_height
            ));
        }

        progress.stage = HealingStage::VerifyingState;

        info!("Completed syncing for shard {:?}", shard_id);
        Ok(())
    }

    /// Mark shard as ready for reintegration
    ///
    /// SAFETY: All healing stages complete.
    pub fn mark_ready_for_reintegration(&mut self, shard_id: ShardId) -> Result<(), String> {
        let progress = self
            .healing_progress
            .get_mut(&shard_id)
            .ok_or("Shard not in healing")?;

        if progress.stage != HealingStage::VerifyingState {
            return Err(format!(
                "Shard not ready: still in {:?} stage",
                progress.stage
            ));
        }

        progress.stage = HealingStage::ReadyForReintegration;

        info!("Shard {:?} is ready for reintegration", shard_id);
        Ok(())
    }

    /// Complete reintegration (shard is back to normal)
    ///
    /// SAFETY: Consensus has verified all healing steps.
    pub fn complete_reintegration(&mut self, shard_id: ShardId) -> Result<(), String> {
        let progress = self
            .healing_progress
            .get_mut(&shard_id)
            .ok_or("Shard not in healing")?;

        if progress.stage != HealingStage::ReadyForReintegration {
            return Err(format!(
                "Shard not ready: still in {:?} stage",
                progress.stage
            ));
        }

        progress.stage = HealingStage::Reintegrated;

        info!("Completed reintegration for shard {:?}", shard_id);
        Ok(())
    }

    /// Get healing progress for a shard
    pub fn get_healing_progress(&self, shard_id: ShardId) -> Option<&HealingProgress> {
        self.healing_progress.get(&shard_id)
    }

    /// Get all shards being healed
    pub fn get_healing_shards(&self) -> Vec<ShardId> {
        self.healing_progress.keys().copied().collect()
    }

    /// Check if a shard is healing
    pub fn is_healing(&self, shard_id: ShardId) -> bool {
        self.healing_progress.contains_key(&shard_id)
    }
}

/// Reintegration validator
///
/// SAFETY: Verifies shard is ready to be reintegrated.
pub struct ReintegrationValidator;

impl ReintegrationValidator {
    /// Verify that a shard can be safely reintegrated
    ///
    /// SAFETY: Checks all preconditions.
    pub fn validate_reintegration(progress: &HealingProgress) -> Result<(), String> {
        // Must have synced to target height
        if progress.synced_height < progress.target_height {
            return Err(format!(
                "Shard not fully synced: {} < {}",
                progress.synced_height, progress.target_height
            ));
        }

        // State roots must match
        if progress.expected_state_root != progress.actual_state_root {
            return Err(format!(
                "State root mismatch: expected {}, got {}",
                progress.expected_state_root, progress.actual_state_root
            ));
        }

        // Must have completed all epochs
        if progress.epochs_verified == 0 {
            return Err("No epochs verified during healing".to_string());
        }

        // Must be in ready stage
        if progress.stage != HealingStage::ReadyForReintegration {
            return Err(format!("Shard not in ready stage: {:?}", progress.stage));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healing_progress_creation() {
        let progress = HealingProgress::new(ShardId(0), CheckpointId(5), 1000, "root".to_string());

        assert_eq!(progress.stage, HealingStage::Initializing);
        assert_eq!(progress.progress_percent(), 0);
    }

    #[test]
    fn test_healing_stage_progression() {
        let mut manager = ShardHealingManager::new();

        manager
            .initiate_healing(ShardId(0), CheckpointId(5), 1000, "root".to_string())
            .unwrap();

        manager.begin_rebuilding(ShardId(0)).unwrap();
        let progress = manager.get_healing_progress(ShardId(0)).unwrap();
        assert_eq!(progress.stage, HealingStage::Rebuilding);
    }

    #[test]
    fn test_healing_progress_percentage() {
        let mut progress =
            HealingProgress::new(ShardId(0), CheckpointId(5), 1000, "root".to_string());

        progress.synced_height = 500;
        assert_eq!(progress.progress_percent(), 50);

        progress.synced_height = 1000;
        assert_eq!(progress.progress_percent(), 100);
    }

    #[test]
    fn test_reintegration_validation() {
        let mut progress =
            HealingProgress::new(ShardId(0), CheckpointId(5), 1000, "root".to_string());

        progress.synced_height = 1000;
        progress.epochs_verified = 5;
        progress.stage = HealingStage::ReadyForReintegration;

        assert!(ReintegrationValidator::validate_reintegration(&progress).is_ok());
    }
}
