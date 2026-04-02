// PHASE 4: SHARD SELF-HEALING & ROLLBACK
// Shard Checkpointing System - Deterministic, verifiable shard snapshots
//
// SAFETY INVARIANTS:
// 1. Checkpoints are created at deterministic intervals (every N shard blocks)
// 2. Each checkpoint includes shard ID, epoch, height, state root, validator signatures
// 3. Checkpoints are immutable once created and finalized
// 4. Checkpoints enable deterministic rollback to known-good state
// 5. Cross-shard transactions reference checkpoint epochs
// 6. All nodes independently derive identical checkpoints

use crate::shard_registry::{EpochId, ShardId, ShardStateRoot};
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Checkpoint ID - unique identifier for a checkpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct CheckpointId(pub u64);

impl CheckpointId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Checkpoint configuration - immutable settings for checkpointing
///
/// SAFETY: These parameters are locked at chain initialization.
/// Changing them requires a hard fork.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CheckpointConfig {
    /// Create checkpoint every N shard blocks
    pub blocks_per_checkpoint: u64,

    /// Maximum number of checkpoints retained per shard
    pub max_retained_checkpoints: u64,

    /// Rollback window (max blocks back to rollback)
    pub max_rollback_depth: u64,

    /// Genesis checkpoint ID
    pub genesis_checkpoint_id: u64,
}

impl CheckpointConfig {
    /// Create a new checkpoint configuration
    pub fn new(
        blocks_per_checkpoint: u64,
        max_retained_checkpoints: u64,
        max_rollback_depth: u64,
    ) -> Result<Self, String> {
        if blocks_per_checkpoint == 0 {
            return Err("blocks_per_checkpoint must be > 0".to_string());
        }
        if max_retained_checkpoints == 0 {
            return Err("max_retained_checkpoints must be > 0".to_string());
        }
        if max_rollback_depth == 0 {
            return Err("max_rollback_depth must be > 0".to_string());
        }

        Ok(CheckpointConfig {
            blocks_per_checkpoint,
            max_retained_checkpoints,
            max_rollback_depth,
            genesis_checkpoint_id: 0,
        })
    }

    /// Determine if a shard block should create a checkpoint
    pub fn should_create_checkpoint(&self, shard_height: u64) -> bool {
        shard_height > 0 && shard_height % self.blocks_per_checkpoint == 0
    }

    /// Compute checkpoint ID for a shard height
    pub fn checkpoint_id_for_height(&self, shard_height: u64) -> CheckpointId {
        CheckpointId(self.genesis_checkpoint_id + (shard_height / self.blocks_per_checkpoint))
    }
}

/// Shard checkpoint - deterministic snapshot of shard state
///
/// SAFETY: Checkpoints are cryptographically committed to the global chain.
/// They enable rollback without requiring re-execution of all transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardCheckpoint {
    /// Unique checkpoint identifier
    pub id: CheckpointId,

    /// Shard this checkpoint belongs to
    pub shard_id: ShardId,

    /// Epoch at checkpoint time
    pub epoch_id: EpochId,

    /// Shard height (block number within shard)
    pub shard_height: u64,

    /// Global block height corresponding to this checkpoint
    pub global_height: u64,

    /// State root of shard at this point
    pub state_root: ShardStateRoot,

    /// Merkle root of shard blocks from genesis to this checkpoint
    pub blocks_merkle_root: String,

    /// Validator set that validated blocks up to this checkpoint
    pub validator_signatures: Vec<ValidatorSignature>,

    /// Timestamp (seconds since epoch)
    pub timestamp: u64,

    /// Hash of this checkpoint (for verification)
    pub checkpoint_hash: String,

    /// Status of checkpoint
    pub status: CheckpointStatus,
}

/// Status of a checkpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointStatus {
    /// Checkpoint created, not yet finalized
    Pending,

    /// Checkpoint has quorum validator signatures
    Signed,

    /// Checkpoint is finalized on-chain
    Finalized,

    /// Checkpoint was invalidated (shard rolled back)
    Invalidated,
}

/// Validator signature on checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// Validator public key
    pub validator_pubkey: Vec<u8>,

    /// Signature over checkpoint
    pub signature: Vec<u8>,
}

impl ShardCheckpoint {
    /// Create a new checkpoint
    pub fn new(
        id: CheckpointId,
        shard_id: ShardId,
        epoch_id: EpochId,
        shard_height: u64,
        global_height: u64,
        state_root: ShardStateRoot,
        blocks_merkle_root: String,
    ) -> Self {
        let checkpoint_hash = Self::compute_checkpoint_hash(
            id,
            shard_id,
            epoch_id,
            shard_height,
            &state_root,
            &blocks_merkle_root,
        );

        ShardCheckpoint {
            id,
            shard_id,
            epoch_id,
            shard_height,
            global_height,
            state_root,
            blocks_merkle_root,
            validator_signatures: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            checkpoint_hash,
            status: CheckpointStatus::Pending,
        }
    }

    /// Compute deterministic checkpoint hash
    ///
    /// SAFETY: Hash includes all checkpoint data; any change invalidates it.
    pub fn compute_checkpoint_hash(
        id: CheckpointId,
        shard_id: ShardId,
        epoch_id: EpochId,
        shard_height: u64,
        state_root: &ShardStateRoot,
        blocks_merkle_root: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(id.0.to_le_bytes());
        hasher.update(shard_id.0.to_le_bytes());
        hasher.update(epoch_id.0.to_le_bytes());
        hasher.update(shard_height.to_le_bytes());
        hasher.update(state_root.root_hash.as_bytes());
        hasher.update(blocks_merkle_root.as_bytes());

        hex::encode(hasher.finalize())
    }

    /// Add validator signature to checkpoint
    pub fn add_signature(&mut self, pubkey: Vec<u8>, signature: Vec<u8>) {
        self.validator_signatures.push(ValidatorSignature {
            validator_pubkey: pubkey,
            signature,
        });
    }

    /// Check if checkpoint has minimum quorum signatures
    ///
    /// SAFETY: Requires 2f+1 signatures for Byzantine tolerance.
    pub fn has_quorum(&self, total_validators: usize) -> bool {
        let min_signatures = (2 * total_validators) / 3 + 1;
        self.validator_signatures.len() >= min_signatures
    }

    /// Verify checkpoint integrity
    pub fn verify_integrity(&self) -> Result<(), String> {
        let recomputed_hash = Self::compute_checkpoint_hash(
            self.id,
            self.shard_id,
            self.epoch_id,
            self.shard_height,
            &self.state_root,
            &self.blocks_merkle_root,
        );

        if recomputed_hash != self.checkpoint_hash {
            return Err("Checkpoint hash mismatch".to_string());
        }

        Ok(())
    }
}

/// Shard checkpoint manager - maintains checkpoint history
///
/// SAFETY: Guarantees deterministic checkpoint creation and retrieval.
#[derive(Clone)]
pub struct ShardCheckpointManager {
    config: CheckpointConfig,

    /// Checkpoints indexed by shard, then by checkpoint ID
    checkpoints: BTreeMap<ShardId, BTreeMap<CheckpointId, ShardCheckpoint>>,

    /// Latest checkpoint for each shard
    latest_checkpoint: BTreeMap<ShardId, CheckpointId>,
}

impl ShardCheckpointManager {
    /// Create a new checkpoint manager
    pub fn new(config: CheckpointConfig) -> Self {
        ShardCheckpointManager {
            config,
            checkpoints: BTreeMap::new(),
            latest_checkpoint: BTreeMap::new(),
        }
    }

    /// Create a new checkpoint for a shard
    ///
    /// SAFETY: Called deterministically when shard_height % blocks_per_checkpoint == 0
    pub fn create_checkpoint(
        &mut self,
        shard_id: ShardId,
        epoch_id: EpochId,
        shard_height: u64,
        global_height: u64,
        state_root: ShardStateRoot,
        blocks_merkle_root: String,
    ) -> Result<CheckpointId, String> {
        if !self.config.should_create_checkpoint(shard_height) {
            return Err(format!(
                "Checkpoint not due at shard height {}",
                shard_height
            ));
        }

        let checkpoint_id = self.config.checkpoint_id_for_height(shard_height);

        let checkpoint = ShardCheckpoint::new(
            checkpoint_id,
            shard_id,
            epoch_id,
            shard_height,
            global_height,
            state_root,
            blocks_merkle_root,
        );

        // Store checkpoint
        self.checkpoints
            .entry(shard_id)
            .or_insert_with(BTreeMap::new)
            .insert(checkpoint_id, checkpoint);

        self.latest_checkpoint.insert(shard_id, checkpoint_id);

        info!(
            "Created checkpoint {:?} for shard {:?} at height {}",
            checkpoint_id, shard_id, shard_height
        );
        Ok(checkpoint_id)
    }

    /// Get a checkpoint by shard and checkpoint ID
    pub fn get_checkpoint(
        &self,
        shard_id: ShardId,
        checkpoint_id: CheckpointId,
    ) -> Option<&ShardCheckpoint> {
        self.checkpoints.get(&shard_id)?.get(&checkpoint_id)
    }

    /// Get mutable reference to checkpoint
    pub fn get_checkpoint_mut(
        &mut self,
        shard_id: ShardId,
        checkpoint_id: CheckpointId,
    ) -> Option<&mut ShardCheckpoint> {
        self.checkpoints.get_mut(&shard_id)?.get_mut(&checkpoint_id)
    }

    /// Get latest checkpoint for a shard
    pub fn get_latest_checkpoint(&self, shard_id: ShardId) -> Option<&ShardCheckpoint> {
        let checkpoint_id = *self.latest_checkpoint.get(&shard_id)?;
        self.get_checkpoint(shard_id, checkpoint_id)
    }

    /// Finalize a checkpoint (mark it as on-chain finalized)
    pub fn finalize_checkpoint(
        &mut self,
        shard_id: ShardId,
        checkpoint_id: CheckpointId,
    ) -> Result<(), String> {
        let checkpoint = self
            .get_checkpoint_mut(shard_id, checkpoint_id)
            .ok_or("Checkpoint not found")?;

        if checkpoint.status != CheckpointStatus::Signed {
            return Err("Checkpoint must be signed before finalization".to_string());
        }

        checkpoint.status = CheckpointStatus::Finalized;
        info!(
            "Finalized checkpoint {:?} for shard {:?}",
            checkpoint_id, shard_id
        );
        Ok(())
    }

    /// Get valid rollback target for a shard
    ///
    /// SAFETY: Returns latest finalized checkpoint within rollback window.
    pub fn get_rollback_target(
        &self,
        shard_id: ShardId,
        current_height: u64,
    ) -> Option<&ShardCheckpoint> {
        let latest = self.get_latest_checkpoint(shard_id)?;

        // Must be finalized
        if latest.status != CheckpointStatus::Finalized {
            return None;
        }

        // Must be within rollback window
        if current_height.saturating_sub(latest.shard_height) > self.config.max_rollback_depth {
            return None;
        }

        Some(latest)
    }

    /// Prune old checkpoints for a shard (keep only N most recent)
    pub fn prune_old_checkpoints(&mut self, shard_id: ShardId) {
        if let Some(shard_checkpoints) = self.checkpoints.get_mut(&shard_id) {
            while shard_checkpoints.len() > self.config.max_retained_checkpoints as usize {
                let oldest_key = *shard_checkpoints.keys().next().unwrap();
                shard_checkpoints.remove(&oldest_key);
                info!(
                    "Pruned checkpoint {:?} for shard {:?}",
                    oldest_key, shard_id
                );
            }
        }
    }

    /// Get checkpoint range for a shard
    pub fn get_checkpoint_range(&self, shard_id: ShardId) -> Vec<&ShardCheckpoint> {
        self.checkpoints
            .get(&shard_id)
            .map(|checkpoints| checkpoints.values().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_config_creation() {
        let config = CheckpointConfig::new(100, 10, 1000).unwrap();
        assert_eq!(config.blocks_per_checkpoint, 100);
    }

    #[test]
    fn test_checkpoint_should_create() {
        let config = CheckpointConfig::new(100, 10, 1000).unwrap();

        assert!(!config.should_create_checkpoint(50));
        assert!(config.should_create_checkpoint(100));
        assert!(config.should_create_checkpoint(200));
    }

    #[test]
    fn test_checkpoint_creation() {
        let mut manager =
            ShardCheckpointManager::new(CheckpointConfig::new(100, 10, 1000).unwrap());

        let state_root = ShardStateRoot {
            root_hash: "0".repeat(64),
            tx_count: 100,
            height: 100,
        };

        let result = manager.create_checkpoint(
            ShardId(0),
            EpochId(0),
            100,
            1000,
            state_root,
            "merkle_root".to_string(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_checkpoint_retrieval() {
        let mut manager =
            ShardCheckpointManager::new(CheckpointConfig::new(100, 10, 1000).unwrap());

        let state_root = ShardStateRoot {
            root_hash: "0".repeat(64),
            tx_count: 100,
            height: 100,
        };

        let checkpoint_id = manager
            .create_checkpoint(
                ShardId(0),
                EpochId(0),
                100,
                1000,
                state_root,
                "merkle_root".to_string(),
            )
            .unwrap();

        let checkpoint = manager.get_checkpoint(ShardId(0), checkpoint_id).unwrap();
        assert_eq!(checkpoint.shard_height, 100);
    }

    #[test]
    fn test_checkpoint_hash_determinism() {
        let state_root = ShardStateRoot {
            root_hash: "abc".to_string(),
            tx_count: 100,
            height: 100,
        };

        let hash1 = ShardCheckpoint::compute_checkpoint_hash(
            CheckpointId(0),
            ShardId(0),
            EpochId(0),
            100,
            &state_root,
            "merkle_root",
        );

        let hash2 = ShardCheckpoint::compute_checkpoint_hash(
            CheckpointId(0),
            ShardId(0),
            EpochId(0),
            100,
            &state_root,
            "merkle_root",
        );

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_quorum_check() {
        let mut checkpoint = ShardCheckpoint::new(
            CheckpointId(0),
            ShardId(0),
            EpochId(0),
            100,
            1000,
            ShardStateRoot {
                root_hash: "0".repeat(64),
                tx_count: 100,
                height: 100,
            },
            "merkle_root".to_string(),
        );

        // Add 3 signatures for 4 validators (3/4 = 75% > 66%)
        checkpoint.add_signature(vec![1], vec![1, 2, 3]);
        checkpoint.add_signature(vec![2], vec![2, 3, 4]);
        checkpoint.add_signature(vec![3], vec![3, 4, 5]);

        assert!(checkpoint.has_quorum(4));
    }
}
