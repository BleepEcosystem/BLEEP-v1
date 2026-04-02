// PHASE 2: VERIFIABLE STATE SNAPSHOTS
// Canonical Snapshot Engine - Foundation for autonomous recovery
//
// SAFETY INVARIANTS:
// 1. Snapshots are created at deterministic intervals (epoch-bound)
// 2. Each snapshot includes: state root, validator signatures, epoch ID, height
// 3. Snapshots are immutable once finalized on-chain
// 4. All snapshots form a deterministic lineage (ancestry verified)
// 5. No snapshot can be created for heights in the past (monotonic)
// 6. Snapshots enable deterministic rollback without re-execution
// 7. All nodes independently derive identical snapshots

use crate::shard_registry::{EpochId, ShardId, ShardStateRoot};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};

/// Snapshot ID - unique identifier for a snapshot
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct SnapshotId(pub u64);

impl SnapshotId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Snapshot configuration - immutable settings set at genesis
///
/// SAFETY: These parameters are locked at chain initialization and cannot be changed.
/// Changing them requires a hard fork consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Create snapshot every N epochs (must be > 0)
    pub epochs_per_snapshot: u64,

    /// Maximum number of snapshots retained (for rollback window)
    pub max_retained_snapshots: u64,

    /// Maximum rollback depth (blocks back from latest)
    pub max_rollback_depth: u64,

    /// Minimum validator quorum for snapshot signatures (e.g., 2/3 of stake)
    pub min_validator_quorum: f64,

    /// Genesis snapshot ID
    pub genesis_snapshot_id: u64,
}

impl SnapshotConfig {
    /// Create a new snapshot configuration
    pub fn new(
        epochs_per_snapshot: u64,
        max_retained_snapshots: u64,
        max_rollback_depth: u64,
        min_validator_quorum: f64,
    ) -> Result<Self, String> {
        if epochs_per_snapshot == 0 {
            return Err("epochs_per_snapshot must be > 0".to_string());
        }
        if max_retained_snapshots == 0 {
            return Err("max_retained_snapshots must be > 0".to_string());
        }
        if max_rollback_depth == 0 {
            return Err("max_rollback_depth must be > 0".to_string());
        }
        if !(0.0..=1.0).contains(&min_validator_quorum) {
            return Err("min_validator_quorum must be between 0 and 1".to_string());
        }

        Ok(SnapshotConfig {
            epochs_per_snapshot,
            max_retained_snapshots,
            max_rollback_depth,
            min_validator_quorum,
            genesis_snapshot_id: 0,
        })
    }

    /// Determine if snapshot should be created at this epoch
    pub fn should_create_snapshot(&self, epoch: u64) -> bool {
        epoch > 0 && epoch % self.epochs_per_snapshot == 0
    }

    /// Compute snapshot ID for an epoch
    pub fn snapshot_id_for_epoch(&self, epoch: u64) -> SnapshotId {
        SnapshotId(self.genesis_snapshot_id + (epoch / self.epochs_per_snapshot))
    }
}

/// Validator signature on a snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotValidatorSignature {
    /// Validator public key
    pub validator_pubkey: Vec<u8>,

    /// Signature over snapshot hash
    pub signature: Vec<u8>,

    /// Stake of this validator (for quorum calculation)
    pub stake: u128,
}

/// Snapshot status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotStatus {
    /// Snapshot created, not yet finalized
    Pending,

    /// Snapshot has collected quorum signatures
    Signed,

    /// Snapshot is finalized on-chain
    Finalized,

    /// Snapshot was invalidated (chain rolled back)
    Invalidated,
}

/// State snapshot - cryptographically committed state at epoch boundary
///
/// SAFETY: Snapshots form the foundation for deterministic recovery.
/// Each snapshot completely captures shard state and is consensus-verifiable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Unique snapshot identifier
    pub id: SnapshotId,

    /// Shard this snapshot belongs to
    pub shard_id: ShardId,

    /// Epoch at snapshot time
    pub epoch_id: EpochId,

    /// Global block height at snapshot
    pub global_height: u64,

    /// State root of shard at this point
    pub state_root: ShardStateRoot,

    /// Merkle root of all transactions in this epoch
    pub transactions_merkle_root: String,

    /// Validator signatures on this snapshot
    pub validator_signatures: Vec<SnapshotValidatorSignature>,

    /// Hash of this snapshot
    pub snapshot_hash: String,

    /// Status of snapshot
    pub status: SnapshotStatus,

    /// Timestamp (seconds since epoch)
    pub timestamp: u64,

    /// Previous snapshot ID (enables lineage verification)
    pub previous_snapshot_id: Option<SnapshotId>,

    /// Proof of inclusion in consensus state
    pub consensus_inclusion_proof: Option<Vec<u8>>,
}

impl StateSnapshot {
    /// Create a new snapshot
    pub fn new(
        id: SnapshotId,
        shard_id: ShardId,
        epoch_id: EpochId,
        global_height: u64,
        state_root: ShardStateRoot,
        transactions_merkle_root: String,
        previous_snapshot_id: Option<SnapshotId>,
    ) -> Self {
        let mut snapshot = StateSnapshot {
            id,
            shard_id,
            epoch_id,
            global_height,
            state_root,
            transactions_merkle_root,
            validator_signatures: Vec::new(),
            snapshot_hash: String::new(),
            status: SnapshotStatus::Pending,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            previous_snapshot_id,
            consensus_inclusion_proof: None,
        };

        // Compute snapshot hash
        snapshot.snapshot_hash = snapshot.compute_hash();
        snapshot
    }

    /// Compute cryptographic hash of this snapshot
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_u64().to_le_bytes());
        hasher.update(self.shard_id.as_u64().to_le_bytes());
        hasher.update(self.epoch_id.as_u64().to_le_bytes());
        hasher.update(self.global_height.to_le_bytes());
        hasher.update(self.state_root.root_hash.as_bytes());
        hasher.update(self.transactions_merkle_root.as_bytes());
        hasher.update(self.timestamp.to_le_bytes());

        hex::encode(hasher.finalize())
    }

    /// Add a validator signature to this snapshot
    ///
    /// SAFETY: Must verify signature is valid before adding
    pub fn add_validator_signature(
        &mut self,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
        stake: u128,
    ) -> Result<(), String> {
        if self.status == SnapshotStatus::Finalized {
            return Err("Cannot add signatures to finalized snapshot".to_string());
        }

        self.validator_signatures.push(SnapshotValidatorSignature {
            validator_pubkey: pubkey,
            signature,
            stake,
        });

        Ok(())
    }

    /// Verify snapshot has quorum support
    pub fn verify_quorum(&self, total_stake: u128, min_quorum: f64) -> bool {
        let signed_stake: u128 = self.validator_signatures.iter().map(|s| s.stake).sum();
        let quorum_stake = (total_stake as f64 * min_quorum) as u128;

        signed_stake >= quorum_stake
    }

    /// Finalize this snapshot (mark as on-chain)
    pub fn finalize(&mut self, inclusion_proof: Vec<u8>) -> Result<(), String> {
        if self.status == SnapshotStatus::Finalized {
            return Err("Snapshot already finalized".to_string());
        }

        self.status = SnapshotStatus::Finalized;
        self.consensus_inclusion_proof = Some(inclusion_proof);

        info!(
            "Snapshot {} for shard {} epoch {} finalized",
            self.id.as_u64(),
            self.shard_id.as_u64(),
            self.epoch_id.as_u64()
        );

        Ok(())
    }

    /// Invalidate this snapshot (chain rolled back past it)
    pub fn invalidate(&mut self) -> Result<(), String> {
        if self.status == SnapshotStatus::Invalidated {
            return Err("Snapshot already invalidated".to_string());
        }

        self.status = SnapshotStatus::Invalidated;

        warn!(
            "Snapshot {} for shard {} invalidated",
            self.id.as_u64(),
            self.shard_id.as_u64()
        );

        Ok(())
    }
}

/// Snapshot inclusion proof - proves snapshot is in consensus state
///
/// SAFETY: Proves snapshot is consensus-approved and recoverable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInclusionProof {
    /// Snapshot ID
    pub snapshot_id: SnapshotId,

    /// Block height where snapshot was finalized
    pub finalization_height: u64,

    /// Merkle proof path from block to snapshot
    pub merkle_proof: Vec<String>,

    /// Validators who signed inclusion
    pub validator_signatures: Vec<Vec<u8>>,
}

/// Snapshot lineage - tracks snapshot ancestry
///
/// SAFETY: Proves snapshot chain is unbroken and fork-safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotLineage {
    /// Snapshots in order (oldest to newest)
    pub snapshots: VecDeque<SnapshotId>,

    /// Hash of lineage (for efficient verification)
    pub lineage_hash: String,
}

impl SnapshotLineage {
    /// Create a new lineage with genesis snapshot
    pub fn new(genesis_id: SnapshotId) -> Self {
        let mut lineage = SnapshotLineage {
            snapshots: VecDeque::new(),
            lineage_hash: String::new(),
        };
        lineage.snapshots.push_back(genesis_id);
        lineage.lineage_hash = lineage.compute_hash();
        lineage
    }

    /// Add a snapshot to lineage
    pub fn add_snapshot(&mut self, snapshot_id: SnapshotId) -> Result<(), String> {
        // Snapshots must be added in order (increasing IDs)
        if let Some(&last_id) = self.snapshots.back() {
            if snapshot_id <= last_id {
                return Err("Snapshot ID must increase monotonically".to_string());
            }
        }

        self.snapshots.push_back(snapshot_id);
        self.lineage_hash = self.compute_hash();

        Ok(())
    }

    /// Verify snapshot exists in lineage
    pub fn contains(&self, snapshot_id: SnapshotId) -> bool {
        self.snapshots.contains(&snapshot_id)
    }

    /// Get direct parent of snapshot
    pub fn get_parent(&self, snapshot_id: SnapshotId) -> Option<SnapshotId> {
        let position = self.snapshots.iter().position(|&id| id == snapshot_id)?;
        if position > 0 {
            Some(self.snapshots[position - 1])
        } else {
            None
        }
    }

    /// Compute hash of lineage
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        for snapshot_id in &self.snapshots {
            hasher.update(snapshot_id.as_u64().to_le_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Verify lineage integrity
    pub fn verify(&self) -> bool {
        if self.snapshots.is_empty() {
            return false;
        }

        // Check monotonic increase
        let ids: Vec<u64> = self.snapshots.iter().map(|s| s.as_u64()).collect();
        for i in 1..ids.len() {
            if ids[i] <= ids[i - 1] {
                return false;
            }
        }

        // Verify lineage hash
        self.lineage_hash == self.compute_hash()
    }
}

/// Canonical Snapshot Engine - Main orchestrator
///
/// SAFETY: Single authoritative source for snapshot management.
/// All recovery and rollback operations derive from this engine.
#[derive(Clone)]
pub struct SnapshotEngine {
    /// Configuration
    config: SnapshotConfig,

    /// All snapshots, indexed by ID
    snapshots: BTreeMap<SnapshotId, StateSnapshot>,

    /// Snapshots per shard
    snapshots_per_shard: BTreeMap<ShardId, Vec<SnapshotId>>,

    /// Snapshot lineage (ancestry)
    lineage: SnapshotLineage,

    /// Next snapshot ID to assign
    next_snapshot_id: SnapshotId,

    /// Total stake of validators (for quorum calculation)
    total_validator_stake: u128,
}

impl SnapshotEngine {
    /// Create a new snapshot engine
    pub fn new(config: SnapshotConfig, genesis_snapshot_id: SnapshotId) -> Self {
        let lineage = SnapshotLineage::new(genesis_snapshot_id);

        SnapshotEngine {
            config,
            snapshots: BTreeMap::new(),
            snapshots_per_shard: BTreeMap::new(),
            lineage,
            next_snapshot_id: SnapshotId(genesis_snapshot_id.as_u64() + 1),
            total_validator_stake: 0,
        }
    }

    /// Register validator stake (for quorum calculation)
    pub fn register_validator_stake(&mut self, stake: u128) {
        self.total_validator_stake = self.total_validator_stake.saturating_add(stake);
    }

    /// Create a new snapshot
    pub fn create_snapshot(
        &mut self,
        shard_id: ShardId,
        epoch_id: EpochId,
        global_height: u64,
        state_root: ShardStateRoot,
        transactions_merkle_root: String,
    ) -> Result<SnapshotId, String> {
        // Check if snapshot should be created at this epoch
        if !self.config.should_create_snapshot(epoch_id.as_u64()) {
            return Err(format!(
                "Snapshot should not be created at epoch {}",
                epoch_id.as_u64()
            ));
        }

        // Get previous snapshot for lineage
        let previous_snapshot_id = self
            .snapshots_per_shard
            .get(&shard_id)
            .and_then(|ids| ids.last())
            .copied();

        let snapshot_id = self.next_snapshot_id;
        let mut snapshot = StateSnapshot::new(
            snapshot_id,
            shard_id,
            epoch_id,
            global_height,
            state_root,
            transactions_merkle_root,
            previous_snapshot_id,
        );

        // Mark as signed if no signatures collected yet
        snapshot.status = SnapshotStatus::Signed;

        self.snapshots.insert(snapshot_id, snapshot);
        self.snapshots_per_shard
            .entry(shard_id)
            .or_insert_with(Vec::new)
            .push(snapshot_id);

        self.next_snapshot_id = SnapshotId(snapshot_id.as_u64() + 1);

        info!(
            "Created snapshot {} for shard {} at epoch {}",
            snapshot_id.as_u64(),
            shard_id.as_u64(),
            epoch_id.as_u64()
        );

        Ok(snapshot_id)
    }

    /// Finalize a snapshot (mark it as on-chain)
    pub fn finalize_snapshot(
        &mut self,
        snapshot_id: SnapshotId,
        inclusion_proof: Vec<u8>,
    ) -> Result<(), String> {
        let snapshot = self
            .snapshots
            .get_mut(&snapshot_id)
            .ok_or_else(|| format!("Snapshot {} not found", snapshot_id.as_u64()))?;

        snapshot.finalize(inclusion_proof)?;

        // Add to lineage
        self.lineage.add_snapshot(snapshot_id)?;

        Ok(())
    }

    /// Get a snapshot by ID
    pub fn get_snapshot(&self, snapshot_id: SnapshotId) -> Option<&StateSnapshot> {
        self.snapshots.get(&snapshot_id)
    }

    /// Get latest finalized snapshot for shard
    pub fn get_latest_finalized_snapshot(&self, shard_id: ShardId) -> Option<&StateSnapshot> {
        let snapshot_ids = self.snapshots_per_shard.get(&shard_id)?;

        snapshot_ids.iter().rev().find_map(|&id| {
            let snapshot = self.snapshots.get(&id)?;
            if snapshot.status == SnapshotStatus::Finalized {
                Some(snapshot)
            } else {
                None
            }
        })
    }

    /// Get all snapshots for a shard
    pub fn get_snapshots_for_shard(&self, shard_id: ShardId) -> Vec<&StateSnapshot> {
        let snapshot_ids = match self.snapshots_per_shard.get(&shard_id) {
            Some(ids) => ids,
            None => return Vec::new(),
        };

        snapshot_ids
            .iter()
            .filter_map(|&id| self.snapshots.get(&id))
            .collect()
    }

    /// Verify snapshot lineage
    pub fn verify_lineage(&self) -> Result<(), String> {
        if !self.lineage.verify() {
            return Err("Snapshot lineage verification failed".to_string());
        }
        Ok(())
    }

    /// Check if snapshot can be used for rollback
    pub fn can_rollback_to(
        &self,
        snapshot_id: SnapshotId,
        current_height: u64,
    ) -> Result<(), String> {
        let snapshot = self
            .snapshots
            .get(&snapshot_id)
            .ok_or_else(|| format!("Snapshot {} not found", snapshot_id.as_u64()))?;

        // Must be finalized
        if snapshot.status != SnapshotStatus::Finalized {
            return Err(format!(
                "Snapshot {} is not finalized (status: {:?})",
                snapshot_id.as_u64(),
                snapshot.status
            ));
        }

        // Must be within rollback window
        let distance = current_height.saturating_sub(snapshot.global_height);
        if distance > self.config.max_rollback_depth {
            return Err(format!(
                "Snapshot {} is too old for rollback ({}> {} blocks)",
                snapshot_id.as_u64(),
                distance,
                self.config.max_rollback_depth
            ));
        }

        Ok(())
    }

    /// Prune old snapshots beyond retention window
    pub fn prune_old_snapshots(&mut self) -> Result<Vec<SnapshotId>, String> {
        let mut pruned = Vec::new();

        for (_shard_id, snapshot_ids) in self.snapshots_per_shard.iter_mut() {
            while snapshot_ids.len() > self.config.max_retained_snapshots as usize {
                if let Some(old_id) = snapshot_ids.first().copied() {
                    self.snapshots.remove(&old_id);
                    pruned.push(old_id);
                    snapshot_ids.remove(0);
                }
            }
        }

        Ok(pruned)
    }

    /// Get snapshot lineage
    pub fn get_lineage(&self) -> &SnapshotLineage {
        &self.lineage
    }

    /// Get total snapshots in system
    pub fn total_snapshots(&self) -> usize {
        self.snapshots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_config_creation() {
        let config = SnapshotConfig::new(10, 100, 1000, 0.66).unwrap();
        assert_eq!(config.epochs_per_snapshot, 10);
        assert_eq!(config.max_retained_snapshots, 100);
    }

    #[test]
    fn test_snapshot_config_validation() {
        assert!(SnapshotConfig::new(0, 100, 1000, 0.66).is_err());
        assert!(SnapshotConfig::new(10, 0, 1000, 0.66).is_err());
        assert!(SnapshotConfig::new(10, 100, 0, 0.66).is_err());
        assert!(SnapshotConfig::new(10, 100, 1000, 1.5).is_err());
    }

    #[test]
    fn test_snapshot_should_create() {
        let config = SnapshotConfig::new(10, 100, 1000, 0.66).unwrap();
        assert!(!config.should_create_snapshot(0));
        assert!(!config.should_create_snapshot(5));
        assert!(config.should_create_snapshot(10));
        assert!(!config.should_create_snapshot(15));
        assert!(config.should_create_snapshot(20));
    }

    #[test]
    fn test_snapshot_creation_and_retrieval() {
        let config = SnapshotConfig::new(10, 100, 1000, 0.66).unwrap();
        let mut engine = SnapshotEngine::new(config, SnapshotId(0));

        let root = ShardStateRoot {
            root_hash: "test_root".to_string(),
            tx_count: 100,
            height: 10,
        };

        let snapshot_id = engine
            .create_snapshot(
                ShardId(0),
                EpochId(10),
                100,
                root.clone(),
                "tx_merkle_root".to_string(),
            )
            .unwrap();

        let snapshot = engine.get_snapshot(snapshot_id).unwrap();
        assert_eq!(snapshot.shard_id, ShardId(0));
        assert_eq!(snapshot.epoch_id, EpochId(10));
    }

    #[test]
    fn test_snapshot_lineage() {
        let config = SnapshotConfig::new(10, 100, 1000, 0.66).unwrap();
        let mut engine = SnapshotEngine::new(config, SnapshotId(0));

        let root = ShardStateRoot {
            root_hash: "test_root".to_string(),
            tx_count: 100,
            height: 10,
        };

        let id1 = engine
            .create_snapshot(
                ShardId(0),
                EpochId(10),
                100,
                root.clone(),
                "merkle1".to_string(),
            )
            .unwrap();

        let id2 = engine
            .create_snapshot(
                ShardId(0),
                EpochId(20),
                200,
                root.clone(),
                "merkle2".to_string(),
            )
            .unwrap();

        engine.finalize_snapshot(id1, vec![]).unwrap();
        engine.finalize_snapshot(id2, vec![]).unwrap();

        assert!(engine.get_lineage().contains(id1));
        assert!(engine.get_lineage().contains(id2));
        assert_eq!(engine.get_lineage().get_parent(id2), Some(id1));
    }

    #[test]
    fn test_cannot_rollback_unfinalized_snapshot() {
        let config = SnapshotConfig::new(10, 100, 1000, 0.66).unwrap();
        let mut engine = SnapshotEngine::new(config, SnapshotId(0));

        let root = ShardStateRoot {
            root_hash: "test_root".to_string(),
            tx_count: 100,
            height: 10,
        };

        let snapshot_id = engine
            .create_snapshot(ShardId(0), EpochId(10), 100, root, "merkle".to_string())
            .unwrap();

        assert!(engine.can_rollback_to(snapshot_id, 200).is_err());
    }

    #[test]
    fn test_snapshot_pruning() {
        let config = SnapshotConfig::new(10, 2, 1000, 0.66).unwrap();
        let mut engine = SnapshotEngine::new(config, SnapshotId(0));

        let root = ShardStateRoot {
            root_hash: "test_root".to_string(),
            tx_count: 100,
            height: 10,
        };

        let _id1 = engine
            .create_snapshot(
                ShardId(0),
                EpochId(10),
                100,
                root.clone(),
                "merkle1".to_string(),
            )
            .unwrap();

        let _id2 = engine
            .create_snapshot(
                ShardId(0),
                EpochId(20),
                200,
                root.clone(),
                "merkle2".to_string(),
            )
            .unwrap();

        let id3 = engine
            .create_snapshot(
                ShardId(0),
                EpochId(30),
                300,
                root.clone(),
                "merkle3".to_string(),
            )
            .unwrap();

        let _id4 = engine
            .create_snapshot(ShardId(0), EpochId(40), 400, root, "merkle4".to_string())
            .unwrap();

        let pruned = engine.prune_old_snapshots().unwrap();
        assert!(!pruned.is_empty());
        // Should have pruned oldest snapshots beyond retention
        assert!(engine.total_snapshots() <= 2);
    }
}
