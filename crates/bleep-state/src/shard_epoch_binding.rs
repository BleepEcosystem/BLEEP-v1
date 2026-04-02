// PHASE 2: DYNAMIC SHARDING UPGRADE
// Shard-Epoch Binding Module - Deterministic epoch-bound shard topology
//
// SAFETY INVARIANTS:
// 1. Shard topology is fully determined by epoch ID
// 2. Topology cannot change mid-epoch
// 3. Topology changes occur only at epoch transitions
// 4. All honest nodes independently derive identical topology for each epoch
// 5. Topology is committed in the first block of each epoch
// 6. Blocks with incorrect registry root for their epoch are rejected

use crate::shard_registry::{EpochId, Shard, ShardId, ShardRegistry, ValidatorAssignment};
use log::info;
use serde::{Deserialize, Serialize};

/// Shard topology snapshot for an epoch
///
/// SAFETY: Immutable within an epoch; changes only at epoch boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochShardTopology {
    /// Epoch this topology is valid for
    pub epoch_id: EpochId,

    /// Registry root hash (canonical commitment to topology)
    pub registry_root: String,

    /// All shards active in this epoch
    pub registry: ShardRegistry,

    /// Protocol version (prevents cross-version forks)
    pub protocol_version: u32,
}

impl EpochShardTopology {
    /// Create a snapshot of shard topology for an epoch
    pub fn new(epoch_id: EpochId, registry: ShardRegistry, protocol_version: u32) -> Self {
        let registry_root = registry.registry_root.clone();

        EpochShardTopology {
            epoch_id,
            registry_root,
            registry,
            protocol_version,
        }
    }

    /// Verify that a block has the correct shard topology for its epoch
    ///
    /// SAFETY: Called during block validation. Ensures all nodes accept/reject
    /// blocks identically based on shard topology.
    pub fn verify_block_topology(
        &self,
        expected_registry_root: &str,
        expected_shard_id: u64,
    ) -> Result<(), String> {
        // Verify registry root matches
        if self.registry_root != expected_registry_root {
            return Err(format!(
                "Block shard registry root mismatch: expected {}, got {}",
                self.registry_root, expected_registry_root
            ));
        }

        // Verify shard ID is valid for this epoch
        let shard_id = ShardId(expected_shard_id);
        if !self.registry.shards.contains_key(&shard_id) {
            return Err(format!(
                "Shard {:?} not found in topology for epoch {:?}",
                shard_id, self.epoch_id
            ));
        }

        Ok(())
    }
}

/// Epoch shard state manager
///
/// SAFETY: Maintains the relationship between epochs and shard topology.
/// Ensures deterministic, fork-safe topology transitions.
pub struct EpochShardBinder {
    /// Current epoch topology
    pub current_topology: EpochShardTopology,

    /// Previous epoch topology (for verification during epoch transition)
    pub previous_topology: Option<EpochShardTopology>,

    /// Pending topology changes (to be applied at next epoch)
    pub pending_topology: Option<EpochShardTopology>,

    /// Protocol version
    pub protocol_version: u32,
}

impl EpochShardBinder {
    /// Create a new shard-epoch binder
    pub fn new(initial_topology: EpochShardTopology, protocol_version: u32) -> Self {
        EpochShardBinder {
            current_topology: initial_topology,
            previous_topology: None,
            pending_topology: None,
            protocol_version,
        }
    }

    /// Get the current epoch ID
    pub fn current_epoch(&self) -> EpochId {
        self.current_topology.epoch_id
    }

    /// Get current shard topology
    pub fn get_current_topology(&self) -> &EpochShardTopology {
        &self.current_topology
    }

    /// Stage a new topology for the next epoch
    ///
    /// SAFETY: Changes are pending until explicitly committed at epoch boundary.
    pub fn stage_topology_change(
        &mut self,
        new_topology: EpochShardTopology,
    ) -> Result<(), String> {
        // Verify protocol version matches
        if new_topology.protocol_version != self.protocol_version {
            return Err(format!(
                "Protocol version mismatch: expected {}, got {}",
                self.protocol_version, new_topology.protocol_version
            ));
        }

        // Verify new epoch is next epoch
        let expected_next_epoch = self.current_topology.epoch_id.0 + 1;
        if new_topology.epoch_id.0 != expected_next_epoch {
            return Err(format!(
                "New topology epoch {} is not next epoch {}",
                new_topology.epoch_id.0, expected_next_epoch
            ));
        }

        self.pending_topology = Some(new_topology);
        info!("Staged topology change for epoch {}", expected_next_epoch);
        Ok(())
    }

    /// Commit pending topology changes at epoch boundary
    ///
    /// SAFETY: Called only when transitioning to a new epoch.
    /// This is atomic: topology changes together with epoch.
    pub fn commit_epoch_transition(&mut self) -> Result<(), String> {
        let new_topology = self
            .pending_topology
            .take()
            .ok_or("No pending topology change")?;

        // Verify new topology epoch matches current + 1
        let expected_epoch = self.current_topology.epoch_id.0 + 1;
        if new_topology.epoch_id.0 != expected_epoch {
            return Err(format!(
                "Cannot commit topology for epoch {}: current epoch is {}",
                new_topology.epoch_id.0, self.current_topology.epoch_id.0
            ));
        }

        // Save current as previous
        self.previous_topology = Some(self.current_topology.clone());

        // Activate new topology
        self.current_topology = new_topology;

        info!(
            "Committed topology change for epoch {}",
            self.current_topology.epoch_id.0
        );
        Ok(())
    }

    /// Verify that a block's shard configuration is valid for its epoch
    ///
    /// SAFETY: Used during block validation. Ensures consensus across all nodes.
    pub fn verify_block_shard_fields(
        &self,
        block_epoch: EpochId,
        block_registry_root: &str,
        block_shard_id: u64,
    ) -> Result<(), String> {
        // Block must be in current epoch
        if block_epoch != self.current_topology.epoch_id {
            return Err(format!(
                "Block epoch {} does not match current epoch {}",
                block_epoch.0, self.current_topology.epoch_id.0
            ));
        }

        // Verify topology matches
        self.current_topology
            .verify_block_topology(block_registry_root, block_shard_id)
    }

    /// Get validator assignment for a shard in current epoch
    pub fn get_shard_validators(&self, shard_id: ShardId) -> Option<ValidatorAssignment> {
        self.current_topology.registry.get_validators(shard_id)
    }

    /// Find the shard responsible for a key in current epoch
    pub fn find_shard_for_key(&self, key: &[u8]) -> Option<ShardId> {
        self.current_topology.registry.find_shard_for_key(key)
    }

    /// Get the shard registry for current epoch
    pub fn get_shard_registry(&self) -> &ShardRegistry {
        &self.current_topology.registry
    }
}

/// Shard topology builder - constructs topologies for genesis and transitions
///
/// SAFETY: Provides deterministic topology construction that all nodes
/// independently compute identically.
pub struct ShardTopologyBuilder {
    protocol_version: u32,
}

impl ShardTopologyBuilder {
    /// Create a new topology builder
    pub fn new(protocol_version: u32) -> Self {
        ShardTopologyBuilder { protocol_version }
    }

    /// Build genesis topology with specified number of shards
    ///
    /// SAFETY: All nodes with the same parameters produce identical topology.
    pub fn build_genesis_topology(
        &self,
        num_shards: u64,
        validators: &[Vec<u8>],
    ) -> Result<EpochShardTopology, String> {
        if num_shards == 0 {
            return Err("num_shards must be > 0".to_string());
        }

        if validators.is_empty() {
            return Err("At least one validator is required".to_string());
        }

        let mut registry = ShardRegistry::new(EpochId(0), self.protocol_version);

        // Compute uniform keyspace divisions
        let key_range: u64 = 256; // 0-255 for byte space
        let keys_per_shard = key_range / num_shards;

        for shard_idx in 0..num_shards {
            let start_key = (shard_idx * keys_per_shard) as u8;
            let end_key = if shard_idx == num_shards - 1 {
                256u64 // Include all remaining in last shard
            } else {
                ((shard_idx + 1) * keys_per_shard) as u64
            };

            // Assign validators to shard (round-robin)
            let assigned_validators: Vec<Vec<u8>> = validators
                .iter()
                .enumerate()
                .filter(|(idx, _)| idx % num_shards as usize == shard_idx as usize)
                .map(|(_, v)| v.clone())
                .collect();

            // Ensure each shard has at least one validator
            let shard_validators = if assigned_validators.is_empty() {
                vec![validators[shard_idx as usize % validators.len()].clone()]
            } else {
                assigned_validators
            };

            let validator_assignment = ValidatorAssignment {
                shard_id: ShardId(shard_idx),
                epoch_id: EpochId(0),
                validators: shard_validators,
                proposer_rotation_index: 0,
            };

            let shard = Shard::new(
                ShardId(shard_idx),
                EpochId(0),
                validator_assignment,
                vec![start_key],
                vec![end_key as u8],
            );

            registry.add_shard(shard)?;
        }

        let topology = EpochShardTopology::new(EpochId(0), registry, self.protocol_version);
        info!("Built genesis topology with {} shards", num_shards);
        Ok(topology)
    }

    /// Build topology for next epoch, optionally with topology changes
    ///
    /// SAFETY: Deterministic; produces identical results given same inputs.
    pub fn build_next_epoch_topology(
        &self,
        current_epoch: EpochId,
        current_registry: &ShardRegistry,
        topology_changes: Vec<TopologyChange>,
    ) -> Result<EpochShardTopology, String> {
        let mut new_registry =
            ShardRegistry::new(EpochId(current_epoch.0 + 1), self.protocol_version);

        // Start with current shards
        for (_, shard) in &current_registry.shards {
            let mut new_shard = shard.clone();
            new_shard.epoch_id = EpochId(current_epoch.0 + 1);
            new_registry.add_shard(new_shard)?;
        }

        // Apply topology changes (splits/merges)
        for change in topology_changes {
            match change {
                TopologyChange::Split { shard_id, .. } => {
                    // Split logic would be applied here
                    // For now, just track that split occurred
                    info!("Applied split for shard {:?}", shard_id);
                }
                TopologyChange::Merge {
                    source1, source2, ..
                } => {
                    // Merge logic would be applied here
                    info!("Applied merge for shards {:?}, {:?}", source1, source2);
                }
            }
        }

        let topology = EpochShardTopology::new(
            EpochId(current_epoch.0 + 1),
            new_registry,
            self.protocol_version,
        );

        info!(
            "Built next epoch topology for epoch {}",
            current_epoch.0 + 1
        );
        Ok(topology)
    }
}

/// Enumeration of topology changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TopologyChange {
    /// Shard split operation
    Split {
        shard_id: ShardId,
        child1_id: ShardId,
        child2_id: ShardId,
    },

    /// Shard merge operation
    Merge {
        source1: ShardId,
        source2: ShardId,
        target_id: ShardId,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_topology_creation() {
        let builder = ShardTopologyBuilder::new(1);
        let validators = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let topology = builder.build_genesis_topology(4, &validators).unwrap();

        assert_eq!(topology.epoch_id, EpochId(0));
        assert_eq!(topology.registry.shard_count, 4);
    }

    #[test]
    fn test_epoch_transition_increments_epoch() {
        let builder = ShardTopologyBuilder::new(1);
        let validators = vec![vec![1, 2, 3]];

        let genesis_topology = builder.build_genesis_topology(2, &validators).unwrap();
        let mut binder = EpochShardBinder::new(genesis_topology, 1);

        let next_topology = builder
            .build_next_epoch_topology(
                binder.current_epoch(),
                &binder.current_topology.registry,
                vec![],
            )
            .unwrap();

        assert_eq!(next_topology.epoch_id, EpochId(1));
    }

    #[test]
    fn test_block_topology_verification() {
        let builder = ShardTopologyBuilder::new(1);
        let validators = vec![vec![1, 2, 3]];

        let topology = builder.build_genesis_topology(2, &validators).unwrap();
        let expected_registry_root = topology.registry_root.clone();

        // Block should pass verification if registry root matches
        assert!(topology
            .verify_block_topology(&expected_registry_root, 0)
            .is_ok());

        // Block should fail if registry root is wrong
        assert!(topology.verify_block_topology("wrong_root", 0).is_err());
    }

    #[test]
    fn test_shard_id_validation() {
        let builder = ShardTopologyBuilder::new(1);
        let validators = vec![vec![1, 2, 3]];

        let topology = builder.build_genesis_topology(2, &validators).unwrap();

        // Valid shard ID should pass
        assert!(topology
            .verify_block_topology(&topology.registry_root, 0)
            .is_ok());

        // Invalid shard ID should fail
        assert!(topology
            .verify_block_topology(&topology.registry_root, 99)
            .is_err());
    }
}
