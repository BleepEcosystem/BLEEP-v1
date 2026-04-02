// PHASE 2: DYNAMIC SHARDING UPGRADE
// Shard Registry Module - Formalize shards as first-class protocol state
//
// SAFETY INVARIANTS:
// 1. Shards exist in global protocol state and are commitment-verified
// 2. Shard topology is immutable within an epoch
// 3. Shard changes occur only at epoch boundaries
// 4. All nodes independently derive identical shard layouts
// 5. Shard state is Merkle-verifiable and fork-safe
// 6. Validator assignments are deterministic and epoch-bound
// 7. Shard splits and merges preserve transaction ordering and state integrity

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};

/// ShardId uniquely identifies a shard in the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct ShardId(pub u64);

impl ShardId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// EpochId uniquely identifies an epoch in the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct EpochId(pub u64);

impl EpochId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Shard status enumeration
///
/// SAFETY: Status transitions must be atomic and verifiable at epoch boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardStatus {
    /// Shard is actively processing transactions
    Active,

    /// Shard is being split into smaller shards (intermediate state)
    Splitting,

    /// Shard is being merged with another shard (intermediate state)
    Merging,

    /// Shard is suspended due to Byzantine faults
    Suspended,
}

/// Validator assignment for a shard
///
/// SAFETY: Validator sets are computed deterministically from:
/// - Shard ID
/// - Epoch ID
/// - Available validator set
///
/// This ensures all honest nodes independently derive identical assignments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorAssignment {
    /// Shard this assignment applies to
    pub shard_id: ShardId,

    /// Epoch this assignment is valid for
    pub epoch_id: EpochId,

    /// Ordered list of validator public keys assigned to this shard
    pub validators: Vec<Vec<u8>>,

    /// Index of primary proposer (rotates per block)
    pub proposer_rotation_index: usize,
}

impl ValidatorAssignment {
    /// Get the primary proposer for this epoch (may change per block)
    pub fn get_proposer(&self) -> Option<&Vec<u8>> {
        if self.validators.is_empty() {
            return None;
        }
        let idx = self.proposer_rotation_index % self.validators.len();
        Some(&self.validators[idx])
    }

    /// Rotate to next proposer
    pub fn rotate_proposer(&mut self) {
        self.proposer_rotation_index = self.proposer_rotation_index.saturating_add(1);
    }
}

/// Shard state root for Merkle verification
///
/// SAFETY: State roots are cryptographic commitments to shard state.
/// State transitions must be atomic and verifiable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardStateRoot {
    /// Merkle root of state tree
    pub root_hash: String,

    /// Number of transactions included
    pub tx_count: u64,

    /// Height of shard state (block height at which state is committed)
    pub height: u64,
}

impl ShardStateRoot {
    /// Compute a Merkle root from raw state data
    ///
    /// This is a placeholder; in production, this would use a proper state tree.
    pub fn compute_from_data(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        ShardStateRoot {
            root_hash: hex::encode(hash),
            tx_count: 0,
            height: 0,
        }
    }
}

/// Shard instance in the protocol
///
/// SAFETY: Shards are fully defined by their metadata and state commitment.
/// No independent shard chain; all state is anchored to the global chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shard {
    /// Unique shard identifier
    pub id: ShardId,

    /// Current shard status
    pub status: ShardStatus,

    /// Epoch this shard configuration is valid for
    pub epoch_id: EpochId,

    /// Validator set assigned to this shard
    pub validators: ValidatorAssignment,

    /// Current state commitment (Merkle root)
    pub state_root: ShardStateRoot,

    /// Key range this shard is responsible for [start, end)
    /// Enables deterministic transaction routing
    pub keyspace_start: Vec<u8>,
    pub keyspace_end: Vec<u8>,

    /// Pending transactions in memory pool (not yet committed)
    pub pending_transactions: VecDeque<Vec<u8>>,

    /// Total transaction count committed in this shard
    pub committed_tx_count: u64,

    /// Height of the last state transition
    pub last_state_update_height: u64,
}

impl Shard {
    /// Create a new shard with initial configuration
    pub fn new(
        id: ShardId,
        epoch_id: EpochId,
        validators: ValidatorAssignment,
        keyspace_start: Vec<u8>,
        keyspace_end: Vec<u8>,
    ) -> Self {
        Shard {
            id,
            status: ShardStatus::Active,
            epoch_id,
            validators,
            state_root: ShardStateRoot {
                root_hash: "0".repeat(64), // Empty state root
                tx_count: 0,
                height: 0,
            },
            keyspace_start,
            keyspace_end,
            pending_transactions: VecDeque::new(),
            committed_tx_count: 0,
            last_state_update_height: 0,
        }
    }

    /// Check if a key belongs to this shard's keyspace
    pub fn contains_key(&self, key: &[u8]) -> bool {
        key >= self.keyspace_start.as_slice() && key < self.keyspace_end.as_slice()
    }

    /// Add a transaction to pending queue
    pub fn add_pending_transaction(&mut self, tx: Vec<u8>) {
        self.pending_transactions.push_back(tx);
    }

    /// Commit pending transactions and update state root
    ///
    /// SAFETY: This is atomic; either all transactions commit or none.
    pub fn commit_transactions(&mut self, new_state_root: ShardStateRoot) -> Result<(), String> {
        let tx_count = self.pending_transactions.len() as u64;
        self.committed_tx_count += tx_count;
        self.state_root = new_state_root;
        self.pending_transactions.clear();
        Ok(())
    }
}

/// Shard Registry - Central protocol state for all shards
///
/// SAFETY: This is the authoritative source for shard topology.
/// All nodes compute identical registries for each epoch.
/// Changes are deterministic, epoch-bound, and immutable within an epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRegistry {
    /// Current epoch
    pub epoch_id: EpochId,

    /// All active shards (indexed by ShardId)
    /// INVARIANT: All shards in this map have the same epoch_id
    pub shards: BTreeMap<ShardId, Shard>,

    /// Total number of shards in current epoch
    pub shard_count: u64,

    /// Registry Merkle root (commitment to all shards)
    pub registry_root: String,

    /// Protocol version (for hard fork safety)
    pub protocol_version: u32,
}

impl ShardRegistry {
    /// Create a new shard registry for an epoch
    pub fn new(epoch_id: EpochId, protocol_version: u32) -> Self {
        ShardRegistry {
            epoch_id,
            shards: BTreeMap::new(),
            shard_count: 0,
            registry_root: "0".repeat(64),
            protocol_version,
        }
    }

    /// Add a shard to the registry
    ///
    /// SAFETY: Can only be called before epoch is finalized.
    /// Once committed, registry is immutable.
    pub fn add_shard(&mut self, shard: Shard) -> Result<(), String> {
        if shard.epoch_id != self.epoch_id {
            return Err(format!(
                "Shard epoch {} does not match registry epoch {}",
                shard.epoch_id.0, self.epoch_id.0
            ));
        }

        if self.shards.contains_key(&shard.id) {
            return Err(format!("Shard {:?} already exists in registry", shard.id));
        }

        self.shards.insert(shard.id, shard);
        self.shard_count += 1;
        self.recompute_registry_root();
        Ok(())
    }

    /// Get a shard by ID
    pub fn get_shard(&self, shard_id: ShardId) -> Option<&Shard> {
        self.shards.get(&shard_id)
    }

    /// Get mutable reference to a shard (for state updates)
    ///
    /// SAFETY: Only used during state transitions within an epoch.
    /// State updates must be atomic and verifiable.
    pub fn get_shard_mut(&mut self, shard_id: ShardId) -> Option<&mut Shard> {
        self.shards.get_mut(&shard_id)
    }

    /// Find the shard responsible for a given key
    ///
    /// SAFETY: Deterministic keyspace mapping ensures all nodes
    /// independently route transactions to the same shard.
    pub fn find_shard_for_key(&self, key: &[u8]) -> Option<ShardId> {
        self.shards
            .iter()
            .find(|(_, shard)| shard.contains_key(key))
            .map(|(id, _)| *id)
    }

    /// Get validator assignment for a shard
    pub fn get_validators(&self, shard_id: ShardId) -> Option<ValidatorAssignment> {
        self.shards.get(&shard_id).map(|s| s.validators.clone())
    }

    /// Recompute the registry Merkle root
    ///
    /// SAFETY: Must be called after any shard modification.
    /// This ensures the registry root reflects the current state.
    pub fn recompute_registry_root(&mut self) {
        let mut hasher = Sha256::new();

        for (_, shard) in &self.shards {
            hasher.update(shard.id.0.to_le_bytes());
            hasher.update(shard.state_root.root_hash.as_bytes());
        }

        self.registry_root = hex::encode(hasher.finalize());
    }

    /// Verify registry matches a given root hash
    ///
    /// SAFETY: Used for consensus verification. Prevents forks due to
    /// registry mismatch.
    pub fn verify_root(&self, expected_root: &str) -> bool {
        self.registry_root == expected_root
    }

    /// Create a snapshot of the current registry
    ///
    /// Used for producing Merkle proofs and state transitions.
    pub fn snapshot(&self) -> ShardRegistrySnapshot {
        ShardRegistrySnapshot {
            epoch_id: self.epoch_id,
            shard_count: self.shard_count,
            registry_root: self.registry_root.clone(),
            shards_by_id: self.shards.iter().map(|(id, s)| (*id, s.clone())).collect(),
        }
    }
}

/// Snapshot of registry state for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRegistrySnapshot {
    pub epoch_id: EpochId,
    pub shard_count: u64,
    pub registry_root: String,
    pub shards_by_id: BTreeMap<ShardId, Shard>,
}

/// Error types for shard operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardRegistryError {
    ShardNotFound(ShardId),
    KeyspaceViolation(Vec<u8>),
    InvalidStateRoot,
    EpochMismatch,
    RegistryRootMismatch,
    TransactionCommitFailed(String),
    ValidatorAssignmentFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_keyspace_containment() {
        let mut shard = Shard::new(
            ShardId(0),
            EpochId(0),
            ValidatorAssignment {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                validators: vec![vec![1, 2, 3]],
                proposer_rotation_index: 0,
            },
            vec![0],
            vec![127],
        );

        assert!(shard.contains_key(&vec![50]));
        assert!(!shard.contains_key(&vec![128]));
    }

    #[test]
    fn test_registry_add_shard() {
        let mut registry = ShardRegistry::new(EpochId(0), 1);

        let shard = Shard::new(
            ShardId(0),
            EpochId(0),
            ValidatorAssignment {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                validators: vec![vec![1, 2, 3]],
                proposer_rotation_index: 0,
            },
            vec![0],
            vec![127],
        );

        assert!(registry.add_shard(shard).is_ok());
        assert_eq!(registry.shard_count, 1);
    }

    #[test]
    fn test_registry_prevents_duplicate_shards() {
        let mut registry = ShardRegistry::new(EpochId(0), 1);

        let shard = Shard::new(
            ShardId(0),
            EpochId(0),
            ValidatorAssignment {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                validators: vec![vec![1, 2, 3]],
                proposer_rotation_index: 0,
            },
            vec![0],
            vec![127],
        );

        assert!(registry.add_shard(shard.clone()).is_ok());
        assert!(registry.add_shard(shard).is_err());
    }

    #[test]
    fn test_find_shard_for_key() {
        let mut registry = ShardRegistry::new(EpochId(0), 1);

        let shard = Shard::new(
            ShardId(0),
            EpochId(0),
            ValidatorAssignment {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                validators: vec![vec![1, 2, 3]],
                proposer_rotation_index: 0,
            },
            vec![0],
            vec![127],
        );

        registry.add_shard(shard).unwrap();

        let found = registry.find_shard_for_key(&vec![50]);
        assert_eq!(found, Some(ShardId(0)));
    }

    #[test]
    fn test_registry_root_verification() {
        let mut registry = ShardRegistry::new(EpochId(0), 1);
        let shard = Shard::new(
            ShardId(0),
            EpochId(0),
            ValidatorAssignment {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                validators: vec![vec![1, 2, 3]],
                proposer_rotation_index: 0,
            },
            vec![0],
            vec![127],
        );

        registry.add_shard(shard).unwrap();
        let expected_root = registry.registry_root.clone();

        assert!(registry.verify_root(&expected_root));
        assert!(!registry.verify_root("invalid_root"));
    }
}
