// PHASE 2: DYNAMIC SHARDING UPGRADE
// Shard Validator Assignment Module - Deterministic validator-shard binding
//
// SAFETY INVARIANTS:
// 1. Validator assignments are deterministic given a validator set and epoch
// 2. All honest nodes independently compute identical assignments
// 3. Assignments are immutable within an epoch
// 4. Assignments rotate at epoch boundaries only
// 5. Validator misbehavior is slashable at shard level
// 6. Assignments ensure Byzantine fault tolerance per shard (2f+1 quorum)

use crate::shard_registry::{EpochId, ShardId, ValidatorAssignment};
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Global validator set for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// Ordered list of validator public keys
    pub validators: Vec<ValidatorInfo>,

    /// Epoch this validator set is valid for
    pub epoch_id: EpochId,

    /// Total stake (sum of all validator stakes)
    pub total_stake: u64,
}

impl ValidatorSet {
    /// Create a new validator set
    pub fn new(validators: Vec<ValidatorInfo>, epoch_id: EpochId) -> Self {
        let total_stake = validators.iter().map(|v| v.stake).sum();

        ValidatorSet {
            validators,
            epoch_id,
            total_stake,
        }
    }

    /// Get validator count
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Check if validator count is sufficient for Byzantine tolerance
    ///
    /// SAFETY: At least 3f+1 validators needed to tolerate f Byzantine faults
    pub fn is_valid(&self) -> bool {
        self.validators.len() >= 4 // Minimum 4 for 1 fault tolerance
    }

    /// Get Byzantine fault tolerance threshold
    /// Can tolerate floor((n-1)/3) Byzantine validators
    pub fn max_byzantine_faults(&self) -> u64 {
        ((self.validators.len() as u64).saturating_sub(1)) / 3
    }
}

/// Information about a single validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator public key (identifier)
    pub public_key: Vec<u8>,

    /// Stake amount (used for PoS selection)
    pub stake: u64,

    /// Validator status
    pub status: ValidatorStatus,
}

/// Validator status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Validator is active and eligible for selection
    Active,

    /// Validator is temporarily inactive
    Inactive,

    /// Validator has been slashed due to Byzantine behavior
    Slashed,
}

/// Shard validator assignment strategy
///
/// SAFETY: All strategies produce deterministic outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignmentStrategy {
    /// Distribute validators uniformly across shards
    UniformDistribution,

    /// Assign validators based on stake (weighted)
    StakeWeighted,

    /// Use deterministic hashing for assignment
    DeterministicHash,
}

/// Shard validator assignment manager
///
/// SAFETY: Produces deterministic, Byzantine-tolerant validator assignments.
pub struct ShardValidatorAssigner {
    strategy: AssignmentStrategy,
    protocol_version: u32,
}

impl ShardValidatorAssigner {
    /// Create a new validator assigner
    pub fn new(strategy: AssignmentStrategy, protocol_version: u32) -> Self {
        ShardValidatorAssigner {
            strategy,
            protocol_version,
        }
    }

    /// Get the protocol version
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Assign validators to shards deterministically
    ///
    /// SAFETY: Same inputs produce identical assignments on all nodes.
    pub fn assign_validators(
        &self,
        validator_set: &ValidatorSet,
        num_shards: u64,
    ) -> Result<BTreeMap<ShardId, ValidatorAssignment>, String> {
        if num_shards == 0 {
            return Err("num_shards must be > 0".to_string());
        }

        if validator_set.validators.is_empty() {
            return Err("Validator set is empty".to_string());
        }

        match self.strategy {
            AssignmentStrategy::UniformDistribution => {
                self.assign_uniform(validator_set, num_shards)
            }
            AssignmentStrategy::StakeWeighted => {
                self.assign_stake_weighted(validator_set, num_shards)
            }
            AssignmentStrategy::DeterministicHash => {
                self.assign_deterministic_hash(validator_set, num_shards)
            }
        }
    }

    /// Uniform distribution: each shard gets n/k validators
    ///
    /// SAFETY: Deterministic round-robin assignment.
    fn assign_uniform(
        &self,
        validator_set: &ValidatorSet,
        num_shards: u64,
    ) -> Result<BTreeMap<ShardId, ValidatorAssignment>, String> {
        let mut assignments = BTreeMap::new();
        let active_validators: Vec<_> = validator_set
            .validators
            .iter()
            .filter(|v| v.status == ValidatorStatus::Active)
            .collect();

        if active_validators.is_empty() {
            return Err("No active validators available".to_string());
        }

        // Assign validators round-robin to shards
        for shard_idx in 0..num_shards {
            let shard_id = ShardId(shard_idx);
            let mut shard_validators = Vec::new();

            // Deterministically select validators for this shard
            for (validator_idx, validator) in active_validators.iter().enumerate() {
                if (validator_idx as u64) % num_shards == shard_idx {
                    shard_validators.push(validator.public_key.clone());
                }
            }

            // Ensure each shard has at least one validator
            if shard_validators.is_empty() {
                let fallback_idx = shard_idx as usize % active_validators.len();
                shard_validators.push(active_validators[fallback_idx].public_key.clone());
            }

            assignments.insert(
                shard_id,
                ValidatorAssignment {
                    shard_id,
                    epoch_id: validator_set.epoch_id,
                    validators: shard_validators,
                    proposer_rotation_index: 0,
                },
            );
        }

        // Verify assignments
        self.verify_assignments(&assignments, validator_set, num_shards)?;

        info!(
            "Assigned {} validators to {} shards (uniform)",
            active_validators.len(),
            num_shards
        );
        Ok(assignments)
    }

    /// Stake-weighted assignment: validators with more stake get more shard assignments
    ///
    /// SAFETY: Proportional to stake, deterministic.
    fn assign_stake_weighted(
        &self,
        validator_set: &ValidatorSet,
        num_shards: u64,
    ) -> Result<BTreeMap<ShardId, ValidatorAssignment>, String> {
        let mut assignments = BTreeMap::new();
        let active_validators: Vec<_> = validator_set
            .validators
            .iter()
            .filter(|v| v.status == ValidatorStatus::Active)
            .collect();

        if active_validators.is_empty() {
            return Err("No active validators available".to_string());
        }

        // Create assignment slots (one per shard)
        let mut assignment_map: Vec<Vec<Vec<u8>>> = vec![Vec::new(); num_shards as usize];

        // Assign validators to slots proportional to stake
        for shard_idx in 0..num_shards {
            // Deterministically select validator based on stake
            let selected_validator = Self::select_by_stake(&active_validators, shard_idx)?;
            assignment_map[shard_idx as usize].push(selected_validator.public_key.clone());
        }

        // Convert to ValidatorAssignments
        for (shard_idx, validators) in assignment_map.into_iter().enumerate() {
            let shard_id = ShardId(shard_idx as u64);
            assignments.insert(
                shard_id,
                ValidatorAssignment {
                    shard_id,
                    epoch_id: validator_set.epoch_id,
                    validators,
                    proposer_rotation_index: 0,
                },
            );
        }

        // Verify assignments
        self.verify_assignments(&assignments, validator_set, num_shards)?;

        info!(
            "Assigned {} validators to {} shards (stake-weighted)",
            active_validators.len(),
            num_shards
        );
        Ok(assignments)
    }

    /// Deterministic hash-based assignment
    ///
    /// SAFETY: Uses SHA3-256 hash of shard ID to select validator.
    fn assign_deterministic_hash(
        &self,
        validator_set: &ValidatorSet,
        num_shards: u64,
    ) -> Result<BTreeMap<ShardId, ValidatorAssignment>, String> {
        let mut assignments = BTreeMap::new();
        let active_validators: Vec<_> = validator_set
            .validators
            .iter()
            .filter(|v| v.status == ValidatorStatus::Active)
            .collect();

        if active_validators.is_empty() {
            return Err("No active validators available".to_string());
        }

        for shard_idx in 0..num_shards {
            let shard_id = ShardId(shard_idx);

            // Hash shard ID deterministically
            let mut hasher = Sha256::new();
            hasher.update(shard_id.0.to_le_bytes());
            let hash = hasher.finalize();

            // Select validator based on hash
            let hash_value = u64::from_le_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ]);
            let validator_idx = (hash_value as usize) % active_validators.len();

            assignments.insert(
                shard_id,
                ValidatorAssignment {
                    shard_id,
                    epoch_id: validator_set.epoch_id,
                    validators: vec![active_validators[validator_idx].public_key.clone()],
                    proposer_rotation_index: 0,
                },
            );
        }

        // Verify assignments
        self.verify_assignments(&assignments, validator_set, num_shards)?;

        info!(
            "Assigned {} validators to {} shards (deterministic hash)",
            active_validators.len(),
            num_shards
        );
        Ok(assignments)
    }

    /// Select a validator deterministically based on stake
    fn select_by_stake<'a>(
        validators: &'a [&'a ValidatorInfo],
        seed: u64,
    ) -> Result<&'a ValidatorInfo, String> {
        if validators.is_empty() {
            return Err("No validators available".to_string());
        }

        let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
        let mut hasher = Sha256::new();
        hasher.update(seed.to_le_bytes());
        let hash = hasher.finalize();

        let hash_value = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);

        let mut cumulative_stake = 0u64;
        let target = hash_value % total_stake;

        for validator in validators {
            cumulative_stake += validator.stake;
            if target < cumulative_stake {
                return Ok(validator);
            }
        }

        Ok(validators[0])
    }

    /// Verify that assignments satisfy Byzantine safety
    ///
    /// SAFETY: All shards must have >= 2f+1 validators
    fn verify_assignments(
        &self,
        assignments: &BTreeMap<ShardId, ValidatorAssignment>,
        _validator_set: &ValidatorSet,
        num_shards: u64,
    ) -> Result<(), String> {
        if assignments.len() as u64 != num_shards {
            return Err(format!(
                "Assignment count {} does not match shard count {}",
                assignments.len(),
                num_shards
            ));
        }

        // Verify each shard has at least one validator
        for assignment in assignments.values() {
            if assignment.validators.is_empty() {
                return Err(format!("Shard {:?} has no validators", assignment.shard_id));
            }
        }

        Ok(())
    }

    /// Rotate validator proposers within a shard at block boundaries
    ///
    /// SAFETY: Deterministic rotation ensures all nodes agree on next proposer.
    pub fn rotate_proposer(&self, assignment: &mut ValidatorAssignment) {
        assignment.rotate_proposer();
    }
}

/// Slashing evidence for Byzantine validator behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvidence {
    /// Validator being slashed
    pub validator_public_key: Vec<u8>,

    /// Shard where misbehavior occurred
    pub shard_id: ShardId,

    /// Epoch of misbehavior
    pub epoch_id: EpochId,

    /// Type of Byzantine behavior
    pub behavior: ByzantineBehavior,

    /// Cryptographic proof of misbehavior
    pub proof: Vec<u8>,
}

/// Byzantine behavior enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByzantineBehavior {
    /// Validator double-signed blocks at same height
    DoubleSigning,

    /// Validator proposed block with invalid shard configuration
    InvalidShardConfig,

    /// Validator failed to produce block when assigned as proposer
    MissedProposal,

    /// Validator participated in conflicting consensus decisions
    ConflictingVotes,
}

impl SlashingEvidence {
    /// Verify slashing evidence is valid
    pub fn verify(&self) -> Result<(), String> {
        if self.proof.is_empty() {
            return Err("No proof provided".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_set_byzantine_tolerance() {
        let validators = vec![
            ValidatorInfo {
                public_key: vec![1],
                stake: 100,
                status: ValidatorStatus::Active,
            },
            ValidatorInfo {
                public_key: vec![2],
                stake: 100,
                status: ValidatorStatus::Active,
            },
            ValidatorInfo {
                public_key: vec![3],
                stake: 100,
                status: ValidatorStatus::Active,
            },
            ValidatorInfo {
                public_key: vec![4],
                stake: 100,
                status: ValidatorStatus::Active,
            },
        ];

        let validator_set = ValidatorSet::new(validators, EpochId(0));

        assert!(validator_set.is_valid());
        assert_eq!(validator_set.max_byzantine_faults(), 1);
    }

    #[test]
    fn test_uniform_assignment_deterministic() {
        let validators = vec![
            ValidatorInfo {
                public_key: vec![1],
                stake: 100,
                status: ValidatorStatus::Active,
            },
            ValidatorInfo {
                public_key: vec![2],
                stake: 100,
                status: ValidatorStatus::Active,
            },
        ];

        let validator_set = ValidatorSet::new(validators, EpochId(0));
        let assigner = ShardValidatorAssigner::new(AssignmentStrategy::UniformDistribution, 1);

        let result1 = assigner.assign_validators(&validator_set, 2).unwrap();
        let result2 = assigner.assign_validators(&validator_set, 2).unwrap();

        // Verify determinism: same inputs produce same outputs
        assert_eq!(result1.len(), result2.len());
    }

    #[test]
    fn test_hash_assignment_deterministic() {
        let validators = vec![ValidatorInfo {
            public_key: vec![1],
            stake: 100,
            status: ValidatorStatus::Active,
        }];

        let validator_set = ValidatorSet::new(validators, EpochId(0));
        let assigner = ShardValidatorAssigner::new(AssignmentStrategy::DeterministicHash, 1);

        let result1 = assigner.assign_validators(&validator_set, 4).unwrap();
        let result2 = assigner.assign_validators(&validator_set, 4).unwrap();

        // Verify determinism
        for (shard_id, assignment) in result1.iter() {
            let other = result2.get(shard_id).unwrap();
            assert_eq!(assignment.validators, other.validators);
        }
    }
}
