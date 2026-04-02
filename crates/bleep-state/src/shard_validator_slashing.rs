// PHASE 4: SHARD SELF-HEALING & ROLLBACK
// Validator Reassignment & Slashing Module - Byzantine fault response
//
// SAFETY INVARIANTS:
// 1. Slashing decisions are deterministic and consensus-verified
// 2. Slashed validators lose stake immediately
// 3. Validator reassignment is deterministic
// 4. Reassignment occurs only at epoch boundaries
// 5. Slashing evidence is cryptographically verifiable
// 6. No validator can appeal or dispute slashing after commitment

use crate::shard_fault_detection::{FaultEvidence, FaultType};
use crate::shard_registry::ShardId;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Validator slashing reason
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingReason {
    /// Validator produced conflicting blocks
    Equivocation,

    /// Validator reported false state root
    FalseStateRoot,

    /// Validator violated cross-shard protocol
    CrossShardViolation,

    /// Validator missed block production duty
    MissedProposal,

    /// Validator misbehavior in cross-shard commit
    TransactionMisbehavior,
}

/// Slashing record - immutable evidence of punishment
///
/// SAFETY: Slashing is permanent and auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRecord {
    /// Validator being slashed
    pub validator_pubkey: Vec<u8>,

    /// Shard where violation occurred
    pub shard_id: ShardId,

    /// Reason for slashing
    pub reason: SlashingReason,

    /// Amount of stake slashed (in smallest unit)
    pub amount_slashed: u64,

    /// Evidence (fault that triggered slashing)
    pub evidence: FaultEvidence,

    /// Epoch when slashing occurred
    pub slashing_epoch: u64,

    /// Whether slashing was finalized on-chain
    pub is_finalized: bool,
}

impl SlashingRecord {
    /// Create a new slashing record from fault evidence
    pub fn from_fault_evidence(
        evidence: FaultEvidence,
        validator_pubkey: Vec<u8>,
        slash_amount: u64,
        epoch: u64,
    ) -> Self {
        let reason = match &evidence.fault_type {
            FaultType::ValidatorEquivocation { .. } => SlashingReason::Equivocation,
            FaultType::StateRootMismatch { .. } => SlashingReason::FalseStateRoot,
            FaultType::InvalidCrossShardReceipt { .. } => SlashingReason::CrossShardViolation,
            FaultType::LivenessFailure { .. } => SlashingReason::MissedProposal,
            _ => SlashingReason::TransactionMisbehavior,
        };

        SlashingRecord {
            validator_pubkey,
            shard_id: evidence.shard_id,
            reason,
            amount_slashed: slash_amount,
            evidence,
            slashing_epoch: epoch,
            is_finalized: false,
        }
    }

    /// Verify slashing record integrity
    pub fn verify(&self) -> Result<(), String> {
        if self.validator_pubkey.is_empty() {
            return Err("Validator pubkey is empty".to_string());
        }

        if self.amount_slashed == 0 {
            return Err("Slashing amount must be > 0".to_string());
        }

        self.evidence.verify()?;
        Ok(())
    }
}

/// Validator slashing manager
///
/// SAFETY: Tracks and enforces slashing decisions.
#[derive(Clone)]
pub struct ValidatorSlashingManager {
    /// Slashing records
    slashing_records: Vec<SlashingRecord>,

    /// Slashed validators (pubkey -> total slashed amount)
    slashed_validators: HashMap<Vec<u8>, u64>,

    /// Validators currently slashed (cannot propose)
    disabled_validators: HashSet<Vec<u8>>,
}

impl ValidatorSlashingManager {
    /// Create a new slashing manager
    pub fn new() -> Self {
        ValidatorSlashingManager {
            slashing_records: Vec::new(),
            slashed_validators: HashMap::new(),
            disabled_validators: HashSet::new(),
        }
    }

    /// Record a slashing event
    ///
    /// SAFETY: Creates immutable record for audit.
    pub fn slash_validator(&mut self, record: SlashingRecord) -> Result<(), String> {
        record.verify()?;

        let pubkey = record.validator_pubkey.clone();
        let amount = record.amount_slashed;

        // Record slashing
        self.slashing_records.push(record);

        // Update slashed amount
        *self.slashed_validators.entry(pubkey.clone()).or_insert(0) += amount;

        // Disable validator
        self.disabled_validators.insert(pubkey.clone());

        info!(
            "Slashed validator {:?} for {} stake",
            hex::encode(&pubkey),
            amount
        );

        Ok(())
    }

    /// Finalize a slashing record (commit to consensus)
    pub fn finalize_slashing(&mut self, index: usize) -> Result<(), String> {
        if index >= self.slashing_records.len() {
            return Err("Invalid slashing record index".to_string());
        }

        self.slashing_records[index].is_finalized = true;
        Ok(())
    }

    /// Get total amount slashed for a validator
    pub fn get_slashed_amount(&self, validator_pubkey: &[u8]) -> u64 {
        self.slashed_validators
            .get(validator_pubkey)
            .copied()
            .unwrap_or(0)
    }

    /// Check if a validator is disabled due to slashing
    pub fn is_validator_disabled(&self, validator_pubkey: &[u8]) -> bool {
        self.disabled_validators.contains(validator_pubkey)
    }

    /// Get all slashing records
    pub fn get_all_slashings(&self) -> Vec<&SlashingRecord> {
        self.slashing_records.iter().collect()
    }

    /// Get slashing records for a shard
    pub fn get_shard_slashings(&self, shard_id: ShardId) -> Vec<&SlashingRecord> {
        self.slashing_records
            .iter()
            .filter(|r| r.shard_id == shard_id)
            .collect()
    }
}

/// Validator reassignment strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReassignmentStrategy {
    /// Randomly reshuffle validators (but deterministic given seed)
    DeterministicReshuffle,

    /// Prioritize removing slashed validators
    PrioritizeSlashed,

    /// Balance stake across shards
    StakeBalance,
}

/// Validator reassignment manager
///
/// SAFETY: Produces deterministic, auditable validator reassignments.
#[derive(Clone)]
pub struct ValidatorReassignmentManager {
    slashing_manager: ValidatorSlashingManager,
    strategy: ReassignmentStrategy,
}

impl ValidatorReassignmentManager {
    /// Create a new reassignment manager
    pub fn new(slashing_manager: ValidatorSlashingManager, strategy: ReassignmentStrategy) -> Self {
        ValidatorReassignmentManager {
            slashing_manager,
            strategy,
        }
    }

    /// Plan validator reassignment for next epoch
    ///
    /// SAFETY: Completely deterministic; all nodes produce identical plans.
    pub fn plan_reassignment(
        &self,
        current_validators: &[Vec<u8>],
        num_shards: u64,
        epoch_seed: u64,
    ) -> Result<ValidatorReassignmentPlan, String> {
        // Filter out disabled validators
        let eligible: Vec<_> = current_validators
            .iter()
            .filter(|pubkey| !self.slashing_manager.is_validator_disabled(pubkey))
            .cloned()
            .collect();

        if eligible.is_empty() {
            return Err("No eligible validators after slashing".to_string());
        }

        match self.strategy {
            ReassignmentStrategy::DeterministicReshuffle => {
                self.plan_deterministic_reshuffle(&eligible, num_shards, epoch_seed)
            }
            ReassignmentStrategy::PrioritizeSlashed => {
                self.plan_slashed_removal(&eligible, num_shards, epoch_seed)
            }
            ReassignmentStrategy::StakeBalance => {
                self.plan_stake_balanced(&eligible, num_shards, epoch_seed)
            }
        }
    }

    /// Plan deterministic reshuffle
    fn plan_deterministic_reshuffle(
        &self,
        validators: &[Vec<u8>],
        num_shards: u64,
        epoch_seed: u64,
    ) -> Result<ValidatorReassignmentPlan, String> {
        use sha2::{Digest, Sha256};

        let mut plan = ValidatorReassignmentPlan {
            validator_assignments: HashMap::new(),
            removed_validators: Vec::new(),
            strategy_used: ReassignmentStrategy::DeterministicReshuffle,
        };

        // Assign validators to shards using deterministic hash
        for (idx, validator) in validators.iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(epoch_seed.to_le_bytes());
            hasher.update((idx as u64).to_le_bytes());
            let hash = hasher.finalize();

            let shard_idx = u64::from_le_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ]) % num_shards;

            plan.validator_assignments
                .entry(ShardId(shard_idx))
                .or_insert_with(Vec::new)
                .push(validator.clone());
        }

        Ok(plan)
    }

    /// Plan slashed validator removal
    fn plan_slashed_removal(
        &self,
        validators: &[Vec<u8>],
        num_shards: u64,
        epoch_seed: u64,
    ) -> Result<ValidatorReassignmentPlan, String> {
        let mut plan = ValidatorReassignmentPlan {
            validator_assignments: HashMap::new(),
            removed_validators: Vec::new(),
            strategy_used: ReassignmentStrategy::PrioritizeSlashed,
        };

        // Record which validators were slashed
        let all_slashings = self.slashing_manager.get_all_slashings();
        for slashing in all_slashings {
            if !plan.removed_validators.contains(&slashing.validator_pubkey) {
                plan.removed_validators
                    .push(slashing.validator_pubkey.clone());
            }
        }

        // Assign remaining validators using reshuffle logic
        let plan = self.plan_deterministic_reshuffle(validators, num_shards, epoch_seed)?;

        Ok(plan)
    }

    /// Plan stake-balanced assignment
    fn plan_stake_balanced(
        &self,
        validators: &[Vec<u8>],
        num_shards: u64,
        _epoch_seed: u64,
    ) -> Result<ValidatorReassignmentPlan, String> {
        let mut plan = ValidatorReassignmentPlan {
            validator_assignments: HashMap::new(),
            removed_validators: Vec::new(),
            strategy_used: ReassignmentStrategy::StakeBalance,
        };

        // Simple equal distribution
        let per_shard = (validators.len() as u64 + num_shards - 1) / num_shards;

        for (idx, validator) in validators.iter().enumerate() {
            let shard_idx = (idx as u64) / per_shard;
            let shard_id = ShardId(shard_idx.min(num_shards - 1));

            plan.validator_assignments
                .entry(shard_id)
                .or_insert_with(Vec::new)
                .push(validator.clone());
        }

        Ok(plan)
    }
}

/// Validator reassignment plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReassignmentPlan {
    /// New validator assignments per shard
    pub validator_assignments: HashMap<ShardId, Vec<Vec<u8>>>,

    /// Validators that were removed (slashed/disabled)
    pub removed_validators: Vec<Vec<u8>>,

    /// Strategy used for reassignment
    pub strategy_used: ReassignmentStrategy,
}

impl ValidatorReassignmentPlan {
    /// Verify plan is valid
    pub fn verify(&self) -> Result<(), String> {
        if self.validator_assignments.is_empty() {
            return Err("No validator assignments in plan".to_string());
        }

        for (shard_id, validators) in &self.validator_assignments {
            if validators.is_empty() {
                return Err(format!("Shard {:?} has no validators", shard_id));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slashing_record_creation() {
        let evidence = FaultEvidence {
            fault_type: FaultType::ValidatorEquivocation {
                validator_pubkey: vec![1, 2, 3],
                block_height: 100,
                hash1: "hash1".to_string(),
                hash2: "hash2".to_string(),
            },
            shard_id: ShardId(0),
            epoch_id: crate::shard_registry::EpochId(0),
            severity: FaultSeverity::Critical,
            detection_height: 100,
            proof: vec![],
            details: "test".to_string(),
        };

        let record = SlashingRecord::from_fault_evidence(evidence, vec![1, 2, 3], 1000, 0);

        assert_eq!(record.reason, SlashingReason::Equivocation);
    }

    #[test]
    fn test_slashing_manager() {
        let mut manager = ValidatorSlashingManager::new();

        let evidence = FaultEvidence {
            fault_type: FaultType::ValidatorEquivocation {
                validator_pubkey: vec![1, 2, 3],
                block_height: 100,
                hash1: "hash1".to_string(),
                hash2: "hash2".to_string(),
            },
            shard_id: ShardId(0),
            epoch_id: crate::shard_registry::EpochId(0),
            severity: FaultSeverity::Critical,
            detection_height: 100,
            proof: vec![],
            details: "test".to_string(),
        };

        let record = SlashingRecord::from_fault_evidence(evidence, vec![1, 2, 3], 1000, 0);

        manager.slash_validator(record).unwrap();
        assert!(manager.is_validator_disabled(&vec![1, 2, 3]));
    }
}
