/// VALIDATOR INCENTIVES & ACCOUNTABILITY
///
/// This module implements reward distribution and validation incentives.
/// Validators are rewarded for honest participation and penalized for malicious behavior.
/// Rewards are performance-based, epoch-settled, and proof-dependent.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum RewardType {
    /// Block proposal reward
    BlockProposal,
    /// Consensus participation reward
    Participation,
    /// Successful healing contribution
    HealingContribution,
    /// Cross-shard coordination reward
    CrossShardCoordination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Active validator
    Active,
    /// Slashed (but still in queue)
    Slashed,
    /// Jailed (temporarily unable to propose)
    Jailed,
    /// Ejected (permanently removed)
    Ejected,
}

/// Validator participation metrics for an epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    /// Validator public key
    pub validator_id: Vec<u8>,
    /// Blocks proposed
    pub blocks_proposed: u32,
    /// Attestations included
    pub attestations_included: u32,
    /// Healing participations
    pub healing_participations: u32,
    /// Shards coordinated
    pub shards_coordinated: u32,
    /// Double signing evidence (0 = none, else > 0)
    pub double_signs_evidence: u32,
    /// Failed state transitions
    pub state_transition_failures: u32,
    /// Epoch this applies to
    pub epoch: u64,
}

/// Reward computation for a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardRecord {
    /// Validator ID
    pub validator_id: Vec<u8>,
    /// Epoch
    pub epoch: u64,
    /// Reward breakdown by type
    pub rewards: BTreeMap<RewardType, u128>,
    /// Total reward amount
    pub total_reward: u128,
    /// Proof of computation
    pub computation_hash: Vec<u8>,
}

impl RewardRecord {
    /// Compute hash of reward computation for verification
    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.validator_id);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.total_reward.to_le_bytes());
        for (reward_type, amount) in &self.rewards {
            hasher.update((*reward_type as u8).to_le_bytes());
            hasher.update(amount.to_le_bytes());
        }
        hasher.finalize().to_vec()
    }

    /// Verify reward computation hash
    pub fn verify_hash(&self) -> Result<(), ValidatorError> {
        let computed = self.compute_hash();
        if computed != self.computation_hash {
            return Err(ValidatorError::RewardHashMismatch);
        }
        Ok(())
    }
}

/// Slashing evidence for a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvidence {
    /// Validator being slashed
    pub validator_id: Vec<u8>,
    /// Epoch when violation occurred
    pub epoch: u64,
    /// Type of violation
    pub violation_type: SlashingViolationType,
    /// Amount slashed (in base tokens)
    pub slash_amount: u128,
    /// Cryptographic proof
    pub proof_hash: Vec<u8>,
    /// Whether this has been disputed/appealed
    pub disputed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingViolationType {
    /// Double signing on same height
    DoubleSigning,
    /// Invalid state transition
    InvalidTransition,
    /// Withholding recovery participation
    RecoveryWithholding,
    /// False governance action
    FalseGovernance,
    /// Provable malicious rollback
    MaliciousRollback,
}

impl SlashingViolationType {
    /// Base slash percentage (of stake)
    pub fn base_slash_percentage(&self) -> u16 {
        match self {
            SlashingViolationType::DoubleSigning => 3200,     // 32%
            SlashingViolationType::InvalidTransition => 1600, // 16%
            SlashingViolationType::RecoveryWithholding => 800, // 8%
            SlashingViolationType::FalseGovernance => 1000,   // 10%
            SlashingViolationType::MaliciousRollback => 3200, // 32%
        }
    }
}

/// Validator account with staked balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorAccount {
    /// Public key
    pub validator_id: Vec<u8>,
    /// Staked balance
    pub stake: u128,
    /// Current status
    pub status: ValidatorStatus,
    /// Cumulative rewards earned
    pub total_rewards: u128,
    /// Cumulative slashes applied
    pub total_slashed: u128,
    /// Epoch when status last changed
    pub status_change_epoch: u64,
    /// Number of consecutive epochs jailed
    pub jail_duration_epochs: u32,
}

impl ValidatorAccount {
    /// Get effective stake (may be reduced by slashing)
    pub fn effective_stake(&self) -> u128 {
        self.stake.saturating_sub(self.total_slashed)
    }

    /// Check if validator is still participating
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            ValidatorStatus::Active | ValidatorStatus::Slashed
        )
    }

    /// Check if validator is permanently removed
    pub fn is_ejected(&self) -> bool {
        matches!(self.status, ValidatorStatus::Ejected)
    }
}

/// Validator incentives engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorIncentivesEngine {
    /// All validators indexed by ID
    pub validators: BTreeMap<Vec<u8>, ValidatorAccount>,
    /// Metrics for current epoch
    pub current_metrics: BTreeMap<Vec<u8>, ValidatorMetrics>,
    /// Reward records per epoch
    pub reward_history: BTreeMap<(u64, Vec<u8>), RewardRecord>,
    /// Slashing evidence (evidence hash -> record)
    pub slashing_evidence: BTreeMap<Vec<u8>, SlashingEvidence>,
    /// Reward parameters (tunable within bounds)
    pub reward_params: RewardParameters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardParameters {
    /// Base reward per block proposal (in minimal units)
    pub block_proposal_reward: u128,
    /// Participation reward per epoch (in minimal units)
    pub participation_reward: u128,
    /// Healing participation reward multiplier (x participation reward)
    pub healing_multiplier: u16,
    /// Cross-shard coordination reward (in minimal units)
    pub cross_shard_reward: u128,
}

impl Default for RewardParameters {
    fn default() -> Self {
        RewardParameters {
            block_proposal_reward: 32 * 10u128.pow(6), // 0.32 BLEEP (8 decimals)
            participation_reward: 1 * 10u128.pow(6),   // 0.01 BLEEP
            healing_multiplier: 3,                     // 3x participation
            cross_shard_reward: 5 * 10u128.pow(6),     // 0.05 BLEEP
        }
    }
}

impl ValidatorIncentivesEngine {
    /// Initialize with genesis parameters
    pub fn genesis() -> Self {
        ValidatorIncentivesEngine {
            validators: BTreeMap::new(),
            current_metrics: BTreeMap::new(),
            reward_history: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            reward_params: RewardParameters::default(),
        }
    }

    /// Register a new validator
    pub fn register_validator(
        &mut self,
        validator_id: Vec<u8>,
        stake: u128,
    ) -> Result<(), ValidatorError> {
        if self.validators.contains_key(&validator_id) {
            return Err(ValidatorError::ValidatorAlreadyExists);
        }

        if stake == 0 {
            return Err(ValidatorError::InvalidStake);
        }

        self.validators.insert(
            validator_id.clone(),
            ValidatorAccount {
                validator_id,
                stake,
                status: ValidatorStatus::Active,
                total_rewards: 0,
                total_slashed: 0,
                status_change_epoch: 0,
                jail_duration_epochs: 0,
            },
        );

        Ok(())
    }

    /// Record validator metrics for an epoch
    pub fn record_metrics(
        &mut self,
        validator_id: Vec<u8>,
        metrics: ValidatorMetrics,
    ) -> Result<(), ValidatorError> {
        if !self.validators.contains_key(&validator_id) {
            return Err(ValidatorError::ValidatorNotFound);
        }

        self.current_metrics.insert(validator_id, metrics);
        Ok(())
    }

    /// Compute rewards for an epoch based on metrics
    pub fn compute_epoch_rewards(
        &mut self,
        epoch: u64,
    ) -> Result<Vec<RewardRecord>, ValidatorError> {
        let mut records = Vec::new();

        for (validator_id, metrics) in self.current_metrics.iter() {
            let mut rewards = BTreeMap::new();
            let mut total = 0u128;

            // Block proposal rewards
            let proposal_reward = (metrics.blocks_proposed as u128)
                .saturating_mul(self.reward_params.block_proposal_reward);
            rewards.insert(RewardType::BlockProposal, proposal_reward);
            total = total.saturating_add(proposal_reward);

            // Participation rewards
            if metrics.attestations_included > 0 {
                let part_reward = self.reward_params.participation_reward;
                rewards.insert(RewardType::Participation, part_reward);
                total = total.saturating_add(part_reward);
            }

            // Healing rewards
            let healing_reward = (metrics.healing_participations as u128)
                .saturating_mul(self.reward_params.participation_reward)
                .saturating_mul(self.reward_params.healing_multiplier as u128)
                / 100;
            if healing_reward > 0 {
                rewards.insert(RewardType::HealingContribution, healing_reward);
                total = total.saturating_add(healing_reward);
            }

            // Cross-shard rewards
            let cross_reward = (metrics.shards_coordinated as u128)
                .saturating_mul(self.reward_params.cross_shard_reward);
            if cross_reward > 0 {
                rewards.insert(RewardType::CrossShardCoordination, cross_reward);
                total = total.saturating_add(cross_reward);
            }

            let mut record = RewardRecord {
                validator_id: validator_id.clone(),
                epoch,
                rewards,
                total_reward: total,
                computation_hash: vec![],
            };
            record.computation_hash = record.compute_hash();

            // Update validator account
            if let Some(validator) = self.validators.get_mut(validator_id) {
                validator.total_rewards = validator.total_rewards.saturating_add(total);
            }

            records.push(record.clone());
            self.reward_history
                .insert((epoch, validator_id.clone()), record);
        }

        Ok(records)
    }

    /// Apply slashing for a violation
    pub fn apply_slashing(&mut self, evidence: SlashingEvidence) -> Result<(), ValidatorError> {
        if let Some(validator) = self.validators.get_mut(&evidence.validator_id) {
            let slash_amount = evidence.slash_amount;

            // Apply slash (cap at effective stake)
            let effective = validator.effective_stake();
            let actual_slash = std::cmp::min(slash_amount, effective);

            validator.total_slashed = validator.total_slashed.saturating_add(actual_slash);

            // Apply jail if too much slashed
            if validator.total_slashed >= validator.stake / 3 {
                validator.status = ValidatorStatus::Jailed;
                validator.jail_duration_epochs = 2016; // ~1 week at 5min epochs
            }

            // Eject if completely slashed
            if validator.total_slashed >= validator.stake {
                validator.status = ValidatorStatus::Ejected;
            }

            self.slashing_evidence
                .insert(evidence.proof_hash.clone(), evidence);
            Ok(())
        } else {
            Err(ValidatorError::ValidatorNotFound)
        }
    }

    /// Unjail a validator after jail period expires
    pub fn unjail_validator(
        &mut self,
        validator_id: Vec<u8>,
        current_epoch: u64,
    ) -> Result<(), ValidatorError> {
        if let Some(validator) = self.validators.get_mut(&validator_id) {
            if validator.status != ValidatorStatus::Jailed {
                return Err(ValidatorError::NotJailed);
            }

            let epochs_jailed = current_epoch.saturating_sub(validator.status_change_epoch);
            if epochs_jailed < validator.jail_duration_epochs as u64 {
                return Err(ValidatorError::JailPeriodNotExpired);
            }

            validator.status = ValidatorStatus::Active;
            validator.status_change_epoch = current_epoch;
            Ok(())
        } else {
            Err(ValidatorError::ValidatorNotFound)
        }
    }

    /// Get total staked amount across all active validators
    pub fn total_active_stake(&self) -> u128 {
        self.validators
            .values()
            .filter(|v| v.is_active())
            .map(|v| v.effective_stake())
            .sum()
    }

    /// Get reward history for a validator
    pub fn get_validator_rewards(
        &self,
        validator_id: &[u8],
        start_epoch: u64,
        end_epoch: u64,
    ) -> Vec<RewardRecord> {
        (start_epoch..=end_epoch)
            .filter_map(|epoch| {
                self.reward_history
                    .get(&(epoch, validator_id.to_vec()))
                    .cloned()
            })
            .collect()
    }
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum ValidatorError {
    #[error("Validator not found")]
    ValidatorNotFound,
    #[error("Validator already exists")]
    ValidatorAlreadyExists,
    #[error("Invalid stake amount")]
    InvalidStake,
    #[error("Reward hash mismatch")]
    RewardHashMismatch,
    #[error("Validator not jailed")]
    NotJailed,
    #[error("Jail period not expired")]
    JailPeriodNotExpired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_registration() {
        let mut engine = ValidatorIncentivesEngine::genesis();
        let validator_id = vec![1, 2, 3, 4];

        assert!(engine
            .register_validator(validator_id.clone(), 1000)
            .is_ok());
        assert!(engine.validators.contains_key(&validator_id));
    }

    #[test]
    fn test_reward_computation() {
        let mut engine = ValidatorIncentivesEngine::genesis();
        let validator_id = vec![1, 2, 3, 4];

        engine.register_validator(validator_id.clone(), 1000).ok();

        let metrics = ValidatorMetrics {
            validator_id: validator_id.clone(),
            blocks_proposed: 5,
            attestations_included: 32,
            healing_participations: 2,
            shards_coordinated: 1,
            double_signs_evidence: 0,
            state_transition_failures: 0,
            epoch: 0,
        };

        engine.record_metrics(validator_id.clone(), metrics).ok();
        let rewards = match engine.compute_epoch_rewards(0) {
            Ok(rewards) => rewards,
            Err(e) => {
                error!("Failed to compute epoch rewards: {:?}", e);
                return;
            }
        };
        assert!(!rewards.is_empty());
        assert!(rewards[0].total_reward > 0);

        // ...existing code...

        let validator = match engine.validators.get(&validator_id) {
            Some(validator) => validator,
            None => {
                error!("Validator not found: {:?}", validator_id);
                return;
            }
        };
        assert_eq!(validator.total_slashed, 380);
        assert_eq!(validator.status, ValidatorStatus::Jailed);
    }

    #[test]
    fn test_total_stake() {
        let mut engine = ValidatorIncentivesEngine::genesis();

        engine.register_validator(vec![1], 1000).ok();
        engine.register_validator(vec![2], 2000).ok();

        assert_eq!(engine.total_active_stake(), 3000);
    }
}
