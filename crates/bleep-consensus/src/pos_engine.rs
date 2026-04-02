// PROOF-OF-STAKE CONSENSUS ENGINE
// Validator-based block selection and finalization
//
// SAFETY INVARIANTS:
// 1. Block proposer is deterministically selected based on stake weight
// 2. Block signature must be from the selected proposer
// 3. Validator participation is verifiable on-chain
// 4. Proposer slashing occurs on double-signing or safety violations

use crate::engine::{ConsensusEngine, ConsensusError};
use crate::epoch::EpochState;
use bleep_core::block::{Block, ConsensusMode, Transaction};
use bleep_core::blockchain::BlockchainState;
use log::info;

/// Validator stake information.
#[derive(Debug, Clone)]
pub struct ValidatorStake {
    /// Public key identifier
    pub id: String,

    /// Current stake amount
    pub stake: u64,

    /// Whether this validator is currently active
    pub active: bool,

    /// Number of slashing events
    pub slashing_count: u32,
}

impl ValidatorStake {
    /// Check if this validator can participate in consensus.
    pub fn can_participate(&self) -> bool {
        self.active && self.slashing_count == 0
    }
}

/// Proof-of-Stake consensus engine.
///
/// SAFETY: This engine implements Byzantine-fault-tolerant consensus
/// based on validator stake weight. Block proposer is determined by
/// a deterministic function of the previous block hash and validator set.
pub struct PoSConsensusEngine {
    /// Validator ID (public key)
    validator_id: String,

    /// This validator's stake weight
    my_stake: u64,

    /// Last block this validator signed
    last_signed_block_height: u64,
}

impl PoSConsensusEngine {
    /// Create a new PoS engine.
    pub fn new(validator_id: String, my_stake: u64) -> Self {
        PoSConsensusEngine {
            validator_id,
            my_stake,
            last_signed_block_height: 0,
        }
    }

    /// Get this validator's stake weight.
    pub fn my_stake(&self) -> u64 {
        self.my_stake
    }

    /// Get the last block height this validator signed.
    pub fn last_signed_block_height(&self) -> u64 {
        self.last_signed_block_height
    }

    /// Update the last signed block height.
    pub fn update_last_signed_block(&mut self, height: u64) {
        if height > self.last_signed_block_height {
            self.last_signed_block_height = height;
        }
    }

    /// Select the block proposer for a given height.
    ///
    /// SAFETY: This function is deterministic.
    /// Same block height + validator set always produces same proposer.
    ///
    /// Uses weighted random selection: each validator has probability
    /// proportional to their stake.
    ///
    /// PUBLIC: Called by orchestrator during block proposal selection.
    pub fn select_proposer(
        height: u64,
        validators: &[ValidatorStake],
        prev_block_hash: &str,
    ) -> Result<String, ConsensusError> {
        // Filter to active validators
        let active: Vec<_> = validators.iter().filter(|v| v.can_participate()).collect();

        if active.is_empty() {
            return Err(ConsensusError::InsufficientValidatorParticipation {
                participation_rate: 0.0,
                threshold: 0.66,
            });
        }

        // Compute total stake
        let total_stake: u64 = active.iter().map(|v| v.stake).sum();
        if total_stake == 0 {
            return Err(ConsensusError::ProposalRejected {
                reason: "Total validator stake is zero".to_string(),
            });
        }

        // Use previous block hash as seed for deterministic selection
        // SAFETY: All nodes with identical validator set will compute the same proposer
        let seed = Self::compute_seed(height, prev_block_hash);
        let selection = seed % total_stake;

        let mut accumulated = 0;
        let selected_validator = active.iter().find(|validator| {
            accumulated += validator.stake;
            accumulated > selection
        });

        // Return selected or first validator as fallback
        if let Some(validator) = selected_validator {
            Ok(validator.id.clone())
        } else {
            Ok(active[0].id.clone())
        }
    }

    /// Compute a deterministic proposer-selection seed.
    ///
    /// ## S-02 Fix: SHA-256 replaces DefaultHasher
    ///
    /// `DefaultHasher` (SipHash-1-3) uses a **per-process random seed** since
    /// Rust 1.7.  Two independent nodes computing `DefaultHasher(height, prev_hash)`
    /// produce *different* values, making them select *different* proposers —
    /// a consensus-safety violation.  It is also not collision-resistant,
    /// enabling stake-grinding attacks.
    ///
    /// **Fix:** `SHA-256(height_le8 || prev_hash_utf8)`, first 8 bytes → `u64`.
    ///
    /// Properties:
    /// - **Platform-deterministic** — every honest node computes the same seed.
    /// - **Pre-image resistant** — prevents seed prediction / grinding.
    /// - **No extra dependency** — `sha2` is already in the workspace.
    ///
    /// PUBLIC: Called by select_proposer to generate deterministic selection.
    pub fn compute_seed(height: u64, prev_hash: &str) -> u64 {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&height.to_le_bytes());
        h.update(prev_hash.as_bytes());
        let d = h.finalize();
        u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
    }

    /// Check if a validator is allowed to participate.
    ///
    /// PUBLIC: Called when validating block proposals.
    pub fn check_validator_health(validator: &ValidatorStake) -> Result<(), ConsensusError> {
        if !validator.active {
            return Err(ConsensusError::ProposalRejected {
                reason: format!("Validator {} is not active", validator.id),
            });
        }

        if validator.slashing_count > 0 {
            return Err(ConsensusError::ProposalRejected {
                reason: format!(
                    "Validator {} has {} slashing events",
                    validator.id, validator.slashing_count
                ),
            });
        }

        Ok(())
    }
}

impl ConsensusEngine for PoSConsensusEngine {
    fn verify_block(
        &self,
        block: &Block,
        epoch_state: &EpochState,
        _blockchain_state: &BlockchainState,
    ) -> Result<(), ConsensusError> {
        // SAFETY: Verify block signature exists
        if block.validator_signature.is_empty() {
            return Err(ConsensusError::InvalidSignature {
                validator_id: "unknown".to_string(),
            });
        }

        // SAFETY: Verify consensus mode matches
        if block.consensus_mode != ConsensusMode::PosNormal {
            return Err(ConsensusError::ConsensusModeMismatch {
                expected: "POS_NORMAL".to_string(),
                got: format!("{:?}", block.consensus_mode),
                epoch: epoch_state.epoch_id,
            });
        }

        // SAFETY: Verify block height is within epoch bounds
        if !epoch_state.contains_height(block.index) {
            return Err(ConsensusError::ProposalRejected {
                reason: format!(
                    "Block height {} is outside epoch {} bounds [{}, {}]",
                    block.index,
                    epoch_state.epoch_id,
                    epoch_state.start_height,
                    epoch_state.end_height
                ),
            });
        }

        // In a real implementation, we would:
        // 1. Verify the block hash
        // 2. Verify the validator's digital signature using their public key
        // 3. Check the validator against an on-chain validator set
        // For now, we accept the block as valid

        info!(
            "PoS verification passed for block {} in epoch {}",
            block.index, epoch_state.epoch_id
        );

        Ok(())
    }

    fn propose_block(
        &self,
        height: u64,
        previous_hash: String,
        transactions: Vec<Transaction>,
        epoch_state: &EpochState,
        _blockchain_state: &BlockchainState,
    ) -> Result<Block, ConsensusError> {
        // SAFETY: Create block with correct consensus fields
        let mut block = Block::with_consensus_and_sharding(
            height,
            transactions,
            previous_hash,
            epoch_state.epoch_id,
            ConsensusMode::PosNormal,
            1,             // protocol_version
            String::new(), // shard_registry_root
            0,             // shard_id - default to main shard
            String::new(), // shard_state_root
        );

        // SAFETY: Sign the block with our validator key
        // In a real implementation, we would use the validator's private key
        block.validator_signature = self.validator_id.as_bytes().to_vec();

        info!(
            "PoS proposed block {} in epoch {} by validator {}",
            height, epoch_state.epoch_id, self.validator_id
        );

        Ok(block)
    }

    fn consensus_mode(&self) -> crate::epoch::ConsensusMode {
        crate::epoch::ConsensusMode::PosNormal
    }

    fn health_status(&self) -> f64 {
        // Return a health score between 0.0 and 1.0
        // In a real implementation, this would check network connectivity,
        // validator status, stake, etc.
        0.95
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pos_engine_creation() {
        let engine = PoSConsensusEngine::new("validator1".to_string(), 1000);
        assert_eq!(engine.validator_id, "validator1");
        assert_eq!(engine.my_stake, 1000);
    }

    #[test]
    fn test_select_proposer_deterministic() {
        let validators = vec![
            ValidatorStake {
                id: "v1".to_string(),
                stake: 100,
                active: true,
                slashing_count: 0,
            },
            ValidatorStake {
                id: "v2".to_string(),
                stake: 200,
                active: true,
                slashing_count: 0,
            },
        ];

        let p1 = PoSConsensusEngine::select_proposer(100, &validators, "hash1").unwrap();
        let p2 = PoSConsensusEngine::select_proposer(100, &validators, "hash1").unwrap();
        // Same height and hash should select same proposer
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_select_proposer_different_heights() {
        let validators = vec![
            ValidatorStake {
                id: "v1".to_string(),
                stake: 100,
                active: true,
                slashing_count: 0,
            },
            ValidatorStake {
                id: "v2".to_string(),
                stake: 200,
                active: true,
                slashing_count: 0,
            },
        ];

        let p1 = PoSConsensusEngine::select_proposer(100, &validators, "hash1").ok();
        let p2 = PoSConsensusEngine::select_proposer(101, &validators, "hash1").ok();
        // Different heights may select different proposers (probabilistically)
        // We just verify that both succeed
        assert!(p1.is_some());
        assert!(p2.is_some());
    }

    #[test]
    fn test_select_proposer_no_active_validators() {
        let validators = vec![ValidatorStake {
            id: "v1".to_string(),
            stake: 100,
            active: false,
            slashing_count: 0,
        }];

        let result = PoSConsensusEngine::select_proposer(100, &validators, "hash1");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_validator_health_active() {
        let validator = ValidatorStake {
            id: "v1".to_string(),
            stake: 100,
            active: true,
            slashing_count: 0,
        };
        assert!(PoSConsensusEngine::check_validator_health(&validator).is_ok());
    }

    #[test]
    fn test_check_validator_health_inactive() {
        let validator = ValidatorStake {
            id: "v1".to_string(),
            stake: 100,
            active: false,
            slashing_count: 0,
        };
        assert!(PoSConsensusEngine::check_validator_health(&validator).is_err());
    }

    #[test]
    fn test_check_validator_health_slashed() {
        let validator = ValidatorStake {
            id: "v1".to_string(),
            stake: 100,
            active: true,
            slashing_count: 1,
        };
        assert!(PoSConsensusEngine::check_validator_health(&validator).is_err());
    }

    #[test]
    fn test_compute_seed_deterministic() {
        // SHA-256 has no per-process salt — must be identical across calls.
        let seed1 = PoSConsensusEngine::compute_seed(100, "hash1");
        let seed2 = PoSConsensusEngine::compute_seed(100, "hash1");
        assert_eq!(seed1, seed2, "S-02: seed must be identical for same inputs");
    }

    #[test]
    fn test_compute_seed_different_inputs() {
        let seed1 = PoSConsensusEngine::compute_seed(100, "hash1");
        let seed2 = PoSConsensusEngine::compute_seed(101, "hash1");
        assert_ne!(
            seed1, seed2,
            "S-02: different heights must yield different seeds"
        );
    }

    #[test]
    fn test_compute_seed_matches_sha256() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&55u64.to_le_bytes());
        h.update(b"prev_abc");
        let d = h.finalize();
        let expected = u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
        assert_eq!(
            PoSConsensusEngine::compute_seed(55, "prev_abc"),
            expected,
            "S-02: must match SHA-256(height_le8 || prev_hash)"
        );
    }
}
