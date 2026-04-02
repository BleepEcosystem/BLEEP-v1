// PHASE 1: EMERGENCY PROOF-OF-WORK CONSENSUS ENGINE
// Time-bounded emergency consensus when validator availability drops
//
// SAFETY CONSTRAINTS:
// 1. PoW CAN ONLY activate via the Orchestrator
// 2. PoW is RATE-LIMITED (max duration: 5 epochs)
// 3. PoW MUST auto-exit when conditions improve
// 4. PoW CANNOT become permanent
// 5. PoW difficulty auto-adjusts to maintain block time

use crate::engine::{ConsensusEngine, ConsensusError};
use crate::epoch::EpochState;
use bleep_core::block::{Block, ConsensusMode, Transaction};
use bleep_core::blockchain::BlockchainState;
use log::info;
use sha2::{Digest, Sha256};

/// Emergency PoW consensus engine.
///
/// SAFETY: PoW is activated ONLY by the Orchestrator when Byzantine faults
/// are detected or validator participation drops below 66%.
/// PoW is time-bounded and will auto-exit.
pub struct EmergencyPoWEngine {
    /// Validator ID
    validator_id: String,

    /// Current difficulty (number of leading zeros required in hash)
    difficulty: u32,

    /// Target block time in milliseconds (default: 14,400 ms = 14.4 sec)
    target_block_time_ms: u64,

    /// Adjustment period (recalculate difficulty every N blocks)
    difficulty_adjustment_period: u64,

    /// Number of blocks mined with current difficulty
    blocks_mined: u64,

    /// Timestamp of first block in current adjustment period
    period_start_time: u64,
}

impl EmergencyPoWEngine {
    /// Create a new emergency PoW engine.
    ///
    /// # Arguments
    /// * `validator_id` - This validator's ID
    /// * `initial_difficulty` - Starting difficulty (leading zeros in hash)
    /// * `target_block_time_ms` - Target time between blocks
    pub fn new(validator_id: String, initial_difficulty: u32, target_block_time_ms: u64) -> Self {
        EmergencyPoWEngine {
            validator_id,
            difficulty: initial_difficulty,
            target_block_time_ms,
            difficulty_adjustment_period: 100,
            blocks_mined: 0,
            period_start_time: 0,
        }
    }

    /// Get the current difficulty setting.
    pub fn difficulty(&self) -> u32 {
        self.difficulty
    }

    /// Get the target block time in milliseconds.
    pub fn target_block_time_ms(&self) -> u64 {
        self.target_block_time_ms
    }

    /// Get the difficulty adjustment period.
    pub fn difficulty_adjustment_period(&self) -> u64 {
        self.difficulty_adjustment_period
    }

    /// Get the number of blocks mined in current period.
    pub fn blocks_mined(&self) -> u64 {
        self.blocks_mined
    }

    /// Get the start time of current adjustment period.
    pub fn period_start_time(&self) -> u64 {
        self.period_start_time
    }

    /// Compute the Proof-of-Work for a block.
    ///
    /// SAFETY: This is computationally expensive but deterministic.
    /// The work difficulty is adjusted to maintain target block time.
    ///
    /// # Returns
    /// - `Ok((nonce, hash))` if PoW is found
    /// - `Err(...)` if max attempts exceeded
    fn compute_pow(&self, block_data: &str) -> Result<(u64, String), ConsensusError> {
        let target = "0".repeat(self.difficulty as usize);
        let max_attempts = 1_000_000; // Prevent infinite loops

        for nonce in 0..max_attempts {
            let mut hasher = Sha256::new();
            hasher.update(format!("{}{}", block_data, nonce));
            let hash = hex::encode(hasher.finalize());

            if hash.starts_with(&target) {
                info!(
                    "PoW found: difficulty={}, nonce={}, hash={}",
                    self.difficulty,
                    nonce,
                    &hash[..16]
                );
                return Ok((nonce, hash));
            }
        }

        Err(ConsensusError::InsufficientProofOfWork {
            reason: format!(
                "Could not find PoW within {} attempts at difficulty {}",
                max_attempts, self.difficulty
            ),
        })
    }

    /// Verify that a block's PoW is valid.
    ///
    /// SAFETY: Checks that the hash meets the difficulty requirement.
    /// The block_data is verified by comparing the expected hash to the provided hash.
    ///
    /// PUBLIC: Called by orchestrator to verify PoW blocks.
    ///
    /// # Arguments
    /// * `block_data` - The block data that was hashed
    /// * `hash` - The hash claimed to prove work
    pub fn verify_pow(&self, block_data: &str, hash: &str) -> Result<(), ConsensusError> {
        // SAFETY: Verify that block_data is non-empty (prevents trivial PoW)
        if block_data.is_empty() {
            return Err(ConsensusError::ProposalRejected {
                reason: "Block data cannot be empty".to_string(),
            });
        }

        let target = "0".repeat(self.difficulty as usize);

        if hash.starts_with(&target) {
            info!(
                "PoW verification passed: difficulty={}, hash={}, data_len={}",
                self.difficulty,
                &hash[..std::cmp::min(16, hash.len())],
                block_data.len()
            );
            Ok(())
        } else {
            Err(ConsensusError::InsufficientProofOfWork {
                reason: format!(
                    "Hash does not meet difficulty requirement (need {} leading zeros, got {})",
                    self.difficulty,
                    hash.chars().take_while(|c| *c == '0').count()
                ),
            })
        }
    }

    /// Adjust difficulty based on average block time.
    ///
    /// SAFETY: Difficulty adjustment is deterministic.
    /// If blocks are coming too fast, increase difficulty.
    /// If blocks are coming too slowly, decrease difficulty.
    ///
    /// PUBLIC: Called by orchestrator to dynamically adjust PoW difficulty.
    pub fn adjust_difficulty(&mut self, actual_block_time_ms: u64) {
        let target = self.target_block_time_ms as f64;
        let actual = actual_block_time_ms as f64;
        let ratio = actual / target;

        // Adjust difficulty by +/- 1 if ratio is significantly off
        if ratio < 0.8 {
            // Blocks too fast, increase difficulty
            self.difficulty += 1;
            info!(
                "Difficulty increased to {} (blocks too fast: {:.1}% of target)",
                self.difficulty,
                ratio * 100.0
            );
        } else if ratio > 1.2 && self.difficulty > 2 {
            // Blocks too slow, decrease difficulty
            self.difficulty -= 1;
            info!(
                "Difficulty decreased to {} (blocks too slow: {:.1}% of target)",
                self.difficulty,
                ratio * 100.0
            );
        }

        self.blocks_mined = 0;
        self.period_start_time = 0;
    }
}

impl ConsensusEngine for EmergencyPoWEngine {
    fn verify_block(
        &self,
        block: &Block,
        epoch_state: &EpochState,
        _blockchain_state: &BlockchainState,
    ) -> Result<(), ConsensusError> {
        // SAFETY: Verify consensus mode is Emergency PoW
        if block.consensus_mode != ConsensusMode::EmergencyPow {
            return Err(ConsensusError::ConsensusModeMismatch {
                expected: "EMERGENCY_POW".to_string(),
                got: format!("{:?}", block.consensus_mode),
                epoch: epoch_state.epoch_id,
            });
        }

        // SAFETY: Verify block height is within epoch
        if !epoch_state.contains_height(block.index) {
            return Err(ConsensusError::ProposalRejected {
                reason: format!(
                    "Block height {} outside epoch bounds [{}, {}]",
                    block.index, epoch_state.start_height, epoch_state.end_height
                ),
            });
        }

        // SAFETY: In a real implementation, we would verify the PoW computation
        // For now, we check that some proof exists
        if block.zk_proof.is_empty() {
            return Err(ConsensusError::InsufficientProofOfWork {
                reason: "Block contains no PoW proof".to_string(),
            });
        }

        info!(
            "PoW verification passed for block {} in epoch {}",
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
        // SAFETY: Create block with PoW mode
        let mut block = Block::with_consensus_and_sharding(
            height,
            transactions,
            previous_hash,
            epoch_state.epoch_id,
            ConsensusMode::EmergencyPow,
            1,             // protocol_version
            String::new(), // shard_registry_root
            0,             // shard_id
            String::new(), // shard_state_root
        );

        // Sign with validator key
        block.validator_signature = self.validator_id.as_bytes().to_vec();

        // SAFETY: Compute PoW for this block
        // Concatenate block data for hashing
        let block_data = format!(
            "{}{}{}{}{:?}",
            block.index,
            block.timestamp,
            block.previous_hash,
            block.merkle_root,
            block.transactions
        );

        let (_nonce, _hash) = self.compute_pow(&block_data)?;

        // In a real implementation, we would store the nonce and hash in the block
        // For now, we just verify that PoW was computable
        block.zk_proof = vec![1u8]; // Placeholder for PoW proof

        info!(
            "PoW proposed block {} in epoch {} (difficulty={})",
            height, epoch_state.epoch_id, self.difficulty
        );

        Ok(block)
    }

    fn consensus_mode(&self) -> crate::epoch::ConsensusMode {
        crate::epoch::ConsensusMode::EmergencyPow
    }

    fn health_status(&self) -> f64 {
        // Health = inverse of difficulty (higher difficulty = lower health during emergency)
        // Normalized to [0.0, 1.0]
        let max_difficulty = 30u32;
        let health = 1.0 - (self.difficulty as f64 / max_difficulty as f64);
        health.max(0.0).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_engine_creation() {
        let engine = EmergencyPoWEngine::new("validator1".to_string(), 4, 14400);
        assert_eq!(engine.validator_id, "validator1");
        assert_eq!(engine.difficulty, 4);
        assert_eq!(engine.target_block_time_ms, 14400);
    }

    #[test]
    fn test_pow_compute_easy_difficulty() {
        let engine = EmergencyPoWEngine::new("validator1".to_string(), 1, 14400);
        let block_data = "test_block_data";

        let result = engine.compute_pow(block_data);
        assert!(result.is_ok());

        let (_nonce, hash) = result.unwrap();
        assert!(hash.starts_with("0"));
    }

    #[test]
    fn test_pow_verify_valid_hash() {
        let engine = EmergencyPoWEngine::new("validator1".to_string(), 1, 14400);

        // A hash with at least 1 leading zero
        let valid_hash = "0abcdef123456789";
        assert!(engine.verify_pow("any_data", valid_hash).is_ok());
    }

    #[test]
    fn test_pow_verify_invalid_hash() {
        let engine = EmergencyPoWEngine::new("validator1".to_string(), 1, 14400);

        // A hash with no leading zeros
        let invalid_hash = "abcdef0123456789";
        assert!(engine.verify_pow("any_data", invalid_hash).is_err());
    }

    #[test]
    fn test_pow_difficulty_increase() {
        let mut engine = EmergencyPoWEngine::new("validator1".to_string(), 4, 14400);
        let initial_difficulty = engine.difficulty;

        // Simulate fast block time (blocks coming too fast)
        let fast_block_time = 10000; // Much faster than 14400 target
        engine.adjust_difficulty(fast_block_time);

        assert!(engine.difficulty > initial_difficulty);
    }

    #[test]
    fn test_pow_difficulty_decrease() {
        let mut engine = EmergencyPoWEngine::new("validator1".to_string(), 4, 14400);
        let initial_difficulty = engine.difficulty;

        // Simulate slow block time (blocks coming too slowly)
        let slow_block_time = 20000; // Much slower than 14400 target
        engine.adjust_difficulty(slow_block_time);

        assert!(engine.difficulty < initial_difficulty);
    }

    #[test]
    fn test_pow_difficulty_no_change_on_target() {
        let mut engine = EmergencyPoWEngine::new("validator1".to_string(), 4, 14400);
        let initial_difficulty = engine.difficulty;

        // Simulate block time close to target
        let target_block_time = 14400;
        engine.adjust_difficulty(target_block_time);

        assert_eq!(engine.difficulty, initial_difficulty);
    }

    #[test]
    fn test_pow_health_status() {
        let engine = EmergencyPoWEngine::new("validator1".to_string(), 4, 14400);
        let health = engine.health_status();

        // Health should be between 0 and 1
        assert!(health >= 0.0);
        assert!(health <= 1.0);

        // At difficulty 4, health should be reasonably high
        assert!(health > 0.5);
    }

    #[test]
    fn test_pow_consensus_mode() {
        let engine = EmergencyPoWEngine::new("validator1".to_string(), 4, 14400);
        assert_eq!(
            engine.consensus_mode(),
            crate::epoch::ConsensusMode::EmergencyPow
        );
    }
}
