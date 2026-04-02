// PHASE 1: CONSENSUS LAYER CORRECTION
// Epoch System - Deterministic, fork-safe epoch management
//
// SAFETY INVARIANTS:
// 1. Epoch ID is deterministically derived from block height
// 2. Consensus mode is locked per epoch (no mid-epoch switching)
// 3. All honest nodes independently compute identical epoch boundaries
// 4. Epoch state is on-chain verifiable and immutable

use serde::{Deserialize, Serialize};
use std::ops::Range;

/// Global consensus modes.
///
/// SAFETY: These modes form a complete enumeration of all possible consensus
/// execution modes. The canonical consensus protocol selects ONE mode per epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ConsensusMode {
    /// Proof of Stake with validator selection by stake weight
    PosNormal,

    /// PBFT-style fast finality (acts as finality gadget only)
    PbftFastFinality,

    /// Emergency Proof of Work (rate-limited, auto-exit on condition clear)
    EmergencyPow,
}

impl ConsensusMode {
    /// Return a human-readable name for logging and diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConsensusMode::PosNormal => "PoS_NORMAL",
            ConsensusMode::PbftFastFinality => "PBFT_FINALITY",
            ConsensusMode::EmergencyPow => "EMERGENCY_POW",
        }
    }
}

/// Epoch configuration: immutable after genesis.
///
/// SAFETY: These parameters are locked at chain initialization.
/// Changing them requires a hard fork, ensuring all nodes have identical
/// epoch boundaries even if they rejoin the network at different times.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Number of blocks per epoch. Must be > 0.
    /// Example: 1000 blocks = ~4 hours at 14.4 sec/block
    pub blocks_per_epoch: u64,

    /// Genesis block height (usually 0, but allows flexibility for forks)
    pub genesis_height: u64,

    /// Protocol version (incremented on hard forks)
    pub protocol_version: u32,
}

impl EpochConfig {
    /// Create a new epoch configuration.
    ///
    /// # Arguments
    /// * `blocks_per_epoch` - Must be positive
    /// * `genesis_height` - Chain height where epochs begin
    /// * `protocol_version` - Version number for fork detection
    pub fn new(
        blocks_per_epoch: u64,
        genesis_height: u64,
        protocol_version: u32,
    ) -> Result<Self, String> {
        if blocks_per_epoch == 0 {
            return Err("blocks_per_epoch must be > 0".to_string());
        }
        Ok(EpochConfig {
            blocks_per_epoch,
            genesis_height,
            protocol_version,
        })
    }

    /// Compute the epoch number for a given block height.
    ///
    /// SAFETY: Deterministic (same height → same epoch on all nodes)
    ///
    /// Formula: epoch_id = (height - genesis_height) / blocks_per_epoch
    pub fn epoch_id(&self, height: u64) -> u64 {
        if height < self.genesis_height {
            return 0;
        }
        (height - self.genesis_height) / self.blocks_per_epoch
    }

    /// Return the block height range for a given epoch.
    ///
    /// Example: If blocks_per_epoch=1000, genesis=0:
    ///   epoch 0: [0, 999]
    ///   epoch 1: [1000, 1999]
    ///   epoch 2: [2000, 2999]
    pub fn height_range(&self, epoch_id: u64) -> Range<u64> {
        let start = self.genesis_height + (epoch_id * self.blocks_per_epoch);
        let end = start + self.blocks_per_epoch;
        start..end
    }

    /// Check if a block height belongs to a given epoch.
    pub fn is_in_epoch(&self, height: u64, epoch_id: u64) -> bool {
        self.epoch_id(height) == epoch_id
    }

    /// Get the starting block height of an epoch.
    pub fn epoch_start_height(&self, epoch_id: u64) -> u64 {
        self.genesis_height + (epoch_id * self.blocks_per_epoch)
    }

    /// Get the ending block height (inclusive) of an epoch.
    pub fn epoch_end_height(&self, epoch_id: u64) -> u64 {
        self.epoch_start_height(epoch_id + 1) - 1
    }
}

/// Per-epoch consensus state.
///
/// SAFETY: Immutable after block finalization.
/// Blocks reference their epoch state for validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EpochState {
    /// Unique identifier for this epoch (derived from height)
    pub epoch_id: u64,

    /// Consensus mode for this epoch (locked at epoch start)
    pub consensus_mode: ConsensusMode,

    /// Block height where this epoch began
    pub start_height: u64,

    /// Block height where this epoch ends (inclusive)
    pub end_height: u64,
}

impl EpochState {
    /// Create a new epoch state.
    pub fn new(
        epoch_id: u64,
        consensus_mode: ConsensusMode,
        start_height: u64,
        end_height: u64,
    ) -> Self {
        EpochState {
            epoch_id,
            consensus_mode,
            start_height,
            end_height,
        }
    }

    /// Check if a block height belongs to this epoch.
    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    /// Verify that the epoch state is consistent with the config.
    ///
    /// SAFETY: Must be called after computing epoch state from config.
    pub fn validate(&self, config: &EpochConfig) -> Result<(), String> {
        let expected_id = config.epoch_id(self.start_height);
        if self.epoch_id != expected_id {
            return Err(format!(
                "Epoch ID mismatch: got {}, expected {}",
                self.epoch_id, expected_id
            ));
        }

        if self.end_height - self.start_height + 1 != config.blocks_per_epoch {
            return Err(format!(
                "Epoch height range mismatch: expected {} blocks, got {}",
                config.blocks_per_epoch,
                self.end_height - self.start_height + 1
            ));
        }

        Ok(())
    }
}

/// Builder for EpochState from configuration.
pub struct EpochBuilder<'a> {
    config: &'a EpochConfig,
}

impl<'a> EpochBuilder<'a> {
    /// Create a new epoch builder.
    pub fn new(config: &'a EpochConfig) -> Self {
        EpochBuilder { config }
    }

    /// Build the epoch state for a given block height.
    ///
    /// SAFETY: Deterministic - same height always produces same state.
    pub fn build(&self, height: u64, consensus_mode: ConsensusMode) -> Result<EpochState, String> {
        let epoch_id = self.config.epoch_id(height);
        let start_height = self.config.epoch_start_height(epoch_id);
        let end_height = self.config.epoch_end_height(epoch_id);

        let epoch_state = EpochState::new(epoch_id, consensus_mode, start_height, end_height);
        epoch_state.validate(self.config)?;

        Ok(epoch_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_config_creation() {
        let config = EpochConfig::new(1000, 0, 1).unwrap();
        assert_eq!(config.blocks_per_epoch, 1000);
        assert_eq!(config.genesis_height, 0);
        assert_eq!(config.protocol_version, 1);
    }

    #[test]
    fn test_epoch_id_determinism() {
        let config = EpochConfig::new(1000, 0, 1).unwrap();

        // Same height always produces same epoch
        assert_eq!(config.epoch_id(0), 0);
        assert_eq!(config.epoch_id(999), 0);
        assert_eq!(config.epoch_id(1000), 1);
        assert_eq!(config.epoch_id(1999), 1);
        assert_eq!(config.epoch_id(2000), 2);
    }

    #[test]
    fn test_height_range() {
        let config = EpochConfig::new(1000, 0, 1).unwrap();

        let range0 = config.height_range(0);
        assert_eq!(range0.start, 0);
        assert_eq!(range0.end, 1000);

        let range1 = config.height_range(1);
        assert_eq!(range1.start, 1000);
        assert_eq!(range1.end, 2000);
    }

    #[test]
    fn test_is_in_epoch() {
        let config = EpochConfig::new(1000, 0, 1).unwrap();

        assert!(config.is_in_epoch(0, 0));
        assert!(config.is_in_epoch(999, 0));
        assert!(!config.is_in_epoch(1000, 0));

        assert!(config.is_in_epoch(1000, 1));
        assert!(config.is_in_epoch(1999, 1));
        assert!(!config.is_in_epoch(2000, 1));
    }

    #[test]
    fn test_epoch_state_builder() {
        let config = EpochConfig::new(1000, 0, 1).unwrap();
        let builder = EpochBuilder::new(&config);

        let epoch = builder.build(500, ConsensusMode::PosNormal).unwrap();
        assert_eq!(epoch.epoch_id, 0);
        assert_eq!(epoch.consensus_mode, ConsensusMode::PosNormal);
        assert_eq!(epoch.start_height, 0);
        assert_eq!(epoch.end_height, 999);
    }

    #[test]
    fn test_epoch_state_validation() {
        let config = EpochConfig::new(1000, 0, 1).unwrap();

        // Valid epoch state
        let valid = EpochState::new(0, ConsensusMode::PosNormal, 0, 999);
        assert!(valid.validate(&config).is_ok());

        // Invalid epoch ID
        let invalid_id = EpochState::new(99, ConsensusMode::PosNormal, 0, 999);
        assert!(invalid_id.validate(&config).is_err());

        // Invalid height range
        let invalid_range = EpochState::new(0, ConsensusMode::PosNormal, 0, 500);
        assert!(invalid_range.validate(&config).is_err());
    }

    #[test]
    fn test_consensus_mode_str() {
        assert_eq!(ConsensusMode::PosNormal.as_str(), "PoS_NORMAL");
        assert_eq!(ConsensusMode::PbftFastFinality.as_str(), "PBFT_FINALITY");
        assert_eq!(ConsensusMode::EmergencyPow.as_str(), "EMERGENCY_POW");
    }

    #[test]
    fn test_zero_blocks_per_epoch_error() {
        let result = EpochConfig::new(0, 0, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_genesis_height() {
        let config = EpochConfig::new(100, 10, 1).unwrap();

        // Before genesis height
        assert_eq!(config.epoch_id(5), 0);

        // At and after genesis
        assert_eq!(config.epoch_id(10), 0);
        assert_eq!(config.epoch_id(109), 0);
        assert_eq!(config.epoch_id(110), 1);
    }
}
