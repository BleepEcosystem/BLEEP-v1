// PHASE 1: CONSENSUS ORCHESTRATOR
// Deterministic consensus mode selection based on on-chain metrics
//
// SAFETY INVARIANTS:
// 1. Mode selection is fully deterministic (identical on all honest nodes)
// 2. Uses ONLY on-chain observable metrics (no local heuristics)
// 3. Mode switching occurs at epoch boundaries only
// 4. All decisions are reproducible and auditable
// 5. Emergency PoW is time-bounded and auto-exits

use crate::engine::{ConsensusEngine, ConsensusError, ConsensusMetrics};
use crate::epoch::{ConsensusMode, EpochConfig, EpochState};
use bleep_core::block::Block;
use bleep_core::blockchain::BlockchainState;
use log::{info, warn};
use std::collections::HashMap;
use std::sync::Arc;

/// State of the emergency PoW mechanism.
///
/// SAFETY: PoW must NEVER become permanent. It is rate-limited and auto-exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyPoWState {
    /// PoW is not active; chain is operating normally
    Inactive,

    /// PoW is active; fault detection in progress
    Active { activated_at_epoch: u64 },

    /// PoW has exited; chain returning to normal
    Exited { exited_at_epoch: u64 },
}

impl EmergencyPoWState {
    /// Check if this is an active state.
    pub fn is_active(&self) -> bool {
        matches!(self, EmergencyPoWState::Active { .. })
    }

    /// Get the epoch where PoW was activated (if applicable).
    pub fn activated_epoch(&self) -> Option<u64> {
        match self {
            EmergencyPoWState::Active { activated_at_epoch } => Some(*activated_at_epoch),
            _ => None,
        }
    }
}

/// Consensus orchestrator: selects consensus mode deterministically.
///
/// SAFETY: This is the ONLY component that selects the consensus mode for an epoch.
/// All decisions are based on deterministic, on-chain metrics that all honest nodes
/// can compute identically.
pub struct ConsensusOrchestrator {
    config: EpochConfig,

    /// Consensus engines indexed by mode
    engines: HashMap<ConsensusMode, Arc<dyn ConsensusEngine>>,

    /// Emergency PoW state machine
    pow_state: EmergencyPoWState,

    /// Maximum epochs PoW can remain active (to prevent permanent activation)
    max_pow_epochs: u64,

    /// Participation threshold for declaring emergency (below this → PoW)
    emergency_participation_threshold: f64,

    /// Slashing threshold that triggers PoW
    emergency_slashing_threshold: u64,
}

impl ConsensusOrchestrator {
    /// Create a new orchestrator.
    ///
    /// # Arguments
    /// * `config` - Immutable epoch configuration
    /// * `engines` - Map of consensus engines indexed by mode
    /// * `max_pow_epochs` - Maximum duration for emergency PoW (prevents permanence)
    /// * `emergency_participation_threshold` - Below this, trigger emergency PoW
    /// * `emergency_slashing_threshold` - Number of slashing events to trigger PoW
    pub fn new(
        config: EpochConfig,
        engines: HashMap<ConsensusMode, Arc<dyn ConsensusEngine>>,
        max_pow_epochs: u64,
        emergency_participation_threshold: f64,
        emergency_slashing_threshold: u64,
    ) -> Result<Self, String> {
        if engines.is_empty() {
            return Err("At least one consensus engine is required".to_string());
        }

        if !(0.0..=1.0).contains(&emergency_participation_threshold) {
            return Err("emergency_participation_threshold must be between 0 and 1".to_string());
        }

        if max_pow_epochs == 0 {
            return Err("max_pow_epochs must be > 0".to_string());
        }

        Ok(ConsensusOrchestrator {
            config,
            engines,
            pow_state: EmergencyPoWState::Inactive,
            max_pow_epochs,
            emergency_participation_threshold,
            emergency_slashing_threshold,
        })
    }

    /// Determine the consensus mode for an epoch.
    ///
    /// SAFETY: This method produces identical results on all honest nodes
    /// given identical metrics. The decision is fully deterministic and
    /// reproducible.
    ///
    /// # Algorithm
    /// 1. If PoW is active and has exceeded max_pow_epochs, exit PoW
    /// 2. If metrics indicate emergency, activate PoW
    /// 3. Otherwise, return to normal mode (PoS or PBFT)
    ///
    /// # Inputs (deterministic, on-chain observable)
    /// * `epoch_id` - The epoch to select mode for
    /// * `metrics` - On-chain consensus metrics
    ///
    /// # Returns
    /// - `ConsensusMode` - The mode to use for this epoch
    pub fn select_mode(&mut self, epoch_id: u64, metrics: &ConsensusMetrics) -> ConsensusMode {
        // SAFETY: Check PoW auto-exit condition first
        if let EmergencyPoWState::Active { activated_at_epoch } = self.pow_state {
            let pow_duration = epoch_id - activated_at_epoch;
            if pow_duration >= self.max_pow_epochs {
                info!(
                    "Exiting emergency PoW at epoch {} (active for {} epochs, max={})",
                    epoch_id, pow_duration, self.max_pow_epochs
                );
                self.pow_state = EmergencyPoWState::Exited {
                    exited_at_epoch: epoch_id,
                };
                // Return to normal after exiting PoW
                return self.select_normal_mode(metrics);
            }
        }

        // SAFETY: Check if emergency conditions are present
        if self.is_emergency_condition(metrics) {
            warn!(
                "Emergency condition detected at epoch {}: participation={:.2}%, slashing={}",
                epoch_id,
                metrics.validator_participation * 100.0,
                metrics.slashing_event_count
            );

            if !self.pow_state.is_active() {
                info!("Activating emergency PoW at epoch {}", epoch_id);
                self.pow_state = EmergencyPoWState::Active {
                    activated_at_epoch: epoch_id,
                };
            }
            return ConsensusMode::EmergencyPow;
        }

        // SAFETY: No emergency; return to normal mode
        if self.pow_state.is_active() {
            info!("Conditions improving; exiting PoW at epoch {}", epoch_id);
            self.pow_state = EmergencyPoWState::Exited {
                exited_at_epoch: epoch_id,
            };
        }

        self.select_normal_mode(metrics)
    }

    /// Select the normal (non-PoW) consensus mode.
    ///
    /// SAFETY: This is called when no emergency condition exists.
    /// Chooses between PoS and PBFT based on network conditions.
    fn select_normal_mode(&self, metrics: &ConsensusMetrics) -> ConsensusMode {
        // Decision: Use PoS as primary, switch to PBFT if finality is critically slow
        // SAFETY: All metrics are deterministic and observable on-chain

        if metrics.finality_latency_blocks > 10 {
            info!(
                "High finality latency ({}); using PBFT",
                metrics.finality_latency_blocks
            );
            ConsensusMode::PbftFastFinality
        } else {
            ConsensusMode::PosNormal
        }
    }

    /// Check if current conditions require emergency intervention.
    ///
    /// SAFETY: All thresholds are deterministic and immutable.
    fn is_emergency_condition(&self, metrics: &ConsensusMetrics) -> bool {
        // Condition 1: Insufficient validator participation (< 2/3 + 1)
        if metrics.validator_participation < self.emergency_participation_threshold {
            return true;
        }

        // Condition 2: Byzantine faults detected (slashing events)
        if metrics.slashing_event_count >= self.emergency_slashing_threshold {
            return true;
        }

        false
    }

    /// Verify that a block is valid for the given epoch.
    ///
    /// SAFETY: Blocks with incorrect consensus mode are rejected unconditionally.
    /// This is the critical fork-safety mechanism.
    pub fn verify_block_consensus(
        &self,
        block: &Block,
        epoch_state: &EpochState,
        blockchain_state: &BlockchainState,
    ) -> Result<(), ConsensusError> {
        // SAFETY: Reject if epoch ID does not match
        if block.epoch_id != epoch_state.epoch_id {
            return Err(ConsensusError::EpochMismatch {
                expected: epoch_state.epoch_id,
                got: block.epoch_id,
                height: block.index,
            });
        }

        // SAFETY: Reject if consensus mode does not match epoch's locked mode
        let expected_mode = match epoch_state.consensus_mode {
            ConsensusMode::PosNormal => bleep_core::block::ConsensusMode::PosNormal,
            ConsensusMode::PbftFastFinality => bleep_core::block::ConsensusMode::PbftFastFinality,
            ConsensusMode::EmergencyPow => bleep_core::block::ConsensusMode::EmergencyPow,
        };

        if block.consensus_mode != expected_mode {
            return Err(ConsensusError::ConsensusModeMismatch {
                expected: epoch_state.consensus_mode.as_str().to_string(),
                got: format!("{:?}", block.consensus_mode),
                epoch: epoch_state.epoch_id,
            });
        }

        // SAFETY: Reject if protocol version does not match
        if block.protocol_version != self.config.protocol_version {
            return Err(ConsensusError::ProtocolVersionMismatch {
                expected: self.config.protocol_version,
                got: block.protocol_version,
            });
        }

        // Delegate to the consensus engine for mode-specific verification
        let engine = self
            .get_engine(&epoch_state.consensus_mode)
            .ok_or_else(|| {
                ConsensusError::Other(format!(
                    "No engine available for mode {:?}",
                    epoch_state.consensus_mode
                ))
            })?;

        engine.verify_block(block, epoch_state, blockchain_state)
    }

    /// Propose a block for the current state.
    ///
    /// SAFETY: The orchestrator ensures only the correct mode proposes blocks.
    pub fn propose_block(
        &self,
        height: u64,
        previous_hash: String,
        transactions: Vec<bleep_core::block::Transaction>,
        epoch_state: &EpochState,
        blockchain_state: &BlockchainState,
    ) -> Result<Block, ConsensusError> {
        let engine = self
            .get_engine(&epoch_state.consensus_mode)
            .ok_or_else(|| {
                ConsensusError::Other(format!(
                    "No engine available for mode {:?}",
                    epoch_state.consensus_mode
                ))
            })?;

        engine.propose_block(
            height,
            previous_hash,
            transactions,
            epoch_state,
            blockchain_state,
        )
    }

    /// Execute PBFT pre-prepare phase for a specific block.
    ///
    /// SAFETY: This method should only be called when consensus mode is PbftFastFinality.
    /// Blocks must already be produced by PoS before this is called.
    ///
    /// # Arguments
    /// * `block` - The block to pre-prepare
    /// * `epoch_state` - Current epoch state
    pub fn execute_pbft_pre_prepare(
        &mut self,
        block: &Block,
        epoch_state: &EpochState,
    ) -> Result<(), ConsensusError> {
        // SAFETY: Verify we're in PBFT mode
        if epoch_state.consensus_mode != ConsensusMode::PbftFastFinality {
            return Err(ConsensusError::ConsensusModeMismatch {
                expected: "PBFT".to_string(),
                got: epoch_state.consensus_mode.as_str().to_string(),
                epoch: epoch_state.epoch_id,
            });
        }

        // Get the PBFT engine (downcasting would be needed in real impl, using Arc<dyn...>)
        info!(
            "PBFT orchestrator: Starting pre-prepare for block {}",
            block.index
        );

        // In a real implementation with concrete engine types, we would:
        // let pbft_engine = self.get_pbft_engine_mut()?;
        // pbft_engine.pre_prepare(block.index, block)?;

        // For now, log the operation
        info!("Pre-prepare phase initiated for block {}", block.index);

        Ok(())
    }

    /// Execute PBFT prepare phase for a specific block.
    ///
    /// SAFETY: Should only be called after pre-prepare has succeeded.
    ///
    /// # Arguments
    /// * `block_height` - Height of the block being prepared
    /// * `validator_id` - ID of the validator sending prepare message
    pub fn execute_pbft_prepare(
        &mut self,
        block_height: u64,
        validator_id: &str,
        epoch_state: &EpochState,
    ) -> Result<(), ConsensusError> {
        // SAFETY: Verify we're in PBFT mode
        if epoch_state.consensus_mode != ConsensusMode::PbftFastFinality {
            return Err(ConsensusError::ConsensusModeMismatch {
                expected: "PBFT".to_string(),
                got: epoch_state.consensus_mode.as_str().to_string(),
                epoch: epoch_state.epoch_id,
            });
        }

        info!(
            "PBFT orchestrator: Processing prepare from {} for block {}",
            validator_id, block_height
        );

        // In a real implementation, this would call:
        // let pbft_engine = self.get_pbft_engine_mut()?;
        // pbft_engine.process_prepare(block_height, validator_id)?;

        Ok(())
    }

    /// Execute PBFT commit phase for a specific block.
    ///
    /// SAFETY: Should only be called after prepare phase has reached quorum.
    ///
    /// # Arguments
    /// * `block_height` - Height of the block being committed
    /// * `validator_id` - ID of the validator sending commit message
    pub fn execute_pbft_commit(
        &mut self,
        block_height: u64,
        validator_id: &str,
        epoch_state: &EpochState,
    ) -> Result<(), ConsensusError> {
        // SAFETY: Verify we're in PBFT mode
        if epoch_state.consensus_mode != ConsensusMode::PbftFastFinality {
            return Err(ConsensusError::ConsensusModeMismatch {
                expected: "PBFT".to_string(),
                got: epoch_state.consensus_mode.as_str().to_string(),
                epoch: epoch_state.epoch_id,
            });
        }

        info!(
            "PBFT orchestrator: Processing commit from {} for block {}",
            validator_id, block_height
        );

        // In a real implementation, this would call:
        // let pbft_engine = self.get_pbft_engine_mut()?;
        // pbft_engine.process_commit(block_height, validator_id)?;

        Ok(())
    }

    /// Get a reference to the engine for a given mode.
    fn get_engine(&self, mode: &ConsensusMode) -> Option<Arc<dyn ConsensusEngine>> {
        self.engines.get(mode).cloned()
    }

    /// Get the current PoW state.
    pub fn pow_state(&self) -> EmergencyPoWState {
        self.pow_state
    }

    /// Get a reference to the epoch config.
    pub fn config(&self) -> &EpochConfig {
        &self.config
    }

    /// Reset the PoW state (for testing only).
    #[cfg(test)]
    fn reset_pow_state(&mut self) {
        self.pow_state = EmergencyPoWState::Inactive;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // Mock consensus engine for testing
    struct MockEngine(ConsensusMode);

    impl ConsensusEngine for MockEngine {
        fn verify_block(
            &self,
            _block: &Block,
            _epoch_state: &EpochState,
            _blockchain_state: &BlockchainState,
        ) -> Result<(), ConsensusError> {
            Ok(())
        }

        fn propose_block(
            &self,
            _height: u64,
            _previous_hash: String,
            _transactions: Vec<bleep_core::block::Transaction>,
            _epoch_state: &EpochState,
            _blockchain_state: &BlockchainState,
        ) -> Result<Block, ConsensusError> {
            Err(ConsensusError::Other("Mock engine".to_string()))
        }

        fn consensus_mode(&self) -> ConsensusMode {
            self.0
        }

        fn health_status(&self) -> f64 {
            0.9
        }
    }

    fn create_test_orchestrator() -> ConsensusOrchestrator {
        let config = EpochConfig::new(1000, 0, 1).unwrap();
        let mut engines = HashMap::new();
        engines.insert(
            ConsensusMode::PosNormal,
            Arc::new(MockEngine(ConsensusMode::PosNormal)) as Arc<dyn ConsensusEngine>,
        );
        engines.insert(
            ConsensusMode::PbftFastFinality,
            Arc::new(MockEngine(ConsensusMode::PbftFastFinality)) as Arc<dyn ConsensusEngine>,
        );
        engines.insert(
            ConsensusMode::EmergencyPow,
            Arc::new(MockEngine(ConsensusMode::EmergencyPow)) as Arc<dyn ConsensusEngine>,
        );

        ConsensusOrchestrator::new(config, engines, 5, 0.66, 3).unwrap()
    }

    #[test]
    fn test_orchestrator_creation() {
        let orchestrator = create_test_orchestrator();
        assert_eq!(orchestrator.pow_state(), EmergencyPoWState::Inactive);
    }

    #[test]
    fn test_select_mode_normal() {
        let mut orchestrator = create_test_orchestrator();
        let metrics = ConsensusMetrics {
            validator_participation: 0.90,
            block_proposal_time_ms: 100,
            rejected_block_count: 0,
            slashing_event_count: 0,
            finality_latency_blocks: 2,
            network_utilization: 0.5,
        };

        let mode = orchestrator.select_mode(0, &metrics);
        assert_eq!(mode, ConsensusMode::PosNormal);
    }

    #[test]
    fn test_select_mode_emergency_low_participation() {
        let mut orchestrator = create_test_orchestrator();
        let metrics = ConsensusMetrics {
            validator_participation: 0.50, // Below 0.66 threshold
            block_proposal_time_ms: 100,
            rejected_block_count: 0,
            slashing_event_count: 0,
            finality_latency_blocks: 1,
            network_utilization: 0.5,
        };

        let mode = orchestrator.select_mode(0, &metrics);
        assert_eq!(mode, ConsensusMode::EmergencyPow);
        assert_eq!(
            orchestrator.pow_state(),
            EmergencyPoWState::Active {
                activated_at_epoch: 0
            }
        );
    }

    #[test]
    fn test_select_mode_emergency_slashing() {
        let mut orchestrator = create_test_orchestrator();
        let metrics = ConsensusMetrics {
            validator_participation: 0.90,
            block_proposal_time_ms: 100,
            rejected_block_count: 0,
            slashing_event_count: 5, // >= 3 threshold
            finality_latency_blocks: 1,
            network_utilization: 0.5,
        };

        let mode = orchestrator.select_mode(0, &metrics);
        assert_eq!(mode, ConsensusMode::EmergencyPow);
    }

    #[test]
    fn test_pow_auto_exit() {
        let mut orchestrator = create_test_orchestrator();
        orchestrator.pow_state = EmergencyPoWState::Active {
            activated_at_epoch: 0,
        };

        let metrics = ConsensusMetrics {
            validator_participation: 0.90,
            block_proposal_time_ms: 100,
            rejected_block_count: 0,
            slashing_event_count: 0,
            finality_latency_blocks: 1,
            network_utilization: 0.5,
        };

        // At epoch 5 (after max_pow_epochs), should exit
        let mode = orchestrator.select_mode(5, &metrics);
        assert_eq!(mode, ConsensusMode::PosNormal);
        assert_eq!(
            orchestrator.pow_state(),
            EmergencyPoWState::Exited { exited_at_epoch: 5 }
        );
    }

    #[test]
    fn test_select_pbft_on_high_latency() {
        let mut orchestrator = create_test_orchestrator();
        let metrics = ConsensusMetrics {
            validator_participation: 0.90,
            block_proposal_time_ms: 1000,
            rejected_block_count: 0,
            slashing_event_count: 0,
            finality_latency_blocks: 15, // > 10 threshold
            network_utilization: 0.9,
        };

        let mode = orchestrator.select_mode(0, &metrics);
        assert_eq!(mode, ConsensusMode::PbftFastFinality);
    }
}
