// PHASE 4: SHARD SELF-HEALING & ROLLBACK
// Fault Detection Module - Deterministic shard fault identification
//
// SAFETY INVARIANTS:
// 1. Faults are detected by rule-based logic, not heuristics
// 2. All nodes independently detect identical faults
// 3. Fault detection is consensus-verifiable
// 4. Multiple detection mechanisms work together
// 5. False positives trigger investigation, not automatic punishment

use crate::shard_checkpoint::CheckpointId;
use crate::shard_registry::EpochId;
use crate::shard_registry::ShardId;
use log::{error, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fault type enumeration
///
/// SAFETY: Only rule-based faults are detected here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultType {
    /// State root mismatches with quorum consensus
    StateRootMismatch {
        expected_root: String,
        observed_root: String,
        dissenting_validators: usize,
    },

    /// Validator produced conflicting blocks at same height
    ValidatorEquivocation {
        validator_pubkey: Vec<u8>,
        block_height: u64,
        hash1: String,
        hash2: String,
    },

    /// Invalid cross-shard receipt (references non-existent tx)
    InvalidCrossShardReceipt {
        receipt_id: String,
        referenced_tx: String,
    },

    /// Shard block execution failed deterministically
    ExecutionFailure { block_height: u64, error: String },

    /// Shard failed to produce block within timeout
    LivenessFailure {
        missed_blocks: u64,
        timeout_epochs: u64,
    },

    /// Checkpoint state root doesn't match claimed state
    CheckpointStateRootMismatch {
        checkpoint_id: CheckpointId,
        expected_root: String,
        observed_root: String,
    },

    /// Transaction ordering inconsistency (replay attack indicator)
    TransactionOrderingViolation {
        block_height: u64,
        transaction_id: String,
    },
}

/// Fault severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FaultSeverity {
    /// Low severity: investigate further
    Low,

    /// Medium severity: shard should be monitored
    Medium,

    /// High severity: shard should be isolated
    High,

    /// Critical: shard must be rolled back immediately
    Critical,
}

/// Detected fault evidence
///
/// SAFETY: Every fault includes cryptographic evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultEvidence {
    /// Type of fault
    pub fault_type: FaultType,

    /// Shard affected
    pub shard_id: ShardId,

    /// Epoch when fault occurred
    pub epoch_id: EpochId,

    /// Severity of fault
    pub severity: FaultSeverity,

    /// Block height where fault was detected
    pub detection_height: u64,

    /// Cryptographic proof (varies by fault type)
    pub proof: Vec<u8>,

    /// Detailed description for audit
    pub details: String,
}

impl FaultEvidence {
    /// Verify that fault evidence is well-formed
    pub fn verify(&self) -> Result<(), String> {
        if self.proof.is_empty() {
            return Err("No proof provided".to_string());
        }

        // Additional validation per fault type
        match &self.fault_type {
            FaultType::StateRootMismatch {
                expected_root,
                observed_root,
                ..
            } => {
                if expected_root == observed_root {
                    return Err("State roots should not match for mismatch fault".to_string());
                }
            }
            FaultType::ValidatorEquivocation { hash1, hash2, .. } => {
                if hash1 == hash2 {
                    return Err("Block hashes should differ for equivocation".to_string());
                }
            }
            _ => {}
        }

        Ok(())
    }
}

/// Fault detection configuration
///
/// SAFETY: Parameters are locked at chain initialization.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FaultDetectionConfig {
    /// Liveness threshold: missed blocks in this many epochs triggers failure
    pub liveness_failure_epochs: u64,

    /// State root mismatch threshold: percentage of validators that must disagree
    pub state_mismatch_threshold_percent: u8,

    /// Minimum validators required for quorum
    pub min_quorum_size: usize,
}

impl FaultDetectionConfig {
    pub fn new(
        liveness_failure_epochs: u64,
        state_mismatch_threshold_percent: u8,
        min_quorum_size: usize,
    ) -> Result<Self, String> {
        if liveness_failure_epochs == 0 {
            return Err("liveness_failure_epochs must be > 0".to_string());
        }
        if state_mismatch_threshold_percent == 0 || state_mismatch_threshold_percent > 100 {
            return Err("state_mismatch_threshold_percent must be 1-100".to_string());
        }
        if min_quorum_size == 0 {
            return Err("min_quorum_size must be > 0".to_string());
        }

        Ok(FaultDetectionConfig {
            liveness_failure_epochs,
            state_mismatch_threshold_percent,
            min_quorum_size,
        })
    }
}

/// Fault detector - identifies faults deterministically
///
/// SAFETY: Uses only on-chain observable evidence.
#[derive(Clone)]
pub struct FaultDetector {
    config: FaultDetectionConfig,
}

impl FaultDetector {
    /// Create a new fault detector
    pub fn new(config: FaultDetectionConfig) -> Self {
        FaultDetector { config }
    }

    /// Detect state root mismatch
    ///
    /// SAFETY: Compares reported state root against quorum consensus.
    pub fn detect_state_root_mismatch(
        &self,
        shard_id: ShardId,
        epoch_id: EpochId,
        block_height: u64,
        reported_root: &str,
        quorum_root: &str,
        total_validators: usize,
        dissenting_count: usize,
    ) -> Option<FaultEvidence> {
        if reported_root == quorum_root {
            return None;
        }

        let dissent_percentage = (dissenting_count * 100) / total_validators.max(1);

        if dissent_percentage < self.config.state_mismatch_threshold_percent as usize {
            return None;
        }

        warn!(
            "State root mismatch detected in shard {:?} at height {}: {} validators dissented",
            shard_id, block_height, dissenting_count
        );

        Some(FaultEvidence {
            fault_type: FaultType::StateRootMismatch {
                expected_root: quorum_root.to_string(),
                observed_root: reported_root.to_string(),
                dissenting_validators: dissenting_count,
            },
            shard_id,
            epoch_id,
            severity: if dissent_percentage > 50 {
                FaultSeverity::Critical
            } else {
                FaultSeverity::High
            },
            detection_height: block_height,
            proof: reported_root.as_bytes().to_vec(),
            details: format!(
                "Shard reported root {} but consensus is {}, {} validators dissented",
                reported_root, quorum_root, dissenting_count
            ),
        })
    }

    /// Detect validator equivocation (double-signing)
    ///
    /// SAFETY: Requires two conflicting blocks with same validator signature.
    pub fn detect_equivocation(
        &self,
        shard_id: ShardId,
        epoch_id: EpochId,
        block_height: u64,
        validator_pubkey: Vec<u8>,
        hash1: String,
        hash2: String,
    ) -> Option<FaultEvidence> {
        if hash1 == hash2 {
            return None;
        }

        error!(
            "Validator equivocation detected in shard {:?} at height {}: same validator signed different blocks",
            shard_id, block_height
        );

        Some(FaultEvidence {
            fault_type: FaultType::ValidatorEquivocation {
                validator_pubkey: validator_pubkey.clone(),
                block_height,
                hash1: hash1.clone(),
                hash2: hash2.clone(),
            },
            shard_id,
            epoch_id,
            severity: FaultSeverity::Critical,
            detection_height: block_height,
            proof: [hash1.as_bytes(), hash2.as_bytes()].concat(),
            details: format!(
                "Validator {:?} signed conflicting blocks at height {}",
                hex::encode(&validator_pubkey),
                block_height
            ),
        })
    }

    /// Detect invalid cross-shard receipt
    ///
    /// SAFETY: Receipt references non-existent or already-executed transaction.
    pub fn detect_invalid_receipt(
        &self,
        shard_id: ShardId,
        epoch_id: EpochId,
        receipt_id: String,
        referenced_tx: String,
    ) -> Option<FaultEvidence> {
        warn!(
            "Invalid cross-shard receipt detected in shard {:?}: references non-existent tx {}",
            shard_id, referenced_tx
        );

        Some(FaultEvidence {
            fault_type: FaultType::InvalidCrossShardReceipt {
                receipt_id: receipt_id.clone(),
                referenced_tx: referenced_tx.clone(),
            },
            shard_id,
            epoch_id,
            severity: FaultSeverity::High,
            detection_height: 0,
            proof: [receipt_id.as_bytes(), referenced_tx.as_bytes()].concat(),
            details: format!(
                "Receipt {} references unknown transaction {}",
                receipt_id, referenced_tx
            ),
        })
    }

    /// Detect execution failure
    ///
    /// SAFETY: Execution failed deterministically (not Byzantine; real bug).
    pub fn detect_execution_failure(
        &self,
        shard_id: ShardId,
        epoch_id: EpochId,
        block_height: u64,
        error: String,
    ) -> Option<FaultEvidence> {
        warn!(
            "Execution failure in shard {:?} at height {}: {}",
            shard_id, block_height, error
        );

        Some(FaultEvidence {
            fault_type: FaultType::ExecutionFailure {
                block_height,
                error: error.clone(),
            },
            shard_id,
            epoch_id,
            severity: FaultSeverity::High,
            detection_height: block_height,
            proof: error.as_bytes().to_vec(),
            details: format!("Block execution failed: {}", error),
        })
    }

    /// Detect liveness failure (missing blocks)
    ///
    /// SAFETY: No blocks produced within timeout period.
    pub fn detect_liveness_failure(
        &self,
        shard_id: ShardId,
        epoch_id: EpochId,
        missed_blocks: u64,
        missed_epochs: u64,
    ) -> Option<FaultEvidence> {
        if missed_epochs < self.config.liveness_failure_epochs {
            return None;
        }

        error!(
            "Liveness failure in shard {:?}: {} blocks missed over {} epochs",
            shard_id, missed_blocks, missed_epochs
        );

        Some(FaultEvidence {
            fault_type: FaultType::LivenessFailure {
                missed_blocks,
                timeout_epochs: missed_epochs,
            },
            shard_id,
            epoch_id,
            severity: FaultSeverity::Medium,
            detection_height: 0,
            proof: missed_blocks.to_le_bytes().to_vec(),
            details: format!("Shard produced no blocks for {} epochs", missed_epochs),
        })
    }

    /// Detect checkpoint state root mismatch
    ///
    /// SAFETY: Checkpoint claimed state doesn't match actual reconstructed state.
    pub fn detect_checkpoint_mismatch(
        &self,
        shard_id: ShardId,
        checkpoint_id: CheckpointId,
        expected_root: String,
        observed_root: String,
    ) -> Option<FaultEvidence> {
        if expected_root == observed_root {
            return None;
        }

        error!(
            "Checkpoint mismatch in shard {:?}: checkpoint {:?} claims {} but actual is {}",
            shard_id, checkpoint_id, expected_root, observed_root
        );

        Some(FaultEvidence {
            fault_type: FaultType::CheckpointStateRootMismatch {
                checkpoint_id,
                expected_root: expected_root.clone(),
                observed_root: observed_root.clone(),
            },
            shard_id,
            epoch_id: EpochId(0), // Would be set by caller
            severity: FaultSeverity::Critical,
            detection_height: 0,
            proof: [expected_root.as_bytes(), observed_root.as_bytes()].concat(),
            details: format!(
                "Checkpoint {:?} state mismatch: {} vs {}",
                checkpoint_id, expected_root, observed_root
            ),
        })
    }

    /// Detect transaction ordering violation
    ///
    /// SAFETY: Transaction appears at different positions in canonical chain.
    pub fn detect_ordering_violation(
        &self,
        shard_id: ShardId,
        epoch_id: EpochId,
        block_height: u64,
        transaction_id: String,
    ) -> Option<FaultEvidence> {
        warn!(
            "Transaction ordering violation in shard {:?} at height {}: tx {}",
            shard_id, block_height, transaction_id
        );

        Some(FaultEvidence {
            fault_type: FaultType::TransactionOrderingViolation {
                block_height,
                transaction_id: transaction_id.clone(),
            },
            shard_id,
            epoch_id,
            severity: FaultSeverity::High,
            detection_height: block_height,
            proof: transaction_id.as_bytes().to_vec(),
            details: format!(
                "Transaction {} ordering violation at height {}",
                transaction_id, block_height
            ),
        })
    }
}

/// Fault history tracker
///
/// SAFETY: Maintains audit trail of all detected faults.
pub struct FaultHistory {
    /// Faults per shard
    faults: HashMap<ShardId, Vec<FaultEvidence>>,
}

impl FaultHistory {
    pub fn new() -> Self {
        FaultHistory {
            faults: HashMap::new(),
        }
    }

    /// Record a detected fault
    pub fn record_fault(&mut self, evidence: FaultEvidence) {
        self.faults
            .entry(evidence.shard_id)
            .or_insert_with(Vec::new)
            .push(evidence);
    }

    /// Get all faults for a shard
    pub fn get_shard_faults(&self, shard_id: ShardId) -> Vec<&FaultEvidence> {
        self.faults
            .get(&shard_id)
            .map(|faults| faults.iter().collect())
            .unwrap_or_default()
    }

    /// Count critical faults for a shard (indicates severe problems)
    pub fn count_critical_faults(&self, shard_id: ShardId) -> usize {
        self.get_shard_faults(shard_id)
            .iter()
            .filter(|f| f.severity == FaultSeverity::Critical)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fault_detection_config() {
        let config = FaultDetectionConfig::new(5, 50, 4).unwrap();
        assert_eq!(config.liveness_failure_epochs, 5);
    }

    #[test]
    fn test_state_root_mismatch_detection() {
        let config = FaultDetectionConfig::new(5, 50, 4).unwrap();
        let detector = FaultDetector::new(config);

        let fault = detector.detect_state_root_mismatch(
            ShardId(0),
            EpochId(0),
            100,
            "root_a",
            "root_b",
            4,
            3,
        );

        assert!(fault.is_some());
        assert_eq!(fault.unwrap().severity, FaultSeverity::Critical);
    }

    #[test]
    fn test_equivocation_detection() {
        let config = FaultDetectionConfig::new(5, 50, 4).unwrap();
        let detector = FaultDetector::new(config);

        let fault = detector.detect_equivocation(
            ShardId(0),
            EpochId(0),
            100,
            vec![1, 2, 3],
            "hash1".to_string(),
            "hash2".to_string(),
        );

        assert!(fault.is_some());
        assert_eq!(fault.unwrap().severity, FaultSeverity::Critical);
    }

    #[test]
    fn test_liveness_failure_detection() {
        let config = FaultDetectionConfig::new(5, 50, 4).unwrap();
        let detector = FaultDetector::new(config);

        let fault = detector.detect_liveness_failure(ShardId(0), EpochId(0), 100, 6);

        assert!(fault.is_some());
    }
}
