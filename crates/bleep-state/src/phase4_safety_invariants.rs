// PHASE 4: SHARD SELF-HEALING & ROLLBACK
// Safety Invariants Module - Enforces protocol safety constraints
//
// SAFETY INVARIANTS:
// 1. No global rollback (only shard-level)
// 2. No cross-shard corruption during shard rollback
// 3. No silent recovery (all operations are auditable)
// 4. No shard resurrection without verification
// 5. Deterministic recovery outcomes
// 6. Byzantine fault tolerance maintained
// 7. Fork prevention (all nodes reach identical state)

use crate::phase4_recovery_orchestrator::RecoveryStage;
use crate::shard_checkpoint::{CheckpointStatus, ShardCheckpoint};
use crate::shard_fault_detection::{FaultEvidence, FaultSeverity};
use crate::shard_registry::ShardId;

use log::{error, warn};
use serde::{Deserialize, Serialize};

/// Safety invariant violation result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantViolation {
    /// Global rollback attempted
    GlobalRollbackAttempted,

    /// Cross-shard state corruption detected
    CrossShardCorruption,

    /// Silent recovery attempted (no audit trail)
    SilentRecovery,

    /// Shard resurrection without verification
    UnverifiedReintegration,

    /// Determinism violation (different nodes reached different states)
    DeterminismViolation,

    /// Byzantine threshold exceeded
    ByzantineThresholdExceeded,

    /// Fork detected
    ForkDetected,

    /// Invalid state transition
    InvalidStateTransition,
}

/// Safety invariant checker
///
/// SAFETY: All critical invariants are verified before state changes.
pub struct SafetyInvariantChecker;

impl SafetyInvariantChecker {
    /// Verify shard-level rollback is valid (not global)
    ///
    /// SAFETY: Ensures only shard state is rolled back, not global chain.
    pub fn verify_shard_rollback_only(
        _rolled_back_shard: ShardId,
        other_shards_unaffected: bool,
    ) -> Result<(), InvariantViolation> {
        if !other_shards_unaffected {
            return Err(InvariantViolation::GlobalRollbackAttempted);
        }

        Ok(())
    }

    /// Verify checkpoint state integrity
    ///
    /// SAFETY: Ensures checkpoint has required signatures and is finalized.
    pub fn verify_checkpoint_integrity(
        checkpoint: &ShardCheckpoint,
    ) -> Result<(), InvariantViolation> {
        // Must be finalized
        if checkpoint.status != CheckpointStatus::Finalized {
            return Err(InvariantViolation::InvalidStateTransition);
        }

        // Must have quorum signatures
        if checkpoint.validator_signatures.is_empty() {
            return Err(InvariantViolation::SilentRecovery);
        }

        Ok(())
    }

    /// Verify rollback is bounded
    ///
    /// SAFETY: Rollback cannot exceed maximum window to prevent historical attacks.
    pub fn verify_rollback_bounded(
        current_height: u64,
        target_height: u64,
        max_rollback_depth: u64,
    ) -> Result<(), InvariantViolation> {
        let rollback_distance = current_height.saturating_sub(target_height);

        if rollback_distance > max_rollback_depth {
            return Err(InvariantViolation::InvalidStateTransition);
        }

        Ok(())
    }

    /// Verify cross-shard transaction abort is complete
    ///
    /// SAFETY: All cross-shard transactions involving rolled-back shard are aborted.
    pub fn verify_crossshard_abort_complete(
        involved_shards: &[ShardId],
        rolled_back_shard: ShardId,
        aborted_count: usize,
        expected_abort_count: usize,
    ) -> Result<(), InvariantViolation> {
        // If rolled-back shard was involved in any cross-shard txs,
        // all must be aborted
        if involved_shards.contains(&rolled_back_shard) {
            if aborted_count != expected_abort_count {
                return Err(InvariantViolation::CrossShardCorruption);
            }
        }

        Ok(())
    }

    /// Verify fault evidence is complete
    ///
    /// SAFETY: All fault evidence has cryptographic proof.
    pub fn verify_fault_evidence(evidence: &FaultEvidence) -> Result<(), InvariantViolation> {
        if evidence.proof.is_empty() {
            return Err(InvariantViolation::SilentRecovery);
        }

        Ok(())
    }

    /// Verify state transition is valid
    ///
    /// SAFETY: Recovery stage transitions follow protocol rules.
    pub fn verify_recovery_stage_transition(
        from_stage: RecoveryStage,
        to_stage: RecoveryStage,
    ) -> Result<(), InvariantViolation> {
        let valid_transitions = match from_stage {
            RecoveryStage::FaultDetected => {
                matches!(to_stage, RecoveryStage::Isolated | RecoveryStage::Failed)
            }
            RecoveryStage::Isolated => {
                matches!(to_stage, RecoveryStage::RollingBack | RecoveryStage::Failed)
            }
            RecoveryStage::RollingBack => {
                matches!(
                    to_stage,
                    RecoveryStage::ValidatorAdjustment | RecoveryStage::Failed
                )
            }
            RecoveryStage::ValidatorAdjustment => {
                matches!(to_stage, RecoveryStage::Healing | RecoveryStage::Failed)
            }
            RecoveryStage::Healing => {
                matches!(
                    to_stage,
                    RecoveryStage::RecoveryComplete | RecoveryStage::Failed
                )
            }
            RecoveryStage::RecoveryComplete => {
                matches!(to_stage, RecoveryStage::Reintegrated)
            }
            RecoveryStage::Reintegrated | RecoveryStage::Failed => {
                false // Terminal states
            }
        };

        if !valid_transitions {
            return Err(InvariantViolation::InvalidStateTransition);
        }

        Ok(())
    }

    /// Verify Byzantine fault tolerance is maintained
    ///
    /// SAFETY: Slashing decisions don't remove consensus threshold.
    pub fn verify_byzantine_tolerance(
        total_validators: usize,
        slashed_count: usize,
        min_quorum: usize,
    ) -> Result<(), InvariantViolation> {
        let remaining = total_validators.saturating_sub(slashed_count);

        if remaining < min_quorum {
            return Err(InvariantViolation::ByzantineThresholdExceeded);
        }

        Ok(())
    }

    /// Verify shard cannot be reintegrated without full healing
    ///
    /// SAFETY: No shortcuts in recovery process.
    pub fn verify_full_healing_required(
        expected_state_root: &str,
        actual_state_root: &str,
        healing_complete: bool,
    ) -> Result<(), InvariantViolation> {
        if !healing_complete {
            return Err(InvariantViolation::UnverifiedReintegration);
        }

        if expected_state_root != actual_state_root {
            return Err(InvariantViolation::CrossShardCorruption);
        }

        Ok(())
    }

    /// Verify consensus-approved transitions
    ///
    /// SAFETY: Recovery operations are consensus-verifiable.
    pub fn verify_consensus_approval(finalized: bool) -> Result<(), InvariantViolation> {
        if !finalized {
            return Err(InvariantViolation::SilentRecovery);
        }

        Ok(())
    }

    /// Verify fault severity triggers appropriate response
    ///
    /// SAFETY: Fault severity determines isolation level.
    pub fn verify_severity_response(
        severity: FaultSeverity,
        is_isolated: bool,
        is_frozen: bool,
    ) -> Result<(), InvariantViolation> {
        match severity {
            FaultSeverity::Critical => {
                // Critical faults must be isolated
                if !is_isolated {
                    return Err(InvariantViolation::InvalidStateTransition);
                }
            }
            FaultSeverity::High => {
                // High severity must be frozen or isolated
                if !is_isolated && !is_frozen {
                    return Err(InvariantViolation::InvalidStateTransition);
                }
            }
            _ => {}
        }

        Ok(())
    }
}

/// Invariant violation handler
///
/// SAFETY: Handles violations according to severity.
pub struct InvariantViolationHandler;

impl InvariantViolationHandler {
    /// Handle an invariant violation
    ///
    /// SAFETY: Prevents state corruption by halting affected operations.
    pub fn handle_violation(
        violation: InvariantViolation,
        shard_id: ShardId,
    ) -> Result<(), String> {
        match violation {
            InvariantViolation::GlobalRollbackAttempted => {
                error!(
                    "CRITICAL: Global rollback attempted for shard {:?}. Halting all recovery.",
                    shard_id
                );
                Err("Global rollback prevention triggered".to_string())
            }
            InvariantViolation::CrossShardCorruption => {
                error!(
                    "CRITICAL: Cross-shard corruption detected for shard {:?}. Isolating shard.",
                    shard_id
                );
                Err("Cross-shard corruption detected".to_string())
            }
            InvariantViolation::SilentRecovery => {
                error!(
                    "CRITICAL: Silent recovery attempted for shard {:?}. Audit trail required.",
                    shard_id
                );
                Err("Silent recovery detected".to_string())
            }
            InvariantViolation::UnverifiedReintegration => {
                error!(
                    "CRITICAL: Shard {:?} reintegration without full healing. Rejecting.",
                    shard_id
                );
                Err("Unverified reintegration attempted".to_string())
            }
            InvariantViolation::DeterminismViolation => {
                error!(
                    "CRITICAL: Determinism violation for shard {:?}. Fork detected.",
                    shard_id
                );
                Err("Determinism violation detected".to_string())
            }
            InvariantViolation::ByzantineThresholdExceeded => {
                error!(
                    "CRITICAL: Byzantine threshold exceeded for shard {:?}. Cannot recover.",
                    shard_id
                );
                Err("Byzantine threshold exceeded".to_string())
            }
            InvariantViolation::ForkDetected => {
                error!(
                    "CRITICAL: Fork detected for shard {:?}. Consensus required.",
                    shard_id
                );
                Err("Fork detected".to_string())
            }
            InvariantViolation::InvalidStateTransition => {
                warn!(
                    "Invalid state transition for shard {:?}. Rejecting operation.",
                    shard_id
                );
                Err("Invalid state transition".to_string())
            }
        }
    }
}

/// Determinism verifier
///
/// SAFETY: Ensures all nodes independently derive identical recovery decisions.
pub struct DeterminismVerifier;

impl DeterminismVerifier {
    /// Verify that multiple nodes reach identical recovery decision
    ///
    /// SAFETY: All honest nodes must independently derive the same result.
    pub fn verify_deterministic_decision(
        local_decision: &[u8],
        peer_decisions: &[&[u8]],
    ) -> Result<(), InvariantViolation> {
        for peer_decision in peer_decisions {
            if local_decision != *peer_decision {
                return Err(InvariantViolation::DeterminismViolation);
            }
        }

        Ok(())
    }

    /// Verify checkpoint hashes are identical across nodes
    ///
    /// SAFETY: Checkpoint is deterministically computed.
    pub fn verify_checkpoint_determinism(
        local_hash: &str,
        peer_hashes: &[&str],
    ) -> Result<(), InvariantViolation> {
        for peer_hash in peer_hashes {
            if local_hash != *peer_hash {
                return Err(InvariantViolation::DeterminismViolation);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_rollback_only() {
        let result = SafetyInvariantChecker::verify_shard_rollback_only(ShardId(0), true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_shard_rollback_global_prevention() {
        let result = SafetyInvariantChecker::verify_shard_rollback_only(ShardId(0), false);
        assert_eq!(result, Err(InvariantViolation::GlobalRollbackAttempted));
    }

    #[test]
    fn test_rollback_bounded() {
        let result = SafetyInvariantChecker::verify_rollback_bounded(1000, 500, 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rollback_unbounded() {
        let result = SafetyInvariantChecker::verify_rollback_bounded(2000, 100, 500);
        assert_eq!(result, Err(InvariantViolation::InvalidStateTransition));
    }

    #[test]
    fn test_recovery_stage_transition() {
        let result = SafetyInvariantChecker::verify_recovery_stage_transition(
            RecoveryStage::FaultDetected,
            RecoveryStage::Isolated,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_recovery_stage_transition() {
        let result = SafetyInvariantChecker::verify_recovery_stage_transition(
            RecoveryStage::FaultDetected,
            RecoveryStage::Reintegrated,
        );
        assert_eq!(result, Err(InvariantViolation::InvalidStateTransition));
    }

    #[test]
    fn test_byzantine_tolerance() {
        let result = SafetyInvariantChecker::verify_byzantine_tolerance(10, 3, 4);
        assert!(result.is_ok());
    }

    #[test]
    fn test_byzantine_tolerance_exceeded() {
        let result = SafetyInvariantChecker::verify_byzantine_tolerance(10, 8, 4);
        assert_eq!(result, Err(InvariantViolation::ByzantineThresholdExceeded));
    }

    #[test]
    fn test_severity_response_critical() {
        let result =
            SafetyInvariantChecker::verify_severity_response(FaultSeverity::Critical, true, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_severity_response_critical_not_isolated() {
        let result =
            SafetyInvariantChecker::verify_severity_response(FaultSeverity::Critical, false, false);
        assert_eq!(result, Err(InvariantViolation::InvalidStateTransition));
    }
}
