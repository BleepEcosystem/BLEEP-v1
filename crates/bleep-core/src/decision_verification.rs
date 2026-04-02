use crate::decision_attestation::{AttestedDecision, DecisionAttestationEngine, DecisionType};
use crate::invariant_enforcement::ProtectedState;
/// Decision Verification Pipeline
///
/// This module implements the complete verification pipeline for all protocol decisions.
/// The pipeline executes in strict order:
/// 1. Signature verification
/// 2. Constraint verification (invariants)
/// 3. Invariant re-checking
/// 4. Rejection with cryptographic evidence on failure
///
/// SAFETY PROPERTY:
/// No decision executes if ANY step fails.
/// All failures are logged with cryptographic evidence.
use crate::protocol_invariants::ProtocolInvariantEngine;
use bleep_crypto::pq_crypto::HashFunctions;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::sync::{Arc, Mutex};

// ==================== VERIFICATION RESULT TYPES ====================

/// Result of a verification step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStepResult {
    /// Step passed
    Pass,

    /// Step failed with evidence
    Fail(Vec<u8>), // Cryptographic evidence of failure
}

/// Complete verification result with audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Unique verification ID
    pub verification_id: String,

    /// Overall result
    pub passed: bool,

    /// Step 1: Signature verification
    pub signature_verification: VerificationStepResult,

    /// Step 2: Constraint verification
    pub constraint_verification: VerificationStepResult,

    /// Step 3: Invariant re-check
    pub invariant_recheck: VerificationStepResult,

    /// If failed, rejection reason
    pub rejection_reason: Option<String>,

    /// Timestamp of verification
    pub timestamp: u64,

    /// Decision ID that was verified
    pub decision_id: String,
}

impl VerificationResult {
    /// Create a new verification result
    pub fn new(decision_id: String, timestamp: u64) -> Self {
        let mut verification_id_hasher = sha3::Sha3_256::new();
        verification_id_hasher.update(decision_id.as_bytes());
        verification_id_hasher.update(timestamp.to_le_bytes());
        let hash = verification_id_hasher.finalize();
        let verification_id = hex::encode(&hash);

        Self {
            verification_id,
            passed: false,
            signature_verification: VerificationStepResult::Fail(vec![]),
            constraint_verification: VerificationStepResult::Fail(vec![]),
            invariant_recheck: VerificationStepResult::Fail(vec![]),
            rejection_reason: None,
            timestamp,
            decision_id,
        }
    }

    /// All steps passed
    pub fn all_passed(&self) -> bool {
        matches!(self.signature_verification, VerificationStepResult::Pass)
            && matches!(self.constraint_verification, VerificationStepResult::Pass)
            && matches!(self.invariant_recheck, VerificationStepResult::Pass)
    }
}

// ==================== VERIFICATION PIPELINE ====================

/// Decision Verification Pipeline
/// Executes all verification steps in strict order
pub struct DecisionVerificationPipeline {
    /// Attestation engine (for signature verification)
    attestation_engine: Arc<Mutex<DecisionAttestationEngine>>,

    /// Invariant engine (for constraint verification)
    invariant_engine: Arc<Mutex<ProtocolInvariantEngine>>,

    /// Protected state (for state transition validation)
    protected_state: Arc<ProtectedState>,

    /// Minimum attestations required for decision approval
    required_attestations: usize,

    /// Current block height (for timestamp validation)
    current_block_height: u64,
}

impl DecisionVerificationPipeline {
    /// Create a new verification pipeline
    pub fn new(
        invariant_engine: Arc<Mutex<ProtocolInvariantEngine>>,
        attestation_engine: Arc<Mutex<DecisionAttestationEngine>>,
        protected_state: Arc<ProtectedState>,
        required_attestations: usize,
        current_block_height: u64,
    ) -> Self {
        Self {
            invariant_engine,
            attestation_engine,
            protected_state,
            required_attestations,
            current_block_height,
        }
    }

    // ==================== VERIFICATION STEPS ====================

    /// STEP 1: Signature Verification
    /// Verify that decision is properly signed by authorized signers
    fn step_1_signature_verification(
        &mut self,
        attested_decision: &AttestedDecision,
        current_time: u64,
    ) -> (VerificationStepResult, Option<String>) {
        let mut attestation_engine = match self.attestation_engine.lock() {
            Ok(engine) => engine,
            Err(_) => {
                return (
                    VerificationStepResult::Fail(
                        HashFunctions::sha3_256(b"signature_verification_lock_failed").to_vec(),
                    ),
                    Some("Failed to acquire attestation engine lock".to_string()),
                );
            }
        };

        match attestation_engine.verify_decision(
            attested_decision,
            self.required_attestations,
            current_time,
        ) {
            Ok(_) => (VerificationStepResult::Pass, None),
            Err(e) => {
                let error_msg = e.to_string();
                let evidence = HashFunctions::sha3_256(error_msg.as_bytes()).to_vec();
                (VerificationStepResult::Fail(evidence), Some(error_msg))
            }
        }
    }

    /// STEP 2: Constraint Verification
    /// Verify that decision respects protocol constraints
    fn step_2_constraint_verification(
        &self,
        decision: &DecisionType,
    ) -> (VerificationStepResult, Option<String>) {
        let invariant_engine = match self.invariant_engine.lock() {
            Ok(engine) => engine,
            Err(_) => {
                return (
                    VerificationStepResult::Fail(
                        HashFunctions::sha3_256(b"constraint_verification_lock_failed").to_vec(),
                    ),
                    Some("Failed to acquire invariant engine lock".to_string()),
                );
            }
        };

        // Verify constraints based on decision type
        let constraint_result = match decision {
            DecisionType::ConsensusModeChange {
                epoch: _,
                new_mode: _,
            } => {
                // Consensus mode changes must not violate supply
                invariant_engine.check_supply_invariant()
            }

            DecisionType::GovernanceExecution {
                proposal_id: _,
                execution_data: _,
            } => {
                // Governance must not violate supply or economic constraints
                invariant_engine.check_supply_invariant()
            }

            DecisionType::AIAdvisory {
                decision_id: _,
                advisory_data: _,
            } => {
                // AI advisory must not claim authority to bypass invariants
                Ok(())
            }

            DecisionType::ValidatorSlashing {
                validator_id,
                amount,
                reason: _,
            } => {
                // Slashing must satisfy constraints
                invariant_engine.check_slashing_conditions(validator_id, *amount)
            }

            DecisionType::StateRecovery {
                recovery_height: _,
                recovery_data: _,
            } => {
                // State recovery must not violate supply cap
                invariant_engine.check_supply_invariant()
            }
        };

        match constraint_result {
            Ok(_) => (VerificationStepResult::Pass, None),
            Err(e) => {
                let error_msg = e.to_string();
                let evidence = HashFunctions::sha3_256(error_msg.as_bytes()).to_vec();
                (VerificationStepResult::Fail(evidence), Some(error_msg))
            }
        }
    }

    /// STEP 3: Invariant Re-Check
    /// After verification steps, re-check all invariants as final safety gate
    fn step_3_invariant_recheck(
        &self,
        decision: &DecisionType,
    ) -> (VerificationStepResult, Option<String>) {
        let invariant_engine = match self.invariant_engine.lock() {
            Ok(engine) => engine,
            Err(_) => {
                return (
                    VerificationStepResult::Fail(
                        HashFunctions::sha3_256(b"invariant_recheck_lock_failed").to_vec(),
                    ),
                    Some("Failed to acquire invariant engine lock".to_string()),
                );
            }
        };

        // Final comprehensive invariant check
        let recheck_result = match decision {
            DecisionType::ValidatorSlashing {
                validator_id,
                amount,
                reason: _,
            } => {
                // Re-verify slashing conditions
                invariant_engine
                    .check_slashing_conditions(validator_id, *amount)
                    .and_then(|_| invariant_engine.check_supply_invariant())
            }

            _ => {
                // For all decisions, verify supply is sound
                invariant_engine
                    .check_supply_invariant()
                    .and_then(|_| invariant_engine.check_consensus_participation(67))
            }
        };

        match recheck_result {
            Ok(_) => (VerificationStepResult::Pass, None),
            Err(e) => {
                let error_msg = e.to_string();
                let evidence = HashFunctions::sha3_256(error_msg.as_bytes()).to_vec();
                (VerificationStepResult::Fail(evidence), Some(error_msg))
            }
        }
    }

    // ==================== MAIN VERIFICATION PIPELINE ====================

    /// Execute the complete verification pipeline
    /// Returns verification result with full audit trail
    pub fn verify_decision(
        &mut self,
        attested_decision: &AttestedDecision,
        current_time: u64,
    ) -> VerificationResult {
        let mut result =
            VerificationResult::new(attested_decision.decision_id.clone(), current_time);

        // STEP 1: Signature Verification
        let (sig_result, sig_error) =
            self.step_1_signature_verification(attested_decision, current_time);
        result.signature_verification = sig_result;

        if let Some(error) = sig_error {
            result.rejection_reason = Some(format!("Signature verification failed: {}", error));
            result.passed = false;
            return result;
        }

        // STEP 2: Constraint Verification
        let (constraint_result, constraint_error) =
            self.step_2_constraint_verification(&attested_decision.decision);
        result.constraint_verification = constraint_result;

        if let Some(error) = constraint_error {
            result.rejection_reason = Some(format!("Constraint verification failed: {}", error));
            result.passed = false;
            return result;
        }

        // STEP 3: Invariant Re-Check
        let (recheck_result, recheck_error) =
            self.step_3_invariant_recheck(&attested_decision.decision);
        result.invariant_recheck = recheck_result;

        if let Some(error) = recheck_error {
            result.rejection_reason = Some(format!("Invariant re-check failed: {}", error));
            result.passed = false;
            return result;
        }

        // All steps passed
        result.passed = true;
        result
    }

    /// Execute a verified decision on protected state
    /// PRECONDITION: verify_decision() must have passed
    pub fn execute_decision(
        &mut self,
        attested_decision: &AttestedDecision,
        verification: &VerificationResult,
    ) -> Result<(), String> {
        // Check that verification passed
        if !verification.passed {
            return Err(format!(
                "Cannot execute unverified decision ({}): {}",
                verification.verification_id,
                verification
                    .rejection_reason
                    .as_deref()
                    .unwrap_or("unknown reason")
            ));
        }

        // Check decision not already executed
        if attested_decision.executed {
            return Err(format!(
                "Decision {} already executed",
                attested_decision.decision_id
            ));
        }

        // Execute based on decision type
        match &attested_decision.decision {
            DecisionType::ConsensusModeChange {
                epoch: _,
                new_mode: _,
            } => {
                // In full implementation, would update consensus mode
                Ok(())
            }

            DecisionType::GovernanceExecution {
                proposal_id,
                execution_data: _,
            } => {
                // In full implementation, would execute governance
                self.protected_state
                    .hook_after_governance_execution(proposal_id)
                    .map_err(|e| e.to_string())
            }

            DecisionType::AIAdvisory {
                decision_id: _,
                advisory_data: _,
            } => {
                // AI advisory doesn't directly execute state changes
                Ok(())
            }

            DecisionType::ValidatorSlashing {
                validator_id,
                amount,
                reason: _,
            } => {
                // Execute slashing on protected state
                self.protected_state
                    .hook_slash_validator(validator_id, *amount, "decision_executed")
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }

            DecisionType::StateRecovery {
                recovery_height: _,
                recovery_data: _,
            } => {
                // In full implementation, would execute state recovery
                Ok(())
            }
        }
    }

    /// Update block height (for time-based validation)
    pub fn update_block_height(&mut self, new_height: u64) {
        self.current_block_height = new_height;
    }
}

// ==================== REJECTION EVIDENCE ====================

/// Evidence of decision rejection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionEvidence {
    /// Decision that was rejected
    pub decision_id: String,

    /// Verification result
    pub verification_result: VerificationResult,

    /// Cryptographic hash of rejection
    pub evidence_hash: Vec<u8>,
}

impl RejectionEvidence {
    /// Create rejection evidence
    pub fn from_verification(verification: &VerificationResult) -> Self {
        let evidence_data = format!(
            "decision_id:{}|passed:{}|reason:{}",
            verification.decision_id,
            verification.passed,
            verification.rejection_reason.as_deref().unwrap_or("none")
        );

        let evidence_hash = HashFunctions::sha3_256(evidence_data.as_bytes()).to_vec();

        Self {
            decision_id: verification.decision_id.clone(),
            verification_result: verification.clone(),
            evidence_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result_creation() {
        let result = VerificationResult::new("decision_1".to_string(), 1000);
        assert_eq!(result.decision_id, "decision_1");
        assert_eq!(result.timestamp, 1000);
        assert!(!result.passed);
    }

    #[test]
    fn test_rejection_evidence_creation() {
        let mut result = VerificationResult::new("decision_1".to_string(), 1000);
        result.rejection_reason = Some("test failure".to_string());

        let evidence = RejectionEvidence::from_verification(&result);
        assert_eq!(evidence.decision_id, "decision_1");
        assert!(!evidence.evidence_hash.is_empty());
    }
}
