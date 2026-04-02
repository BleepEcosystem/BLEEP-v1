// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// Safety Constraints Engine - Machine-verifiable safety validation
//
// SAFETY INVARIANTS:
// 1. All constraints are deterministically evaluated
// 2. Validation failures are deterministic and reproducible
// 3. No proposal passes validation without satisfying ALL constraints
// 4. Constraints are applied uniformly to all proposals
// 5. Constraint failures are logged and auditable
// 6. Worst-case scenarios are simulated deterministically

use crate::apip::APIP;
use crate::protocol_rules::ProtocolRuleSet;
use log::info;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SafetyConstraintError {
    #[error("Invariant violation: {0}")]
    InvariantViolation(String),

    #[error("Constraint check failed: {0}")]
    ConstraintCheckFailed(String),

    #[error("Simulation failed: {0}")]
    SimulationFailed(String),

    #[error("Compatibility check failed: {0}")]
    CompatibilityCheckFailed(String),

    #[error("Unknown rule: {0}")]
    UnknownRule(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

impl From<crate::protocol_rules::ProtocolRuleError> for SafetyConstraintError {
    fn from(err: crate::protocol_rules::ProtocolRuleError) -> Self {
        SafetyConstraintError::ValidationError(err.to_string())
    }
}

/// Result of a constraint check
#[derive(Debug, Clone)]
pub struct ConstraintCheckResult {
    /// Whether the constraint passed
    pub passed: bool,

    /// Constraint name
    pub constraint_name: String,

    /// Detailed message
    pub message: String,

    /// Severity if failed (informational, warning, error)
    pub severity: CheckSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckSeverity {
    /// Informational, doesn't fail validation
    Informational,

    /// Warning, should be reviewed but doesn't fail
    Warning,

    /// Hard failure, proposal rejected
    Error,
}

/// Detailed validation report
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// Proposal ID being validated
    pub proposal_id: String,

    /// Whether validation passed overall
    pub is_valid: bool,

    /// Timestamp of validation
    pub validated_at: u64,

    /// All constraint check results
    pub checks: Vec<ConstraintCheckResult>,

    /// Count of passed checks
    pub passed_count: usize,

    /// Count of failed checks
    pub failed_count: usize,

    /// Count of warning checks
    pub warning_count: usize,
}

impl ValidationReport {
    /// Create a new validation report
    pub fn new(proposal_id: String) -> Self {
        ValidationReport {
            proposal_id,
            is_valid: true,
            validated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            checks: Vec::new(),
            passed_count: 0,
            failed_count: 0,
            warning_count: 0,
        }
    }

    /// Add a check result
    pub fn add_check(&mut self, result: ConstraintCheckResult) {
        if result.severity == CheckSeverity::Error && !result.passed {
            self.is_valid = false;
            self.failed_count += 1;
        } else if result.severity == CheckSeverity::Warning {
            self.warning_count += 1;
        } else if result.passed {
            self.passed_count += 1;
        }

        self.checks.push(result);
    }

    /// Generate a human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "ValidationReport {{ proposal_id: {}, valid: {}, passed: {}, failed: {}, warnings: {} }}",
            self.proposal_id, self.is_valid, self.passed_count, self.failed_count, self.warning_count
        )
    }
}

/// Machine-verifiable safety constraints engine
pub struct SafetyConstraintsEngine;

impl SafetyConstraintsEngine {
    /// Validate an A-PIP against all safety constraints
    ///
    /// SAFETY: This performs comprehensive deterministic validation.
    /// All checks must pass for the proposal to be valid.
    pub fn validate_proposal(
        apip: &APIP,
        current_ruleset: &ProtocolRuleSet,
    ) -> Result<ValidationReport, SafetyConstraintError> {
        let mut report = ValidationReport::new(apip.proposal_id.clone());

        // Constraint 1: Basic structural validation
        Self::check_apip_completeness(apip, &mut report);

        // Constraint 2: Rule bounds validation
        Self::check_rule_bounds(apip, current_ruleset, &mut report)?;

        // Constraint 3: Safety bounds validation
        Self::check_safety_bounds(apip, &mut report)?;

        // Constraint 4: Invariant compatibility
        Self::check_invariant_compatibility(apip, current_ruleset, &mut report)?;

        // Constraint 5: Worst-case scenario simulation
        Self::check_worst_case_scenarios(apip, current_ruleset, &mut report)?;

        // Constraint 6: AI confidence thresholds
        Self::check_ai_confidence(apip, current_ruleset, &mut report)?;

        // Constraint 7: Risk level approval threshold
        Self::check_risk_approval_requirements(apip, &mut report);

        // Constraint 8: Epoch validity
        Self::check_epoch_validity(apip, &mut report);

        info!("Proposal validation complete: {}", report.summary());

        Ok(report)
    }

    /// Constraint 1: Check A-PIP completeness and structure
    fn check_apip_completeness(apip: &APIP, report: &mut ValidationReport) {
        let result = ConstraintCheckResult {
            passed: apip.is_complete(),
            constraint_name: "APIP_COMPLETENESS".to_string(),
            message: if apip.is_complete() {
                "All required A-PIP fields are populated".to_string()
            } else {
                "A-PIP is missing required fields".to_string()
            },
            severity: CheckSeverity::Error,
        };
        report.add_check(result);
    }

    /// Constraint 2: Verify all rule changes respect bounds
    fn check_rule_bounds(
        apip: &APIP,
        ruleset: &ProtocolRuleSet,
        report: &mut ValidationReport,
    ) -> Result<(), SafetyConstraintError> {
        for change in &apip.rule_changes {
            let rule = ruleset.get_rule(&change.rule_name).map_err(|e| {
                SafetyConstraintError::UnknownRule(format!(
                    "Failed to get rule {}: {}",
                    change.rule_name, e
                ))
            })?;

            // Check new value is within rule bounds
            let in_bounds = rule.bounds.contains(change.new_value);

            let result = ConstraintCheckResult {
                passed: in_bounds,
                constraint_name: format!("RULE_BOUNDS_{}", change.rule_name),
                message: if in_bounds {
                    format!(
                        "Rule {} new value {} in bounds [{}, {}]",
                        change.rule_name, change.new_value, rule.bounds.min, rule.bounds.max
                    )
                } else {
                    format!(
                        "Rule {} new value {} OUT OF BOUNDS [{}, {}]",
                        change.rule_name, change.new_value, rule.bounds.min, rule.bounds.max
                    )
                },
                severity: CheckSeverity::Error,
            };

            report.add_check(result);
        }

        Ok(())
    }

    /// Constraint 3: Verify safety bounds are respected
    fn check_safety_bounds(
        apip: &APIP,
        report: &mut ValidationReport,
    ) -> Result<(), SafetyConstraintError> {
        for change in &apip.rule_changes {
            if let Some(bounds) = apip.safety_bounds.get(&change.rule_name) {
                let is_safe = bounds.is_safe(change.new_value);

                let result = ConstraintCheckResult {
                    passed: is_safe,
                    constraint_name: format!("SAFETY_BOUNDS_{}", change.rule_name),
                    message: if is_safe {
                        format!(
                            "Rule {} new value {} within safety bounds [{}, {}]",
                            change.rule_name,
                            change.new_value,
                            bounds.absolute_min,
                            bounds.absolute_max
                        )
                    } else {
                        format!(
                            "Rule {} new value {} VIOLATES safety bounds [{}, {}]",
                            change.rule_name,
                            change.new_value,
                            bounds.absolute_min,
                            bounds.absolute_max
                        )
                    },
                    severity: CheckSeverity::Error,
                };

                report.add_check(result);
            }
        }

        Ok(())
    }

    /// Constraint 4: Check compatibility with protocol invariants
    fn check_invariant_compatibility(
        apip: &APIP,
        ruleset: &ProtocolRuleSet,
        report: &mut ValidationReport,
    ) -> Result<(), SafetyConstraintError> {
        // CRITICAL INVARIANT 1: Finality threshold must stay at 67%
        // (This is immutable, so check should always pass if rule is immutable)
        for change in &apip.rule_changes {
            if change.rule_name == "FINALITY_THRESHOLD" {
                let finality_rule = ruleset.get_rule("FINALITY_THRESHOLD")?;
                if !finality_rule.is_mutable {
                    let result = ConstraintCheckResult {
                        passed: false,
                        constraint_name: "INVARIANT_IMMUTABLE_FINALITY".to_string(),
                        message: "Cannot modify immutable FINALITY_THRESHOLD rule".to_string(),
                        severity: CheckSeverity::Error,
                    };
                    report.add_check(result);
                }
            }
        }

        // INVARIANT 2: Validator rotation must be reasonable
        for change in &apip.rule_changes {
            if change.rule_name == "VALIDATOR_ROTATION_CADENCE" {
                let reasonable_rotation = change.new_value <= 100;
                let result = ConstraintCheckResult {
                    passed: reasonable_rotation,
                    constraint_name: "INVARIANT_REASONABLE_ROTATION".to_string(),
                    message: if reasonable_rotation {
                        "Validator rotation cadence is reasonable".to_string()
                    } else {
                        "Validator rotation cadence too long (> 100 epochs)".to_string()
                    },
                    severity: CheckSeverity::Error,
                };
                report.add_check(result);
            }
        }

        // INVARIANT 3: Slashing proportion must be > 0%
        for change in &apip.rule_changes {
            if change.rule_name == "SLASHING_PROPORTION" {
                let non_zero_slashing = change.new_value > 0;
                let result = ConstraintCheckResult {
                    passed: non_zero_slashing,
                    constraint_name: "INVARIANT_NONZERO_SLASHING".to_string(),
                    message: if non_zero_slashing {
                        "Slashing proportion is non-zero".to_string()
                    } else {
                        "Slashing proportion must be > 0%".to_string()
                    },
                    severity: CheckSeverity::Error,
                };
                report.add_check(result);
            }
        }

        Ok(())
    }

    /// Constraint 5: Simulate worst-case scenarios
    fn check_worst_case_scenarios(
        apip: &APIP,
        _ruleset: &ProtocolRuleSet,
        report: &mut ValidationReport,
    ) -> Result<(), SafetyConstraintError> {
        // SCENARIO 1: Shard split threshold affects consensus safety
        // Worst case: if threshold is too low, shards become too small
        // for Byzantine fault tolerance
        for change in &apip.rule_changes {
            if change.rule_name == "SHARD_SPLIT_THRESHOLD" {
                // Minimum viable shard needs ~32 validators for safety
                // At ~100 state bytes per validator record
                let min_safe_threshold = 32 * 100;

                let scenario_passed = change.new_value >= min_safe_threshold as u64;
                let result = ConstraintCheckResult {
                    passed: scenario_passed,
                    constraint_name: "SCENARIO_MIN_SHARD_SIZE".to_string(),
                    message: if scenario_passed {
                        format!(
                            "Shard split threshold {} allows minimum safe shard size",
                            change.new_value
                        )
                    } else {
                        format!(
                            "Shard split threshold {} too low (minimum: {})",
                            change.new_value, min_safe_threshold
                        )
                    },
                    severity: CheckSeverity::Error,
                };
                report.add_check(result);
            }
        }

        // SCENARIO 2: Cross-shard timeout must allow for typical latency
        for change in &apip.rule_changes {
            if change.rule_name == "CROSS_SHARD_TIMEOUT" {
                // At 14.4 seconds per block, 10 blocks = ~144 seconds
                let minimum_timeout_blocks = 10;

                let scenario_passed = change.new_value >= minimum_timeout_blocks;
                let result = ConstraintCheckResult {
                    passed: scenario_passed,
                    constraint_name: "SCENARIO_CROSS_SHARD_LATENCY".to_string(),
                    message: if scenario_passed {
                        format!("Cross-shard timeout {} blocks acceptable", change.new_value)
                    } else {
                        format!(
                            "Cross-shard timeout {} blocks too short (minimum: {})",
                            change.new_value, minimum_timeout_blocks
                        )
                    },
                    severity: CheckSeverity::Error,
                };
                report.add_check(result);
            }
        }

        Ok(())
    }

    /// Constraint 6: Verify AI confidence meets minimum threshold
    fn check_ai_confidence(
        apip: &APIP,
        ruleset: &ProtocolRuleSet,
        report: &mut ValidationReport,
    ) -> Result<(), SafetyConstraintError> {
        let min_confidence = ruleset
            .get_rule_value("AI_PROPOSAL_MIN_CONFIDENCE")
            .map_err(|e| {
                SafetyConstraintError::UnknownRule(format!(
                    "AI_PROPOSAL_MIN_CONFIDENCE not found: {}",
                    e
                ))
            })?;

        let confidence_met = apip.confidence_score >= min_confidence as u8;

        let result = ConstraintCheckResult {
            passed: confidence_met,
            constraint_name: "AI_CONFIDENCE_THRESHOLD".to_string(),
            message: if confidence_met {
                format!(
                    "AI confidence {} meets minimum requirement {}",
                    apip.confidence_score, min_confidence
                )
            } else {
                format!(
                    "AI confidence {} below minimum requirement {}",
                    apip.confidence_score, min_confidence
                )
            },
            severity: CheckSeverity::Error,
        };

        report.add_check(result);
        Ok(())
    }

    /// Constraint 7: Check risk level requires appropriate approval
    fn check_risk_approval_requirements(apip: &APIP, report: &mut ValidationReport) {
        let min_approval = apip.risk_level.min_approval_threshold();

        let result = ConstraintCheckResult {
            passed: true,
            constraint_name: "RISK_APPROVAL_REQUIREMENT".to_string(),
            message: format!(
                "Risk level {} requires {} approval threshold",
                apip.risk_level.as_str(),
                min_approval
            ),
            severity: CheckSeverity::Informational,
        };

        report.add_check(result);
    }

    /// Constraint 8: Check epoch validity
    fn check_epoch_validity(apip: &APIP, report: &mut ValidationReport) {
        let result = ConstraintCheckResult {
            passed: apip.target_epoch > 0,
            constraint_name: "EPOCH_VALIDITY".to_string(),
            message: if apip.target_epoch > 0 {
                format!("Target epoch {} is valid", apip.target_epoch)
            } else {
                "Target epoch must be > 0".to_string()
            },
            severity: CheckSeverity::Error,
        };

        report.add_check(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_rules::{ProtocolRuleSetFactory, RuleBounds};

    #[test]
    fn test_validation_report_creation() {
        let report = ValidationReport::new("APIP-TEST".to_string());
        assert_eq!(report.proposal_id, "APIP-TEST");
        assert!(report.is_valid);
    }

    #[test]
    fn test_constraint_check_result() {
        let result = ConstraintCheckResult {
            passed: true,
            constraint_name: "TEST".to_string(),
            message: "Test passed".to_string(),
            severity: CheckSeverity::Error,
        };

        assert!(result.passed);
    }

    #[test]
    fn test_safety_bounds_validation() {
        let bounds = SafetyBounds::new(100, 1000, 200, 900).unwrap();
        assert!(bounds.is_safe(500));
        assert!(!bounds.is_safe(50));
        assert!(!bounds.is_safe(1500));
    }
}
