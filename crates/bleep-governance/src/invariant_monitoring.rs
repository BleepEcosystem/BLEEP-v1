// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// Invariant Monitoring & Rollback Triggers
//
// SAFETY INVARIANTS:
// 1. Invariants are checked continuously
// 2. Invariant violations trigger automatic rollback
// 3. Monitoring is deterministic and identical on all nodes
// 4. All violations are logged immutably
// 5. Thresholds are protocol rules (mutable via governance)
// 6. Emergency rollback is available if monitoring fails

use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InvariantError {
    #[error("Invariant violated: {0}")]
    InvariantViolation(String),

    #[error("Monitoring failed: {0}")]
    MonitoringFailed(String),

    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Type of protocol invariant being monitored
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvariantType {
    /// Network liveness: validators must produce blocks
    Liveness,

    /// Safety: finality must be achieved
    Finality,

    /// State coherence: all shards must agree on state
    StateCoherence,

    /// Validator health: enough active validators
    ValidatorHealth,

    /// Consensus participation: sufficient validator participation
    ConsensusParticipation,

    /// Slashing correctness: slashing events are valid
    SlashingCorrectness,

    /// Checkpoint integrity: checkpoints are valid
    CheckpointIntegrity,

    /// Cross-shard consistency: cross-shard transactions are consistent
    CrossShardConsistency,

    /// AI performance: AI proposals are performing well
    AIPerformance,
}

impl InvariantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            InvariantType::Liveness => "LIVENESS",
            InvariantType::Finality => "FINALITY",
            InvariantType::StateCoherence => "STATE_COHERENCE",
            InvariantType::ValidatorHealth => "VALIDATOR_HEALTH",
            InvariantType::ConsensusParticipation => "CONSENSUS_PARTICIPATION",
            InvariantType::SlashingCorrectness => "SLASHING_CORRECTNESS",
            InvariantType::CheckpointIntegrity => "CHECKPOINT_INTEGRITY",
            InvariantType::CrossShardConsistency => "CROSS_SHARD_CONSISTENCY",
            InvariantType::AIPerformance => "AI_PERFORMANCE",
        }
    }
}

/// Invariant threshold definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantThreshold {
    /// Invariant being monitored
    pub invariant_type: InvariantType,

    /// Threshold value (e.g., minimum percentage)
    pub threshold: f64,

    /// Number of consecutive epochs threshold must be violated
    pub violation_window: u64,

    /// Whether violation triggers automatic rollback
    pub triggers_rollback: bool,

    /// Severity level (informational, warning, critical)
    pub severity: InvariantSeverity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvariantSeverity {
    /// Informational, no action required
    Informational,

    /// Warning, should be monitored
    Warning,

    /// Critical, triggers investigation
    Critical,

    /// Fatal, triggers rollback
    Fatal,
}

impl InvariantThreshold {
    pub fn new(
        invariant_type: InvariantType,
        threshold: f64,
        violation_window: u64,
        triggers_rollback: bool,
        severity: InvariantSeverity,
    ) -> Result<Self, InvariantError> {
        if threshold < 0.0 || threshold > 100.0 {
            return Err(InvariantError::InvalidThreshold(format!(
                "Threshold must be [0, 100], got {}",
                threshold
            )));
        }

        Ok(InvariantThreshold {
            invariant_type,
            threshold,
            violation_window,
            triggers_rollback,
            severity,
        })
    }
}

/// Record of an invariant violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationRecord {
    /// Type of invariant violated
    pub invariant_type: InvariantType,

    /// Epoch when violation occurred
    pub epoch: u64,

    /// Block height when violation detected
    pub block_height: u64,

    /// Actual measured value
    pub measured_value: f64,

    /// Expected threshold
    pub threshold: f64,

    /// Detailed description
    pub description: String,

    /// Whether rollback was triggered
    pub triggered_rollback: bool,

    /// Proposal ID that caused this violation (if applicable)
    pub proposal_id: Option<String>,
}

/// Invariant monitor (per-shard)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantMonitor {
    /// Shard ID
    pub shard_id: u32,

    /// Thresholds being monitored
    pub thresholds: HashMap<String, InvariantThreshold>,

    /// Current violation counts (invariant_type -> violation_count)
    pub violation_counts: HashMap<String, u64>,

    /// History of all violations
    pub violation_history: Vec<ViolationRecord>,

    /// Current epoch
    pub current_epoch: u64,
}

impl InvariantMonitor {
    pub fn new(shard_id: u32) -> Self {
        InvariantMonitor {
            shard_id,
            thresholds: HashMap::new(),
            violation_counts: HashMap::new(),
            violation_history: Vec::new(),
            current_epoch: 0,
        }
    }

    /// Add a threshold to monitor
    pub fn add_threshold(&mut self, threshold: InvariantThreshold) -> Result<(), InvariantError> {
        let key = threshold.invariant_type.as_str().to_string();

        if self.thresholds.contains_key(&key) {
            return Err(InvariantError::InvalidThreshold(format!(
                "Threshold {} already exists",
                key
            )));
        }

        self.thresholds.insert(key, threshold);
        Ok(())
    }

    /// Check a single invariant
    ///
    /// SAFETY: Returns whether invariant is violated and if rollback triggered
    pub fn check_invariant(
        &mut self,
        invariant_type: InvariantType,
        measured_value: f64,
        description: String,
        epoch: u64,
        block_height: u64,
        proposal_id: Option<String>,
    ) -> Result<bool, InvariantError> {
        self.current_epoch = epoch;

        let key = invariant_type.as_str().to_string();
        let threshold = self.thresholds.get(&key).ok_or_else(|| {
            InvariantError::MonitoringFailed(format!("No threshold defined for {}", key))
        })?;

        // Check if value violates threshold
        let is_violated = measured_value < threshold.threshold;

        if is_violated {
            // Increment violation counter
            let count = self.violation_counts.entry(key.clone()).or_insert(0);
            *count += 1;

            // Record violation
            let record = ViolationRecord {
                invariant_type,
                epoch,
                block_height,
                measured_value,
                threshold: threshold.threshold,
                description: description.clone(),
                triggered_rollback: false,
                proposal_id: proposal_id.clone(),
            };

            // Check if rollback should trigger
            let triggers_rollback =
                *count >= threshold.violation_window && threshold.triggers_rollback;

            let mut final_record = record;
            if triggers_rollback {
                final_record.triggered_rollback = true;
                warn!(
                    "INVARIANT VIOLATION TRIGGERS ROLLBACK: {} = {} (threshold {})",
                    key, measured_value, threshold.threshold
                );
            } else {
                match threshold.severity {
                    InvariantSeverity::Informational => {
                        info!(
                            "Invariant warning: {} = {} (threshold {})",
                            key, measured_value, threshold.threshold
                        );
                    }
                    InvariantSeverity::Warning => {
                        warn!(
                            "Invariant warning: {} = {} (threshold {})",
                            key, measured_value, threshold.threshold
                        );
                    }
                    InvariantSeverity::Critical | InvariantSeverity::Fatal => {
                        error!(
                            "INVARIANT VIOLATION: {} = {} (threshold {})",
                            key, measured_value, threshold.threshold
                        );
                    }
                }
            }

            self.violation_history.push(final_record);
            Ok(triggers_rollback)
        } else {
            // Clear violation counter when healthy
            self.violation_counts.insert(key, 0);
            Ok(false)
        }
    }

    /// Perform deterministic invariant health check
    ///
    /// SAFETY: Returns aggregate health status
    pub fn health_status(&self) -> HealthStatus {
        let total_invariants = self.thresholds.len();
        let violated = self
            .violation_counts
            .values()
            .filter(|&count| *count > 0)
            .count();

        let health_percentage = if total_invariants == 0 {
            100.0
        } else {
            ((total_invariants - violated) as f64 / total_invariants as f64) * 100.0
        };

        HealthStatus {
            health_percentage,
            total_invariants: total_invariants as u64,
            violated_count: violated as u64,
            is_healthy: violated == 0,
        }
    }

    /// Reset epoch violations (called at epoch boundary)
    pub fn reset_epoch_violations(&mut self) {
        self.violation_counts.clear();
    }

    /// Get violation history for specific invariant
    pub fn violation_history_for(&self, invariant_type: InvariantType) -> Vec<&ViolationRecord> {
        let key = invariant_type.as_str();
        self.violation_history
            .iter()
            .filter(|r| r.invariant_type.as_str() == key)
            .collect()
    }
}

/// Overall health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health percentage [0, 100]
    pub health_percentage: f64,

    /// Total invariants monitored
    pub total_invariants: u64,

    /// Number of violated invariants
    pub violated_count: u64,

    /// Is system healthy
    pub is_healthy: bool,
}

/// Global invariant monitoring system
pub struct GlobalInvariantMonitor {
    /// Per-shard monitors
    monitors: HashMap<u32, InvariantMonitor>,

    /// Genesis thresholds (default for all shards)
    genesis_thresholds: Vec<InvariantThreshold>,
}

impl GlobalInvariantMonitor {
    pub fn new() -> Self {
        GlobalInvariantMonitor {
            monitors: HashMap::new(),
            genesis_thresholds: vec![
                // Default thresholds for genesis
                InvariantThreshold::new(
                    InvariantType::Liveness,
                    80.0, // At least 80% liveness
                    2,    // 2 consecutive epoch violations
                    true, // Triggers rollback
                    InvariantSeverity::Fatal,
                )
                .unwrap(),
                InvariantThreshold::new(
                    InvariantType::Finality,
                    66.0, // At least 66% finality
                    1,
                    true,
                    InvariantSeverity::Fatal,
                )
                .unwrap(),
                InvariantThreshold::new(
                    InvariantType::ValidatorHealth,
                    75.0, // At least 75% validators healthy
                    3,
                    true,
                    InvariantSeverity::Critical,
                )
                .unwrap(),
                InvariantThreshold::new(
                    InvariantType::ConsensusParticipation,
                    60.0, // At least 60% participation
                    2,
                    false, // Warning only
                    InvariantSeverity::Warning,
                )
                .unwrap(),
                InvariantThreshold::new(
                    InvariantType::AIPerformance,
                    50.0, // AI proposals >= 50% acceptance
                    5,
                    false,
                    InvariantSeverity::Warning,
                )
                .unwrap(),
            ],
        }
    }

    /// Get or create monitor for shard
    pub fn get_or_create_monitor(&mut self, shard_id: u32) -> &mut InvariantMonitor {
        self.monitors.entry(shard_id).or_insert_with(|| {
            let mut monitor = InvariantMonitor::new(shard_id);

            // Add genesis thresholds
            for threshold in &self.genesis_thresholds {
                let _ = monitor.add_threshold(threshold.clone());
            }

            monitor
        })
    }

    /// Get global health across all shards
    pub fn global_health(&self) -> GlobalHealth {
        let mut total_health = 0.0;
        let shard_count = self.monitors.len();

        let mut min_health: f64 = 100.0;
        let mut max_health: f64 = 0.0;
        let mut total_violated = 0u64;

        for monitor in self.monitors.values() {
            let status = monitor.health_status();
            total_health += status.health_percentage;
            min_health = min_health.min(status.health_percentage);
            max_health = max_health.max(status.health_percentage);
            total_violated += status.violated_count;
        }

        let avg_health = if shard_count > 0 {
            total_health / shard_count as f64
        } else {
            100.0
        };

        GlobalHealth {
            average_health: avg_health,
            min_health,
            max_health,
            total_shards: shard_count as u64,
            total_violated_invariants: total_violated,
            is_globally_healthy: avg_health >= 75.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalHealth {
    pub average_health: f64,
    pub min_health: f64,
    pub max_health: f64,
    pub total_shards: u64,
    pub total_violated_invariants: u64,
    pub is_globally_healthy: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invariant_threshold_creation() {
        let threshold = InvariantThreshold::new(
            InvariantType::Liveness,
            80.0,
            2,
            true,
            InvariantSeverity::Fatal,
        )
        .unwrap();

        assert_eq!(threshold.threshold, 80.0);
        assert_eq!(threshold.violation_window, 2);
        assert!(threshold.triggers_rollback);
    }

    #[test]
    fn test_invariant_monitor() {
        let mut monitor = InvariantMonitor::new(0);

        let threshold = InvariantThreshold::new(
            InvariantType::Liveness,
            80.0,
            2,
            true,
            InvariantSeverity::Fatal,
        )
        .unwrap();

        monitor.add_threshold(threshold).unwrap();

        // Check passing invariant
        let violates1 = monitor
            .check_invariant(
                InvariantType::Liveness,
                85.0,
                "Test".to_string(),
                1,
                100,
                None,
            )
            .unwrap();
        assert!(!violates1);

        // Check failing invariant
        let violates2 = monitor
            .check_invariant(
                InvariantType::Liveness,
                70.0,
                "Test".to_string(),
                2,
                200,
                None,
            )
            .unwrap();
        assert!(!violates2); // Not yet at violation window

        // Check second violation
        let violates3 = monitor
            .check_invariant(
                InvariantType::Liveness,
                70.0,
                "Test".to_string(),
                3,
                300,
                None,
            )
            .unwrap();
        assert!(violates3); // Now triggers rollback
    }

    #[test]
    fn test_health_status() {
        let mut monitor = InvariantMonitor::new(0);

        let threshold = InvariantThreshold::new(
            InvariantType::Liveness,
            80.0,
            1,
            false,
            InvariantSeverity::Warning,
        )
        .unwrap();

        monitor.add_threshold(threshold).unwrap();

        let status = monitor.health_status();
        assert!(status.is_healthy);
        assert_eq!(status.total_invariants, 1);
        assert_eq!(status.violated_count, 0);
    }

    #[test]
    fn test_global_invariant_monitor() {
        let mut global_monitor = GlobalInvariantMonitor::new();

        let monitor1 = global_monitor.get_or_create_monitor(0);
        assert_eq!(monitor1.shard_id, 0);

        let monitor2 = global_monitor.get_or_create_monitor(1);
        assert_eq!(monitor2.shard_id, 1);

        let health = global_monitor.global_health();
        assert_eq!(health.total_shards, 2);
        assert!(health.is_globally_healthy);
    }
}
