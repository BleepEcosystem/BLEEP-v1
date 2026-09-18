// PHASE 3: SELF-HEALING ORCHESTRATOR
// Coordinates detection and recovery, implements safety-liveness balance
//
// SAFETY INVARIANTS:
// 1. Detection → Classification → Recovery (atomic pipeline)
// 2. All state changes logged immutably
// 3. No recovery without detection evidence
// 4. All validators execute same recovery (deterministic)
// 5. Safety > Liveness (prefer stall over divergence)
// 6. Recovery actions respect Byzantine thresholds

use crate::incident_detector::{DetectionParams, IncidentDetector, IncidentReport};
use crate::recovery_controller::{
    ProtocolParams, RecoveryController, RecoveryLog, RecoveryPreconditions, RecoveryStatus,
};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OrchestratorState {
    Healthy,
    Degraded,
    Critical,
    Recovering,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingCycle {
    /// Epoch of this cycle
    pub epoch: u64,

    /// State before cycle
    pub state_before: OrchestratorState,

    /// Incidents detected in this cycle
    pub incidents_detected: Vec<IncidentReport>,

    /// Recovery actions executed
    pub recovery_actions: Vec<RecoveryLog>,

    /// State after cycle
    pub state_after: OrchestratorState,

    /// Health score (0-100)
    pub health_score: u64,
}

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("Detection failed: {0}")]
    DetectionFailed(String),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Invalid state transition")]
    InvalidStateTransition,
}

/// Self-healing orchestrator: coordinates detection + recovery
pub struct SelfHealingOrchestrator {
    /// Incident detector
    detector: IncidentDetector,

    /// Recovery controller
    recovery: RecoveryController,

    /// Healing cycle history
    healing_history: Vec<HealingCycle>,

    /// Current orchestrator state
    current_state: OrchestratorState,

    /// Recovery strategy
    strategy: RecoveryStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStrategy {
    /// Automatic recovery enabled
    pub auto_recovery_enabled: bool,

    /// Minimum incidents to trigger recovery
    pub incident_threshold: usize,

    /// Safety mode: prefer stall over divergence
    pub safety_over_liveness: bool,

    /// Maximum concurrent recoveries
    pub max_concurrent_recoveries: usize,
}

impl Default for RecoveryStrategy {
    fn default() -> Self {
        RecoveryStrategy {
            auto_recovery_enabled: true,
            incident_threshold: 1,
            safety_over_liveness: true,
            max_concurrent_recoveries: 1,
        }
    }
}

impl SelfHealingOrchestrator {
    pub fn new(
        detection_params: DetectionParams,
        initial_validators: Vec<String>,
        initial_params: ProtocolParams,
        recovery_preconditions: RecoveryPreconditions,
        strategy: RecoveryStrategy,
    ) -> Self {
        let detector = IncidentDetector::new(detection_params);
        let recovery =
            RecoveryController::new(initial_validators, initial_params, recovery_preconditions);

        SelfHealingOrchestrator {
            detector,
            recovery,
            healing_history: Vec::new(),
            current_state: OrchestratorState::Healthy,
            strategy,
        }
    }

    /// Execute one healing cycle (called at each epoch)
    pub fn execute_cycle(&mut self, epoch: u64) -> Result<HealingCycle, OrchestratorError> {
        let state_before = self.current_state;

        // Phase 1: Detection
        let incidents = self
            .detector
            .check_health(epoch)
            .map_err(|e| OrchestratorError::DetectionFailed(e.to_string()))?;

        // Phase 2: State assessment
        let new_state = self.assess_state(&incidents);

        // Phase 3: Recovery (if enabled and incidents detected)
        let mut recovery_actions = Vec::new();
        if self.strategy.auto_recovery_enabled && !incidents.is_empty() {
            for incident in &incidents {
                match self.recovery.execute_recovery(incident, epoch) {
                    Ok(actions) => {
                        recovery_actions.extend(actions);
                    }
                    Err(e) => {
                        warn!("Recovery failed: {:?}", e);
                        if let Some(action) = incident.proposed_recovery.first() {
                            recovery_actions.push(RecoveryLog {
                                action: *action,
                                execution_epoch: epoch,
                                status: RecoveryStatus::Failed,
                                result: e.to_string(),
                                action_hash: incident.incident_id.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Phase 4: Acknowledge incidents
        for incident in &incidents {
            let _ = self.detector.acknowledge_incident(&incident.incident_id);
        }

        // Phase 5: Transition state
        self.current_state = new_state;

        // Phase 6: Log cycle
        let health_score = self.detector.health_score();
        let cycle = HealingCycle {
            epoch,
            state_before,
            incidents_detected: incidents,
            recovery_actions,
            state_after: new_state,
            health_score,
        };

        self.healing_history.push(cycle.clone());

        // Keep last 1000 cycles
        if self.healing_history.len() > 1000 {
            self.healing_history.remove(0);
        }

        info!(
            "Healing cycle {} completed: {:?} → {:?}",
            epoch, state_before, new_state
        );

        Ok(cycle)
    }

    /// Observe block (called by consensus)
    pub fn observe_block(
        &mut self,
        height: u64,
        epoch: u64,
        proposer: String,
        state_root: Vec<u8>,
    ) {
        self.detector
            .observe_block(height, epoch, proposer, state_root);
    }

    /// Observe finality (called by consensus)
    pub fn observe_finality(
        &mut self,
        finalized_height: u64,
        finalized_epoch: u64,
        finality_epoch: u64,
    ) {
        self.detector
            .observe_finality(finalized_height, finalized_epoch, finality_epoch);
    }

    /// Take state snapshot (called periodically)
    pub fn take_snapshot(
        &mut self,
        epoch: u64,
        state_root: Vec<u8>,
    ) -> Result<(), OrchestratorError> {
        self.recovery
            .take_snapshot(epoch, state_root)
            .map_err(|e| OrchestratorError::RecoveryFailed(e.to_string()))?;
        Ok(())
    }

    /// Assess health based on incidents
    fn assess_state(&self, incidents: &[IncidentReport]) -> OrchestratorState {
        if incidents.is_empty() {
            return OrchestratorState::Healthy;
        }

        // Count critical incidents
        let critical_count = incidents
            .iter()
            .filter(|i| i.severity == crate::incident_detector::IncidentSeverity::Critical)
            .count();

        if critical_count > 0 {
            OrchestratorState::Critical
        } else {
            OrchestratorState::Degraded
        }
    }

    /// Check if chain is healthy
    pub fn is_healthy(&self) -> bool {
        self.current_state == OrchestratorState::Healthy
    }

    /// Get current state
    pub fn get_state(&self) -> OrchestratorState {
        self.current_state
    }

    /// Get recent healing cycles
    pub fn get_healing_history(&self, count: usize) -> Vec<&HealingCycle> {
        self.healing_history
            .iter()
            .rev()
            .take(count)
            .rev()
            .collect()
    }

    /// Get all incidents
    pub fn get_incidents(&self) -> &[IncidentReport] {
        self.detector.get_incidents()
    }

    /// Get recovery log
    pub fn get_recovery_log(&self) -> &[RecoveryLog] {
        self.recovery.get_recovery_log()
    }

    /// Get health score
    pub fn get_health_score(&self) -> u64 {
        self.detector.health_score()
    }

    /// Check if validator is frozen
    pub fn is_validator_frozen(&self, validator_id: &str, current_epoch: u64) -> bool {
        self.recovery
            .is_validator_frozen(validator_id, current_epoch)
    }

    /// Get current validators
    pub fn get_validators(&self) -> &[String] {
        self.recovery.get_validators()
    }

    /// Get protocol parameters
    pub fn get_params(&self) -> &ProtocolParams {
        self.recovery.get_params()
    }

    /// Get the configured recovery strategy.
    pub fn get_strategy(&self) -> &RecoveryStrategy {
        &self.strategy
    }
}

/// Health report: comprehensive system status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    /// Current epoch
    pub current_epoch: u64,

    /// Orchestrator state
    pub orchestrator_state: OrchestratorState,

    /// Health score
    pub health_score: u64,

    /// Active incidents
    pub active_incidents: usize,

    /// Recent recovery actions
    pub recent_recoveries: usize,

    /// Validator count
    pub validator_count: usize,

    /// Status message
    pub status_message: String,
}

impl SelfHealingOrchestrator {
    /// Generate health report
    pub fn generate_health_report(&self, current_epoch: u64) -> HealthReport {
        let active_incidents = self.detector.get_active_incidents().len();
        let recent_recoveries = self
            .recovery
            .get_recovery_log()
            .iter()
            .filter(|log| log.execution_epoch > current_epoch - 10)
            .count();

        let status_message = match self.current_state {
            OrchestratorState::Healthy => "All systems operational".to_string(),
            OrchestratorState::Degraded => format!("{} incidents detected", active_incidents),
            OrchestratorState::Critical => format!("CRITICAL: {} incidents", active_incidents),
            OrchestratorState::Recovering => {
                format!("Executing recovery for {} incidents", active_incidents)
            }
        };

        HealthReport {
            current_epoch,
            orchestrator_state: self.current_state,
            health_score: self.detector.health_score(),
            active_incidents,
            recent_recoveries,
            validator_count: self.recovery.get_validators().len(),
            status_message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident_detector::{DetectionParams, IncidentType};
    use crate::recovery_controller::RecoveryPreconditions;

    #[test]
    fn test_healthy_cycle() {
        let validators = vec![
            "val-1".to_string(),
            "val-2".to_string(),
            "val-3".to_string(),
        ];
        let mut orchestrator = SelfHealingOrchestrator::new(
            DetectionParams::default(),
            validators,
            ProtocolParams::default(),
            RecoveryPreconditions::default(),
            RecoveryStrategy::default(),
        );

        // Record normal block
        orchestrator.observe_block(1, 1, "val-1".to_string(), vec![1, 2, 3]);

        // Record finality
        orchestrator.observe_finality(1, 1, 1);

        // Execute cycle
        let cycle = orchestrator.execute_cycle(2).unwrap();

        assert!(cycle.incidents_detected.is_empty());
        assert_eq!(orchestrator.get_state(), OrchestratorState::Healthy);
    }

    #[test]
    fn test_finality_delay_detection_and_recovery() {
        let validators = vec![
            "val-1".to_string(),
            "val-2".to_string(),
            "val-3".to_string(),
        ];
        let mut orchestrator = SelfHealingOrchestrator::new(
            DetectionParams::default(),
            validators,
            ProtocolParams::default(),
            RecoveryPreconditions::default(),
            RecoveryStrategy::default(),
        );

        // Record finality at epoch 1
        orchestrator.observe_finality(100, 1, 1);

        // Execute cycle at epoch 8 (gap = 7, threshold = 5)
        let cycle = orchestrator.execute_cycle(8).unwrap();

        // Should detect finality delay
        assert!(!cycle.incidents_detected.is_empty());
        assert_eq!(
            cycle.incidents_detected[0].incident_type,
            IncidentType::FinalityDelay
        );
        assert_eq!(orchestrator.get_state(), OrchestratorState::Critical);
    }

    #[test]
    fn test_state_assessment() {
        let validators = vec!["val-1".to_string(), "val-2".to_string()];
        let orchestrator = SelfHealingOrchestrator::new(
            DetectionParams::default(),
            validators,
            ProtocolParams::default(),
            RecoveryPreconditions::default(),
            RecoveryStrategy::default(),
        );

        // No incidents → Healthy
        assert_eq!(orchestrator.assess_state(&[]), OrchestratorState::Healthy);
    }

    #[test]
    fn test_health_report() {
        let validators = vec!["val-1".to_string(), "val-2".to_string()];
        let orchestrator = SelfHealingOrchestrator::new(
            DetectionParams::default(),
            validators,
            ProtocolParams::default(),
            RecoveryPreconditions::default(),
            RecoveryStrategy::default(),
        );

        let report = orchestrator.generate_health_report(10);
        assert_eq!(report.current_epoch, 10);
        assert_eq!(report.orchestrator_state, OrchestratorState::Healthy);
    }

    #[test]
    fn test_snapshot_and_recovery_integration() {
        let validators = vec![
            "val-1".to_string(),
            "val-2".to_string(),
            "val-3".to_string(),
        ];
        let mut orchestrator = SelfHealingOrchestrator::new(
            DetectionParams::default(),
            validators,
            ProtocolParams::default(),
            RecoveryPreconditions::default(),
            RecoveryStrategy::default(),
        );

        // Take snapshot
        let _ = orchestrator.take_snapshot(5, vec![1, 2, 3]);

        // Record finality at epoch 1
        orchestrator.observe_finality(100, 1, 1);

        // Trigger incident at epoch 8
        let cycle = orchestrator.execute_cycle(8).unwrap();

        // Should have detected incident
        assert!(!cycle.incidents_detected.is_empty());
        // Should have attempted recovery
        assert!(!cycle.recovery_actions.is_empty());
    }
}
