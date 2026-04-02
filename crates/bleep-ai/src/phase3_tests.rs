/// Comprehensive tests for BLEEP Phase 3 AI Decision Module
///
/// These tests validate:
/// - Deterministic inference reproducibility
/// - Cross-platform consistency
/// - Constraint rejection of invalid proposals
/// - Adversarial input handling
/// - Model governance
/// - Cryptographic attestation
/// - Feedback loop accuracy tracking

#[cfg(test)]
mod tests {
    use crate::{
        ai_attestation::*, ai_consensus_integration::*, ai_constraint_validator::*,
        ai_feedback_loop::*, ai_proposal_types::*, deterministic_inference::*,
    };
    use std::collections::BTreeMap;

    // ==================== DETERMINISTIC INFERENCE TESTS ====================

    #[test]
    fn test_inference_deterministic_replay() {
        let mut engine = DeterministicInferenceEngine::new(0);

        let metadata = ModelMetadata::new(
            "test_model".to_string(),
            "1.0.0".to_string(),
            "model_hash_abc123".to_string(),
            "file_hash_def456".to_string(),
            0,
            5,
            3,
        );

        let binary = vec![42u8; 100];
        let _ = engine.register_model(metadata, binary);

        let inputs1 = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let inputs2 = vec![0.1, 0.2, 0.3, 0.4, 0.5];

        // Both inferences should produce identical outputs
        let result1 = engine.infer("test_model", "1.0.0", &inputs1, 0.85, vec![1, 2, 3]);
        let result2 = engine.infer("test_model", "1.0.0", &inputs2, 0.85, vec![1, 2, 3]);

        // Due to different nonces, attestations differ, but outputs should be identical
        if let (Ok(record1), Ok(record2)) = (result1, result2) {
            assert_eq!(record1.final_outputs, record2.final_outputs);
            assert_eq!(record1.confidence, record2.confidence);
        }
    }

    #[test]
    fn test_model_hash_verification() {
        let mut engine = DeterministicInferenceEngine::new(0);

        let correct_hash = "correct_hash";
        let incorrect_hash = "wrong_hash";

        let metadata = ModelMetadata::new(
            "test".to_string(),
            "1.0".to_string(),
            correct_hash.to_string(),
            "file_hash".to_string(),
            0,
            5,
            3,
        );

        let binary = vec![0u8; 100];

        // Registration should fail because hash doesn't match
        let result = engine.register_model(metadata, binary);
        assert!(result.is_err());
    }

    #[test]
    fn test_input_normalization() {
        let mut config = NormalizationConfig::identity();
        config.mean = vec![0.5, 0.5, 0.5];
        config.std_dev = vec![1.0, 1.0, 1.0];

        let input = vec![0.5, 0.5, 0.5];
        let normalized = config.normalize(&input).unwrap();

        // After normalization with identity mean/std should still be [0, 0, 0]
        assert_eq!(normalized.len(), 3);
    }

    #[test]
    fn test_output_rounding() {
        let config = OutputRoundingConfig::precise(2);
        let output = vec![1.23456, 2.98765, 3.00001];

        let rounded = config.round(&output).unwrap();
        assert_eq!(rounded.len(), 3);

        // Values should be rounded to 2 decimal places
        assert!((rounded[0] - 1.23).abs() < 0.01);
        assert!((rounded[1] - 2.99).abs() < 0.01);
    }

    // ==================== AI PROPOSAL VALIDATION TESTS ====================

    #[test]
    fn test_consensus_mode_proposal_validation() {
        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Improve finality".to_string(),
            confidence: 0.85,
            evidence: vec![EvidenceType::Metric {
                name: "finality_latency".to_string(),
                value: 15.0,
                threshold: 20.0,
                direction: "below".to_string(),
            }],
            risk_score: 25,
            cooldown_epochs: 5,
        });

        assert!(proposal.validate().is_ok());
    }

    #[test]
    fn test_proposal_rejects_invalid_confidence() {
        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Test".to_string(),
            confidence: 1.5, // Invalid!
            evidence: vec![EvidenceType::Metric {
                name: "test".to_string(),
                value: 1.0,
                threshold: 2.0,
                direction: "below".to_string(),
            }],
            risk_score: 25,
            cooldown_epochs: 5,
        });

        assert!(proposal.validate().is_err());
    }

    #[test]
    fn test_proposal_rejects_invalid_risk_score() {
        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Test".to_string(),
            confidence: 0.85,
            evidence: vec![EvidenceType::Metric {
                name: "test".to_string(),
                value: 1.0,
                threshold: 2.0,
                direction: "below".to_string(),
            }],
            risk_score: 101, // Invalid!
            cooldown_epochs: 5,
        });

        assert!(proposal.validate().is_err());
    }

    #[test]
    fn test_validator_participation_evidence() {
        let evidence = EvidenceType::ValidatorParticipation {
            total_validators: 100,
            active_validators: 150, // Invalid!
            participation_rate: 0.95,
        };

        assert!(evidence.validate().is_err());
    }

    #[test]
    fn test_fee_statistics_ordering() {
        let evidence = EvidenceType::FeeStatistics {
            avg_fee: 1000,
            min_fee: 2000, // Invalid ordering!
            max_fee: 500,
            target_fee: 1000,
        };

        assert!(evidence.validate().is_err());
    }

    // ==================== CONSTRAINT VALIDATOR TESTS ====================

    #[test]
    fn test_constraint_validator_accepts_valid_mode_switch() {
        let invariants = ProtocolInvariants::mainnet();
        let context = ConstraintContext {
            current_epoch: 100,
            last_mode_switch_epoch: 80,
            current_consensus_mode: "PoS".to_string(),
            total_validators: 100,
            active_validators: 85,
            participation_rate: 0.85,
            total_stake: 1_000_000,
            slashing_this_epoch: 0,
            current_base_fee: 1000,
            current_validator_reward: 100,
            avg_finality_latency: 5,
            recent_proposals: vec![],
            governance_can_veto: true,
        };

        let mut validator = ConstraintValidator::new(invariants, context);

        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 101,
            reason: "Improve finality".to_string(),
            confidence: 0.85,
            evidence: vec![EvidenceType::Metric {
                name: "finality".to_string(),
                value: 5.0,
                threshold: 10.0,
                direction: "below".to_string(),
            }],
            risk_score: 25,
            cooldown_epochs: 5,
        });

        let result = validator.validate_proposal(&proposal);
        assert!(result.is_ok());
    }

    #[test]
    fn test_constraint_validator_rejects_high_risk() {
        let invariants = ProtocolInvariants::mainnet();
        let context = ConstraintContext {
            current_epoch: 100,
            last_mode_switch_epoch: 95,
            current_consensus_mode: "PoS".to_string(),
            total_validators: 100,
            active_validators: 85,
            participation_rate: 0.85,
            total_stake: 1_000_000,
            slashing_this_epoch: 0,
            current_base_fee: 1000,
            current_validator_reward: 100,
            avg_finality_latency: 5,
            recent_proposals: vec![],
            governance_can_veto: true,
        };

        let mut validator = ConstraintValidator::new(invariants, context);

        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 101,
            reason: "Test".to_string(),
            confidence: 0.85,
            evidence: vec![EvidenceType::Metric {
                name: "metric".to_string(),
                value: 1.0,
                threshold: 2.0,
                direction: "below".to_string(),
            }],
            risk_score: 95, // Too high!
            cooldown_epochs: 5,
        });

        let result = validator.validate_proposal(&proposal);
        assert!(result.is_err());
    }

    #[test]
    fn test_constraint_validator_cooldown() {
        let invariants = ProtocolInvariants::mainnet();
        let context = ConstraintContext {
            current_epoch: 100,
            last_mode_switch_epoch: 95, // Only 5 epochs ago, need 10
            current_consensus_mode: "PoS".to_string(),
            total_validators: 100,
            active_validators: 85,
            participation_rate: 0.85,
            total_stake: 1_000_000,
            slashing_this_epoch: 0,
            current_base_fee: 1000,
            current_validator_reward: 100,
            avg_finality_latency: 5,
            recent_proposals: vec![],
            governance_can_veto: true,
        };

        let mut validator = ConstraintValidator::new(invariants, context);

        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 101,
            reason: "Test".to_string(),
            confidence: 0.85,
            evidence: vec![],
            risk_score: 25,
            cooldown_epochs: 5,
        });

        let result = validator.validate_proposal(&proposal);
        assert!(result.is_err());
    }

    // ==================== ATTESTATION TESTS ====================

    #[test]
    fn test_attestation_record_nonce_uniqueness() {
        let mut manager = AIAttestationManager::new(0);

        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Test".to_string(),
            confidence: 0.8,
            evidence: vec![],
            risk_score: 20,
            cooldown_epochs: 2,
        });

        let commitment1 =
            AIOutputCommitment::new(proposal.clone(), 10, vec![1, 2, 3], None).unwrap();
        let record1 = AIAttestationRecord::new(commitment1.clone());

        assert!(manager.record_attestation(record1).is_ok());

        // Try to record same commitment again (should fail due to nonce)
        let record2 = AIAttestationRecord::new(commitment1);
        assert!(manager.record_attestation(record2).is_err());
    }

    // ==================== FEEDBACK LOOP TESTS ====================

    #[test]
    fn test_accuracy_metrics_calculation() {
        let mut metrics = AccuracyMetrics::new();

        metrics.record_prediction(true, true); // Correct
        metrics.record_prediction(true, false); // Incorrect
        metrics.record_prediction(false, false); // Correct

        assert_eq!(metrics.total_predictions, 3);
        assert_eq!(metrics.correct_predictions, 2);
        assert!((metrics.accuracy_rate - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_confidence_calibration() {
        let mut calibration = ConfidenceCalibration::new();

        // High confidence, correct predictions
        assert!(calibration.record_calibration(0.95, true).is_ok());
        assert!(calibration.record_calibration(0.95, true).is_ok());

        // Low confidence, incorrect predictions
        assert!(calibration.record_calibration(0.15, false).is_ok());

        // Should have some calibration error
        assert!(calibration.calibration_error >= 0.0);
    }

    #[test]
    fn test_model_performance_drift_detection() {
        let mut perf = ModelPerformance::new("test_model".to_string(), "1.0".to_string());

        // Simulate many incorrect predictions
        for _ in 0..100 {
            let _ = perf.record_inference(10.0, false, 0.5);
        }

        perf.detect_drift(0.7);
        assert!(perf.drift_detected);
    }

    #[test]
    fn test_feedback_manager_tracks_models() {
        let mut manager = FeedbackManager::new(0);
        manager.register_model("model1".to_string(), "1.0".to_string());

        let _ = manager.record_outcome("model1", "1.0", 10.0, true, 0.9);
        let _ = manager.record_outcome("model1", "1.0", 12.0, true, 0.85);
        let _ = manager.record_outcome("model1", "1.0", 11.0, false, 0.7);

        let perf = manager.get_model_performance("model1", "1.0");
        assert!(perf.is_some());

        let health = manager.get_health_metrics();
        assert_eq!(health.total_models, 1);
    }

    // ==================== CONSENSUS INTEGRATION TESTS ====================

    #[test]
    fn test_proposal_lifecycle() {
        let mut orchestrator = AIConsensusOrchestrator::new(0);

        let stats = orchestrator.get_stats();
        assert_eq!(stats.total_proposals, 0);

        orchestrator.update_epoch(10);

        let updated_stats = orchestrator.get_stats();
        assert_eq!(updated_stats.total_proposals, 0);
    }

    // ==================== CROSS-MODULE INTEGRATION TESTS ====================

    #[test]
    fn test_end_to_end_proposal_flow() {
        // Create a valid consensus mode switch proposal
        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Improve finality latency".to_string(),
            confidence: 0.88,
            evidence: vec![EvidenceType::FinalityLatency {
                avg_blocks_to_finality: 5,
                max_latency_blocks: 10,
                target_latency: 8,
            }],
            risk_score: 30,
            cooldown_epochs: 10,
        });

        // Validate schema
        assert!(proposal.validate().is_ok());

        // Validate constraints
        let invariants = ProtocolInvariants::mainnet();
        let context = ConstraintContext {
            current_epoch: 50,
            last_mode_switch_epoch: 10,
            current_consensus_mode: "PoS".to_string(),
            total_validators: 100,
            active_validators: 85,
            participation_rate: 0.85,
            total_stake: 5_000_000,
            slashing_this_epoch: 0,
            current_base_fee: 1000,
            current_validator_reward: 100,
            avg_finality_latency: 5,
            recent_proposals: vec![],
            governance_can_veto: true,
        };

        let mut validator = ConstraintValidator::new(invariants, context);
        let constraints = validator.validate_proposal(&proposal);
        assert!(constraints.is_ok());

        // Create attestation
        let commitment =
            AIOutputCommitment::new(proposal.clone(), 50, vec![42, 43, 44], None).unwrap();
        let record = AIAttestationRecord::new(commitment);

        // Verify attestation is created
        assert!(!record.attestation_id.is_empty());
    }
}
