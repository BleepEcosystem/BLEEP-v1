/// Unit tests for Phase 3 AI modules that don't depend on bleep-core
/// These tests validate core functionality in isolation

#[cfg(test)]
mod phase3_unit_tests {
    use crate::{
        ai_attestation::*, ai_constraint_validator::*, ai_feedback_loop::*, ai_proposal_types::*,
        deterministic_inference::*,
    };

    // ==================== DETERMINISTIC INFERENCE TESTS ====================

    #[test]
    fn test_output_rounding_precision() {
        let config = OutputRoundingConfig::precise(2);
        let output = vec![1.23456, 2.98765, 3.00001];

        let rounded = config.round(&output).unwrap();
        assert_eq!(rounded.len(), 3);
        // Values should be rounded to 2 decimal places
        assert!((rounded[0] - 1.23).abs() < 0.01);
        assert!((rounded[1] - 2.99).abs() < 0.01);
    }

    #[test]
    fn test_normalization_identity() {
        let config = NormalizationConfig::identity();
        let input = vec![0.5, 0.5, 0.5];
        let normalized = config.normalize(&input).unwrap();
        assert_eq!(normalized.len(), 3);
    }

    #[test]
    fn test_model_metadata_creation() {
        let metadata = ModelMetadata::new(
            "test_model".to_string(),
            "1.0.0".to_string(),
            "model_hash".to_string(),
            "file_hash".to_string(),
            0,
            5,
            3,
        );

        assert_eq!(metadata.model_name, "test_model");
        assert_eq!(metadata.version, "1.0.0");
    }

    // ==================== AI PROPOSAL VALIDATION TESTS ====================

    #[test]
    fn test_consensus_mode_proposal_valid() {
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
    fn test_proposal_confidence_bounds() {
        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Test".to_string(),
            confidence: 1.5, // Invalid: must be [0.0, 1.0]
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
    fn test_proposal_risk_score_bounds() {
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
            risk_score: 101, // Invalid: must be [0, 100]
            cooldown_epochs: 5,
        });

        assert!(proposal.validate().is_err());
    }

    #[test]
    fn test_shard_rollback_proposal() {
        let proposal = AIProposal::ShardRollback(ShardRollbackProposal {
            shard_id: 1,
            target_height: 1000,
            reason: "Byzantine event detected".to_string(),
            confidence: 0.92,
            evidence: vec![EvidenceType::FaultCount {
                fault_type: "byzantine".to_string(),
                count: 3,
                threshold: 2,
            }],
            risk_score: 45,
            rollback_duration_epochs: 10,
        });

        assert!(proposal.validate().is_ok());
    }

    #[test]
    fn test_tokenomics_proposal() {
        let proposal = AIProposal::TokenomicsAdjustment(TokenomicsProposal {
            new_base_fee: 1500,
            new_validator_reward: 125,
            reason: "Market adjustment".to_string(),
            confidence: 0.78,
            evidence: vec![EvidenceType::FeeStatistics {
                avg_fee: 1200,
                min_fee: 800,
                max_fee: 2000,
                target_fee: 1500,
            }],
            risk_score: 20,
        });

        assert!(proposal.validate().is_ok());
    }

    #[test]
    fn test_validator_participation_evidence_valid() {
        let evidence = EvidenceType::ValidatorParticipation {
            total_validators: 100,
            active_validators: 85,
            participation_rate: 0.85,
        };

        assert!(evidence.validate().is_ok());
    }

    #[test]
    fn test_validator_participation_evidence_invalid() {
        let evidence = EvidenceType::ValidatorParticipation {
            total_validators: 100,
            active_validators: 150, // Invalid: can't exceed total
            participation_rate: 0.95,
        };

        assert!(evidence.validate().is_err());
    }

    #[test]
    fn test_fee_statistics_valid() {
        let evidence = EvidenceType::FeeStatistics {
            avg_fee: 1000,
            min_fee: 500,
            max_fee: 2000,
            target_fee: 1000,
        };

        assert!(evidence.validate().is_ok());
    }

    #[test]
    fn test_fee_statistics_ordering_invalid() {
        let evidence = EvidenceType::FeeStatistics {
            avg_fee: 1000,
            min_fee: 2000, // Invalid: min > avg
            max_fee: 500,
            target_fee: 1000,
        };

        assert!(evidence.validate().is_err());
    }

    #[test]
    fn test_proposal_id_determinism() {
        let proposal1 = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Test".to_string(),
            confidence: 0.85,
            evidence: vec![],
            risk_score: 25,
            cooldown_epochs: 5,
        });

        let proposal2 = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Test".to_string(),
            confidence: 0.85,
            evidence: vec![],
            risk_score: 25,
            cooldown_epochs: 5,
        });

        let id1 = proposal1.compute_id().unwrap();
        let id2 = proposal2.compute_id().unwrap();
        assert_eq!(id1, id2); // Same proposal = same ID
    }

    // ==================== CONSTRAINT VALIDATOR TESTS ====================

    #[test]
    fn test_protocol_invariants_mainnet() {
        let invariants = ProtocolInvariants::mainnet();
        assert_eq!(invariants.min_validators, 20);
        assert_eq!(invariants.min_participation_rate, 0.67);
        assert_eq!(invariants.max_slashing_per_epoch, 0.05);
        assert_eq!(invariants.mode_switch_cooldown_epochs, 10);
    }

    #[test]
    fn test_protocol_invariants_testnet() {
        let invariants = ProtocolInvariants::testnet();
        assert_eq!(invariants.min_validators, 5);
        assert_eq!(invariants.min_participation_rate, 0.51);
        assert_eq!(invariants.max_slashing_per_epoch, 0.20);
        assert_eq!(invariants.mode_switch_cooldown_epochs, 2);
    }

    #[test]
    fn test_constraint_context_creation() {
        let context = ConstraintContext {
            current_epoch: 100,
            last_mode_switch_epoch: 50,
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

        assert_eq!(context.current_epoch, 100);
        assert_eq!(context.total_validators, 100);
    }

    // ==================== ATTESTATION TESTS ====================

    #[test]
    fn test_attestation_record_creation() {
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

        let commitment = AIOutputCommitment::new(proposal, 10, vec![1, 2, 3], None).unwrap();
        let record = AIAttestationRecord::new(commitment);

        assert!(!record.attestation_id.is_empty());
        assert_eq!(record.verification_status, "pending");
    }

    #[test]
    fn test_attestation_manager_nonce_tracking() {
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

        // Try to record same commitment (should fail due to nonce)
        let record2 = AIAttestationRecord::new(commitment1);
        assert!(manager.record_attestation(record2).is_err());
    }

    // ==================== FEEDBACK LOOP TESTS ====================

    #[test]
    fn test_accuracy_metrics_basic() {
        let mut metrics = AccuracyMetrics::new();

        metrics.record_prediction(true, true); // TP
        metrics.record_prediction(true, false); // FN
        metrics.record_prediction(false, false); // TN

        assert_eq!(metrics.total_predictions, 3);
        assert_eq!(metrics.correct_predictions, 2);
    }

    #[test]
    fn test_accuracy_rate_calculation() {
        let mut metrics = AccuracyMetrics::new();

        for _ in 0..8 {
            metrics.record_prediction(true, true);
        }
        for _ in 0..2 {
            metrics.record_prediction(true, false);
        }

        assert_eq!(metrics.total_predictions, 10);
        assert_eq!(metrics.correct_predictions, 8);
        assert!((metrics.accuracy_rate - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_confidence_calibration_tracking() {
        let mut calibration = ConfidenceCalibration::new();

        assert!(calibration.record_calibration(0.95, true).is_ok());
        assert!(calibration.record_calibration(0.95, true).is_ok());
        assert!(calibration.record_calibration(0.05, false).is_ok());

        // Calibration error should be calculated
        assert!(calibration.calibration_error >= 0.0);
    }

    #[test]
    fn test_model_performance_tracking() {
        let mut perf = ModelPerformance::new("model1".to_string(), "1.0".to_string());

        let _ = perf.record_inference(10.0, true, 0.95);
        let _ = perf.record_inference(12.0, true, 0.90);
        let _ = perf.record_inference(11.0, false, 0.85);

        assert_eq!(perf.total_inferences, 3);
        assert!((perf.avg_latency_ms - 11.0).abs() < 0.1);
    }

    #[test]
    fn test_feedback_manager_registration() {
        let mut manager = FeedbackManager::new(0);
        manager.register_model("model1".to_string(), "1.0".to_string());

        let perf = manager.get_model_performance("model1", "1.0");
        assert!(perf.is_some());
    }

    #[test]
    fn test_feedback_manager_outcome_recording() {
        let mut manager = FeedbackManager::new(0);
        manager.register_model("test_model".to_string(), "1.0".to_string());

        assert!(manager
            .record_outcome("test_model", "1.0", 10.0, true, 0.9)
            .is_ok());
        assert!(manager
            .record_outcome("test_model", "1.0", 12.0, true, 0.85)
            .is_ok());

        let perf = manager.get_model_performance("test_model", "1.0");
        assert!(perf.is_some());
        assert_eq!(perf.unwrap().total_inferences, 2);
    }

    #[test]
    fn test_system_health_metrics() {
        let mut manager = FeedbackManager::new(0);
        manager.register_model("model1".to_string(), "1.0".to_string());
        manager.register_model("model2".to_string(), "1.0".to_string());

        let health = manager.get_health_metrics();
        assert_eq!(health.total_models, 2);
        assert_eq!(health.healthy_models, 2);
    }

    // ==================== CROSS-MODULE INTEGRATION ====================

    #[test]
    fn test_end_to_end_proposal_creation() {
        // Create proposal
        let proposal = AIProposal::ConsensusModeSwitch(ConsensusModeProposal {
            current_mode: "PoS".to_string(),
            proposed_mode: "PBFT".to_string(),
            activation_epoch: 100,
            reason: "Improve finality".to_string(),
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

        // Create attestation
        let commitment =
            AIOutputCommitment::new(proposal.clone(), 50, vec![1, 2, 3], None).unwrap();
        let record = AIAttestationRecord::new(commitment);

        assert!(!record.attestation_id.is_empty());
        assert!(record.proposal_id.is_some());
    }

    #[test]
    fn test_proposal_with_evidence_validation() {
        let proposal = AIProposal::ShardRebalance(ShardRebalanceProposal {
            shard_distribution: vec![50, 50, 50],
            reason: "Load balancing".to_string(),
            confidence: 0.82,
            evidence: vec![
                EvidenceType::Metric {
                    name: "cpu_usage".to_string(),
                    value: 75.0,
                    threshold: 70.0,
                    direction: "above".to_string(),
                },
                EvidenceType::CrossShardHealth {
                    latency_ms: 150,
                    success_rate: 0.95,
                    error_count: 2,
                },
            ],
            risk_score: 40,
        });

        assert!(proposal.validate().is_ok());
    }
}
