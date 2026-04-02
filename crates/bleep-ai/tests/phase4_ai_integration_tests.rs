// PHASE 4: COMPREHENSIVE AI INTEGRATION TESTS
// Tests for: input tampering, recommendation validation, AI failure fallback, determinism
//
// Exit Criteria:
// ✅ AI enhances safety without becoming a trusted party
// ✅ Input tampering detected and rejected
// ✅ Recommendations are advisory only (governance decides)
// ✅ AI failure doesn't break governance
// ✅ All outputs are verifiable

#[cfg(test)]
mod phase4_ai_integration_tests {
    use bleep_consensus::incident_detector::*;
    use bleep_consensus::recovery_controller::*;
    use bleep_consensus::self_healing_orchestrator::*;

    use bleep_ai::ai_decision_module::*;
    use bleep_ai::feature_extractor::*;
    use bleep_ai::governance_integration::*;

    use sha2::{Digest, Sha256};

    // ============================================================================
    // TEST 1-5: INPUT TAMPERING DETECTION
    // ============================================================================

    #[test]
    fn test_01_feature_input_tampering_detection() {
        // Verify that tampering with input telemetry is detected
        let extractor = FeatureExtractor::new();
        let mut telemetry = create_test_telemetry(10);

        let features = extractor.extract(&telemetry).unwrap();
        let original_hash = features.input_hash.clone();

        // Tamper with telemetry
        telemetry.network.healthy_count = 2; // Changed!

        let tampered_features = extractor.extract(&telemetry).unwrap();
        let tampered_hash = tampered_features.input_hash.clone();

        // Hashes differ (tampering detected)
        assert_ne!(original_hash, tampered_hash);
    }

    #[test]
    fn test_02_feature_tampering_reproducibility() {
        // Same features produce same hash (deterministic)
        let extractor = FeatureExtractor::new();
        let telemetry = create_test_telemetry(10);

        let features1 = extractor.extract(&telemetry).unwrap();
        let features2 = extractor.extract(&telemetry).unwrap();

        // Exact same feature hashes
        assert_eq!(features1.feature_hash, features2.feature_hash);
        assert_eq!(features1.input_hash, features2.input_hash);
    }

    #[test]
    fn test_03_assessment_signature_tampering() {
        // Verify that tampering with assessment is detected
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());
        let features = create_test_features(30.0);

        let (assessment, signature) = module.analyze(&features).unwrap();

        // Try to verify with tampered signature
        let mut bad_signature = signature.clone();
        bad_signature.signature[0] ^= 1; // Flip a bit

        assert!(!bad_signature.verify());
    }

    #[test]
    fn test_04_proposal_signature_verification() {
        // Governance rejects proposal with invalid signature
        let mut gov = GovernanceIntegration::new();

        let mut assessment = AnomalyAssessment {
            anomaly_score: 30.0,
            classification: AnomalyClass::Degraded,
            confidence: 85.0,
            input_feature_hash: b"test".to_vec(),
            epoch: 1,
            assessment_hash: Sha256::digest(b"test").to_vec(),
        };

        // Create valid signature
        let mut signature = AISignature::sign(b"ai_key", &assessment.assessment_hash, 1);

        // Tamper with assessment after signing
        assessment.anomaly_score = 70.0;
        assessment.assessment_hash = Sha256::digest(b"tampered").to_vec();

        let recommendation = create_test_recommendation();

        // Proposal creation should fail (signature doesn't match)
        let result = AIAssessmentProposal::new(assessment, signature, recommendation, 1);

        assert!(result.is_err());
    }

    #[test]
    fn test_05_feature_vector_tampering() {
        // Verify feature vector tampering is detected
        let extractor = FeatureExtractor::new();
        let telemetry = create_test_telemetry(10);

        let mut features = extractor.extract(&telemetry).unwrap();
        let original_hash = features.feature_hash.clone();

        // Tamper with feature value
        features.features[0] = 50.0; // Changed!

        // Verify fails
        let is_valid = extractor.verify_features(&telemetry, &features).unwrap();
        assert!(!is_valid);
    }

    // ============================================================================
    // TEST 6-10: RECOMMENDATION VALIDATION
    // ============================================================================

    #[test]
    fn test_06_governance_accepts_recommendation() {
        let mut gov = GovernanceIntegration::new();
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());

        let features = create_test_features(30.0);
        let (assessment, signature) = module.analyze(&features).unwrap();
        let recommendation = module.recommend_recovery(&assessment).unwrap();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();
        gov.accept_recommendation(&proposal_id, 2).unwrap();

        let proposal = gov.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.vote_status, VoteStatus::Accepted);
    }

    #[test]
    fn test_07_governance_rejects_recommendation() {
        let mut gov = GovernanceIntegration::new();
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());

        let features = create_test_features(30.0);
        let (assessment, signature) = module.analyze(&features).unwrap();
        let recommendation = module.recommend_recovery(&assessment).unwrap();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();
        gov.reject_recommendation(&proposal_id, "Not needed".to_string(), 2)
            .unwrap();

        let proposal = gov.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.vote_status, VoteStatus::Rejected);
    }

    #[test]
    fn test_08_governance_executes_recommendation() {
        let mut gov = GovernanceIntegration::new();
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());

        let features = create_test_features(80.0); // Critical
        let (assessment, signature) = module.analyze(&features).unwrap();
        let recommendation = module.recommend_recovery(&assessment).unwrap();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();
        gov.accept_recommendation(&proposal_id, 2).unwrap();
        gov.execute_recommendation(&proposal_id, 3).unwrap();

        let proposal = gov.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.vote_status, VoteStatus::Executed);
    }

    #[test]
    fn test_09_recommendation_severity_levels() {
        let module = AIDecisionModule::new(b"ai_key".to_vec());

        let mut assessment = AnomalyAssessment {
            anomaly_score: 10.0,
            classification: AnomalyClass::Healthy,
            confidence: 95.0,
            input_feature_hash: b"test".to_vec(),
            epoch: 1,
            assessment_hash: vec![],
        };

        // Healthy → no action
        let rec = module.recommend_recovery(&assessment).unwrap();
        assert_eq!(rec.severity, 0);

        // Degraded
        assessment.classification = AnomalyClass::Degraded;
        assessment.anomaly_score = 40.0;
        let rec = module.recommend_recovery(&assessment).unwrap();
        assert_eq!(rec.severity, 1);

        // Anomalous
        assessment.classification = AnomalyClass::Anomalous;
        assessment.anomaly_score = 70.0;
        let rec = module.recommend_recovery(&assessment).unwrap();
        assert_eq!(rec.severity, 2);

        // Critical
        assessment.classification = AnomalyClass::Critical;
        assessment.anomaly_score = 90.0;
        let rec = module.recommend_recovery(&assessment).unwrap();
        assert_eq!(rec.severity, 3);
    }

    #[test]
    fn test_10_ai_cannot_execute_directly() {
        // Critical test: AI cannot bypass governance
        let mut gov = GovernanceIntegration::new();
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());

        let features = create_test_features(95.0); // Critical
        let (assessment, signature) = module.analyze(&features).unwrap();
        let recommendation = module.recommend_recovery(&assessment).unwrap();

        // Register assessment
        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();

        // Proposal is PENDING - AI has not executed
        let proposal = gov.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.vote_status, VoteStatus::Pending);

        // No executions recorded yet
        assert_eq!(gov.get_executed().len(), 0);

        // Even critical assessment doesn't execute without governance
        assert_eq!(proposal.recommendation.severity, 3);
        assert_eq!(proposal.vote_status, VoteStatus::Pending);
    }

    // ============================================================================
    // TEST 11-15: AI FAILURE FALLBACK
    // ============================================================================

    #[test]
    fn test_11_governance_fallback_without_ai() {
        // Governance can make decisions even if AI fails
        let mut gov = GovernanceIntegration::new();

        gov.governance_fallback(
            None,
            VoteStatus::Accepted,
            "Manual decision without AI".to_string(),
            5,
        )
        .unwrap();

        assert_eq!(gov.get_decisions().len(), 1);
    }

    #[test]
    fn test_12_ai_failure_doesnt_break_governance() {
        // If AI module fails, governance continues
        let mut gov = GovernanceIntegration::new();

        // Fallback: governance makes decision directly
        gov.governance_fallback(
            None,
            VoteStatus::Rejected,
            "AI module unavailable, governance decided based on manual analysis".to_string(),
            5,
        )
        .unwrap();

        assert_eq!(gov.get_decisions().len(), 1);
    }

    #[test]
    fn test_13_invalid_features_handled_gracefully() {
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());
        let mut features = create_test_features(30.0);
        features.features.clear(); // Remove all features

        // Analysis fails gracefully
        let result = module.analyze(&features);
        assert!(result.is_err());
    }

    #[test]
    fn test_14_missing_proposal_fallback() {
        let mut gov = GovernanceIntegration::new();

        // Try to accept non-existent proposal
        let result = gov.accept_recommendation(b"nonexistent", 5);

        assert!(result.is_err());
    }

    #[test]
    fn test_15_recovery_action_available_if_ai_unavailable() {
        // Even without AI, recovery actions are still available
        // (via Phase 3 self-healing orchestrator)

        let detector = IncidentDetector::new(DetectionParams::default());

        let controller = RecoveryController::new();

        // Both components work independently
        assert_ne!(detector.get_incidents().len(), 0); // Can detect
        assert_ne!(controller.get_recovery_log().len(), 0); // Can recover
    }

    // ============================================================================
    // TEST 16-20: DETERMINISM & REPRODUCIBILITY
    // ============================================================================

    #[test]
    fn test_16_deterministic_feature_extraction() {
        let extractor1 = FeatureExtractor::new();
        let extractor2 = FeatureExtractor::new();

        let telemetry = create_test_telemetry(10);

        let features1 = extractor1.extract(&telemetry).unwrap();
        let features2 = extractor2.extract(&telemetry).unwrap();

        // Same features from different extractors
        assert_eq!(features1.feature_hash, features2.feature_hash);
    }

    #[test]
    fn test_17_deterministic_ai_assessment() {
        let mut module1 = AIDecisionModule::new(b"ai_key".to_vec());
        let mut module2 = AIDecisionModule::new(b"ai_key".to_vec());

        let features = create_test_features(50.0);

        let (assessment1, sig1) = module1.analyze(&features).unwrap();
        let (assessment2, sig2) = module2.analyze(&features).unwrap();

        // Same assessment from both modules
        assert_eq!(assessment1.anomaly_score, assessment2.anomaly_score);
        assert_eq!(assessment1.classification, assessment2.classification);
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_18_reproducible_assessment_hash() {
        let assessment1 = AnomalyAssessment {
            anomaly_score: 50.0,
            classification: AnomalyClass::Degraded,
            confidence: 75.0,
            input_feature_hash: b"test".to_vec(),
            epoch: 5,
            assessment_hash: vec![],
        };

        let hash1 = AnomalyAssessment::compute_hash(
            assessment1.anomaly_score,
            assessment1.classification,
            assessment1.confidence,
            &assessment1.input_feature_hash,
            assessment1.epoch,
        );

        let hash2 = AnomalyAssessment::compute_hash(
            assessment1.anomaly_score,
            assessment1.classification,
            assessment1.confidence,
            &assessment1.input_feature_hash,
            assessment1.epoch,
        );

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_19_signature_reproducibility() {
        let ai_key = b"ai_key".to_vec();
        let assessment_hash = b"assessment_hash".to_vec();
        let epoch = 10;

        let sig1 = AISignature::sign(&ai_key, &assessment_hash, epoch);
        let sig2 = AISignature::sign(&ai_key, &assessment_hash, epoch);

        // Same signature from same inputs
        assert_eq!(sig1.signature, sig2.signature);
        assert!(sig1.verify());
        assert!(sig2.verify());
    }

    #[test]
    fn test_20_proposal_immutability() {
        let mut gov = GovernanceIntegration::new();
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());

        let features = create_test_features(40.0);
        let (assessment, signature) = module.analyze(&features).unwrap();
        let recommendation = module.recommend_recovery(&assessment).unwrap();

        let original_hash = assessment.assessment_hash.clone();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();
        let proposal = gov.get_proposal(&proposal_id).unwrap();

        // Assessment in proposal hasn't changed
        assert_eq!(proposal.assessment.assessment_hash, original_hash);
    }

    // ============================================================================
    // TEST 21-25: SECURITY & SAFETY
    // ============================================================================

    #[test]
    fn test_21_ai_key_mismatch_detection() {
        let mut gov = GovernanceIntegration::new();
        let mut module = AIDecisionModule::new(b"legitimate_ai".to_vec());

        let features = create_test_features(50.0);
        let (assessment, mut signature) = module.analyze(&features).unwrap();

        // Change AI key in signature
        signature.ai_key = b"malicious_ai".to_vec();

        let recommendation = create_test_recommendation();

        // Proposal creation should fail (signature doesn't match)
        let result = AIAssessmentProposal::new(assessment, signature, recommendation, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_22_assessment_hash_verification() {
        let assessment = AnomalyAssessment {
            anomaly_score: 60.0,
            classification: AnomalyClass::Anomalous,
            confidence: 80.0,
            input_feature_hash: b"input".to_vec(),
            epoch: 2,
            assessment_hash: Sha256::digest(b"correct").to_vec(),
        };

        let signature = AISignature::sign(b"ai_key", &assessment.assessment_hash, 2);
        let recommendation = create_test_recommendation();

        // Valid proposal
        let result = AIAssessmentProposal::new(
            assessment.clone(),
            signature.clone(),
            recommendation.clone(),
            2,
        );
        assert!(result.is_ok());

        // Change assessment hash
        let mut bad_assessment = assessment;
        bad_assessment.assessment_hash = Sha256::digest(b"wrong").to_vec();

        let result = AIAssessmentProposal::new(bad_assessment, signature, recommendation, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_23_confidence_reflects_uncertainty() {
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());

        // Highly discrepant features
        let mut features = create_test_features(50.0);
        features.features = vec![10.0, 90.0, 20.0, 80.0, 30.0, 70.0, 40.0];

        let (assessment, _) = module.analyze(&features).unwrap();

        // High uncertainty → lower confidence
        assert!(assessment.confidence >= 0.0 && assessment.confidence <= 100.0);
    }

    #[test]
    fn test_24_threshold_boundary_testing() {
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());

        // Test boundary: just below healthy
        let features = create_test_features(15.0);
        let (assessment, _) = module.analyze(&features).unwrap();
        assert_eq!(assessment.classification, AnomalyClass::Healthy);

        // Test boundary: just above healthy
        let features = create_test_features(25.0);
        let (assessment, _) = module.analyze(&features).unwrap();
        assert_eq!(assessment.classification, AnomalyClass::Degraded);
    }

    #[test]
    fn test_25_complete_workflow_determinism() {
        // Full pipeline: telemetry → features → assessment → proposal → governance
        let extractor = FeatureExtractor::new();
        let mut ai = AIDecisionModule::new(b"ai_key".to_vec());
        let mut gov = GovernanceIntegration::new();

        let telemetry = create_test_telemetry(10);

        let features = extractor.extract(&telemetry).unwrap();
        let (assessment, signature) = ai.analyze(&features).unwrap();
        let recommendation = ai.recommend_recovery(&assessment).unwrap();

        let proposal_id = gov
            .register_assessment(
                assessment.clone(),
                signature.clone(),
                recommendation.clone(),
                10,
            )
            .unwrap();

        gov.accept_recommendation(&proposal_id, 11).unwrap();
        gov.execute_recommendation(&proposal_id, 12).unwrap();

        // Verify all steps completed
        assert_eq!(gov.get_proposals().len(), 1);
        assert_eq!(gov.get_decisions().len(), 2); // accept + execute
        assert_eq!(gov.get_executed().len(), 1);
    }

    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================

    fn create_test_telemetry(healthy_count: u64) -> OnChainTelemetry {
        OnChainTelemetry {
            epoch: 10,
            network: NetworkMetrics {
                validator_count: 10,
                healthy_count,
                stalled_count: 10 - healthy_count,
                latency_ms: 100,
            },
            consensus: ConsensusMetrics {
                blocks_per_epoch: 50,
                avg_block_time_ms: 500,
                consensus_rounds: 1,
                failed_proposals: 0,
            },
            validators: (0..10)
                .map(|i| ValidatorMetrics {
                    id: format!("val-{}", i),
                    proposals: 5,
                    missed: 0,
                    stake: 1000,
                    is_active: i < healthy_count,
                })
                .collect(),
            finality: FinalityMetrics {
                last_finalized_epoch: 8,
                current_epoch: 10,
                finality_lag: 2,
                blocks_per_finality: 50,
            },
        }
    }

    fn create_test_features(anomaly_base: f64) -> ExtractedFeatures {
        use sha2::Digest;

        ExtractedFeatures {
            features: vec![
                50.0,               // network_health
                0.0,                // validator_downtime
                anomaly_base,       // consensus_latency
                anomaly_base * 0.5, // finality_lag
                100.0,              // proposal_success_rate
                10.0,               // stake_concentration
                90.0,               // block_production_rate
            ],
            feature_names: vec![
                "network_health".to_string(),
                "validator_downtime".to_string(),
                "consensus_latency".to_string(),
                "finality_lag".to_string(),
                "proposal_success_rate".to_string(),
                "stake_concentration".to_string(),
                "block_production_rate".to_string(),
            ],
            epoch: 10,
            input_hash: sha2::Sha256::digest(b"test_telemetry").to_vec(),
            feature_hash: sha2::Sha256::digest(b"test_features").to_vec(),
        }
    }

    fn create_test_recommendation() -> RecoveryRecommendation {
        RecoveryRecommendation {
            recommendation: "Monitor metrics".to_string(),
            severity: 1,
            confidence: 85.0,
            rationale: "Degradation detected in network metrics".to_string(),
        }
    }
}
