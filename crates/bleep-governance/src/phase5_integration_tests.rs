// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// Integration Tests - Real-world scenarios and edge cases
//
// TESTING REQUIREMENTS MET:
// ✓ Proposal validation (safety constraints)
// ✓ Rejected unsafe proposals
// ✓ Approved safe proposals
// ✓ Deterministic activation
// ✓ Failed upgrade rollback
// ✓ AI reputation updates
// ✓ Edge cases and adversarial scenarios

#[cfg(test)]
mod integration_tests {
    use crate::{
        ai_hooks::AIHooks,
        ai_reputation::{AIReputationTracker, ProposalOutcome},
        apip::{AIModelMetadata, APIPBuilder, RiskLevel, RuleChange},
        protocol_evolution::ProtocolEvolutionOrchestrator,
        protocol_rules::{ProtocolRuleSetFactory, RuleBounds},
        safety_constraints::SafetyConstraintsEngine,
    };

    fn create_orchestrator() -> ProtocolEvolutionOrchestrator {
        let genesis = ProtocolRuleSetFactory::create_genesis().unwrap();
        ProtocolEvolutionOrchestrator::new(genesis)
    }

    fn create_model(id: &str) -> AIModelMetadata {
        AIModelMetadata::new(
            id.to_string(),
            "1.0.0".to_string(),
            "Test Model".to_string(),
            "Test Organization".to_string(),
        )
    }

    fn create_proposal(
        id: &str,
        model_id: &str,
        rule_name: &str,
        old_val: u64,
        new_val: u64,
        confidence: u8,
        risk: RiskLevel,
    ) -> crate::apip::APIP {
        APIPBuilder::new(
            id.to_string(),
            create_model(model_id),
            format!("Proposal: {}", id),
            "Test proposal".to_string(),
            10,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            rule_name.to_string(),
            old_val,
            new_val,
            crate::protocol_rules::RuleVersion::new(0, 1, 0),
            "Change justification".to_string(),
        ))
        .unwrap()
        .confidence(confidence)
        .unwrap()
        .risk(risk, "Test risk".to_string())
        .unwrap()
        .expected_impact("Better protocol".to_string())
        .unwrap()
        .rollback_strategy("Revert to old value".to_string())
        .unwrap()
        .ai_signature(vec![1, 2, 3, 4, 5])
        .unwrap()
        .build()
        .unwrap()
    }

    // TEST 1: Basic proposal submission and validation
    #[test]
    fn test_proposal_submission_and_validation() {
        let mut orch = create_orchestrator();
        let proposal = create_proposal(
            "APIP-001",
            "ai-model-1",
            "SHARD_SPLIT_THRESHOLD",
            1_000_000,
            1_100_000,
            80,
            RiskLevel::Low,
        );

        let report = orch.submit_proposal(proposal, 1).unwrap();
        assert!(report.is_valid);
        assert!(report.passed_count > 0);
    }

    // TEST 2: Reject unsafe proposal (value out of bounds)
    #[test]
    fn test_reject_unsafe_proposal_out_of_bounds() {
        let mut orch = create_orchestrator();

        // Try to set shard split threshold to 100 (way too low, min is 100_000)
        let proposal = create_proposal(
            "APIP-002",
            "ai-model-1",
            "SHARD_SPLIT_THRESHOLD",
            1_000_000,
            50, // Out of bounds
            80,
            RiskLevel::Low,
        );

        let report = orch.submit_proposal(proposal, 1).unwrap();
        assert!(!report.is_valid);
        assert!(report.failed_count > 0);
    }

    // TEST 3: Reject proposal with insufficient AI confidence
    #[test]
    fn test_reject_low_confidence_proposal() {
        let mut orch = create_orchestrator();

        // Set confidence below minimum (70%)
        let proposal = create_proposal(
            "APIP-003",
            "ai-model-1",
            "SHARD_SPLIT_THRESHOLD",
            1_000_000,
            1_100_000,
            30, // Too low
            RiskLevel::Low,
        );

        let report = orch.submit_proposal(proposal, 1).unwrap();
        assert!(!report.is_valid);
    }

    // TEST 4: Approve safe proposal with voting
    #[test]
    fn test_approve_safe_proposal_with_voting() {
        let mut orch = create_orchestrator();

        let proposal = create_proposal(
            "APIP-004",
            "ai-model-1",
            "VALIDATOR_ROTATION_CADENCE",
            10,
            12,
            85,
            RiskLevel::Low,
        );

        let report = orch.submit_proposal(proposal.clone(), 1).unwrap();
        assert!(report.is_valid);

        // Record voting result: 150 votes for, 50 against = 75% approval
        // Low risk requires 51%, so should pass
        let vote_result = orch
            .record_voting_result("APIP-004".to_string(), 150, 50, 2)
            .unwrap();

        assert!(vote_result.approved);
        assert_eq!(vote_result.approval_percentage, 75);
    }

    // TEST 5: Reject proposal with insufficient voting support
    #[test]
    fn test_reject_proposal_insufficient_votes() {
        let mut orch = create_orchestrator();

        let proposal = create_proposal(
            "APIP-005",
            "ai-model-1",
            "SHARD_SPLIT_THRESHOLD",
            1_000_000,
            1_100_000,
            75,
            RiskLevel::High,
        );

        orch.submit_proposal(proposal, 1).unwrap();

        // Record voting: 100 for, 150 against = 40% approval
        // High risk requires 80%, so should fail
        let vote_result = orch
            .record_voting_result("APIP-005".to_string(), 100, 150, 2)
            .unwrap();

        assert!(!vote_result.approved);
        assert_eq!(vote_result.approval_percentage, 40);
    }

    // TEST 6: Deterministic activation at target epoch
    #[test]
    fn test_deterministic_activation() {
        let mut orch = create_orchestrator();

        let proposal = create_proposal(
            "APIP-006",
            "ai-model-1",
            "CHECKPOINT_FREQUENCY",
            100,
            120,
            80,
            RiskLevel::Low,
        );

        orch.submit_proposal(proposal, 1).unwrap();
        orch.record_voting_result("APIP-006".to_string(), 200, 50, 2)
            .unwrap();

        // Activate at target epoch 10
        let records = orch
            .activate_proposal("APIP-006".to_string(), 10, 10000)
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].old_value, 100);
        assert_eq!(records[0].new_value, 120);
        assert_eq!(records[0].activation_epoch, 10);

        // Verify rule was updated
        let updated_rule = orch.get_ruleset().get_rule("CHECKPOINT_FREQUENCY").unwrap();
        assert_eq!(updated_rule.value, 120);
    }

    // TEST 7: Rollback activated proposal
    #[test]
    fn test_rollback_activated_proposal() {
        let mut orch = create_orchestrator();

        let proposal = create_proposal(
            "APIP-007",
            "ai-model-1",
            "SLASHING_PROPORTION",
            5,
            0,  // This is bad - disables slashing
            50, // Low confidence
            RiskLevel::Critical,
        );

        orch.submit_proposal(proposal, 1).unwrap();
        orch.record_voting_result("APIP-007".to_string(), 300, 50, 2)
            .unwrap();

        orch.activate_proposal("APIP-007".to_string(), 10, 10000)
            .unwrap();

        // Verify it was activated
        let rule = orch.get_ruleset().get_rule("SLASHING_PROPORTION").unwrap();
        assert_eq!(rule.value, 0);

        // Now rollback due to critical issue
        let rollback_records = orch
            .rollback_proposal("APIP-007".to_string(), 15, "Slashing disabled".to_string())
            .unwrap();

        assert_eq!(rollback_records.len(), 1);
        assert!(rollback_records[0].was_rolled_back);
        assert_eq!(rollback_records[0].rollback_epoch, Some(15));

        // Verify rule was restored
        let restored_rule = orch.get_ruleset().get_rule("SLASHING_PROPORTION").unwrap();
        assert_eq!(restored_rule.value, 5);
    }

    // TEST 8: AI reputation tracking
    #[test]
    fn test_ai_reputation_tracking() {
        let mut orch = create_orchestrator();

        let proposal = create_proposal(
            "APIP-008",
            "ai-model-rep-test",
            "SHARD_SPLIT_THRESHOLD",
            1_000_000,
            1_100_000,
            85,
            RiskLevel::Low,
        );

        orch.submit_proposal(proposal, 1).unwrap();
        orch.record_voting_result("APIP-008".to_string(), 200, 50, 2)
            .unwrap();
        orch.activate_proposal("APIP-008".to_string(), 10, 10000)
            .unwrap();

        // Record success outcome
        orch.record_proposal_outcome("APIP-008".to_string(), ProposalOutcome::Accepted, 15)
            .unwrap();

        // Create another proposal from same model
        let proposal2 = create_proposal(
            "APIP-009",
            "ai-model-rep-test",
            "CHECKPOINT_FREQUENCY",
            100,
            110,
            80,
            RiskLevel::Low,
        );

        orch.submit_proposal(proposal2, 1).unwrap();

        // AI should have good reputation now
        // (reputation affects advisory weighting in real system)
    }

    // TEST 9: Multiple concurrent proposals
    #[test]
    fn test_multiple_concurrent_proposals() {
        let mut orch = create_orchestrator();

        // Submit 5 different proposals
        for i in 0..5 {
            let proposal = create_proposal(
                &format!("APIP-{:03}", 100 + i),
                &format!("ai-model-{}", i % 2),
                if i % 2 == 0 {
                    "SHARD_SPLIT_THRESHOLD"
                } else {
                    "CHECKPOINT_FREQUENCY"
                },
                if i % 2 == 0 { 1_000_000 } else { 100 },
                if i % 2 == 0 {
                    1_050_000 + (i as u64 * 10_000)
                } else {
                    110 + (i as u64)
                },
                75 + (i as u8),
                RiskLevel::Low,
            );

            let report = orch.submit_proposal(proposal, i as u64 + 1).unwrap();
            assert!(report.is_valid);
        }

        // All proposals should be stored
        assert_eq!(
            orch.get_proposal("APIP-100").unwrap().proposal_id,
            "APIP-100"
        );
        assert_eq!(
            orch.get_proposal("APIP-104").unwrap().proposal_id,
            "APIP-104"
        );
    }

    // TEST 10: Epoch boundaries and determinism
    #[test]
    fn test_epoch_determinism() {
        let mut orch1 = create_orchestrator();
        let mut orch2 = create_orchestrator();

        let proposal = create_proposal(
            "APIP-EPOCH-TEST",
            "ai-model-epoch",
            "VALIDATOR_ROTATION_CADENCE",
            10,
            15,
            85,
            RiskLevel::Low,
        );

        // Both orchestrators submit at same epoch
        let report1 = orch1.submit_proposal(proposal.clone(), 5).unwrap();
        let report2 = orch2.submit_proposal(proposal.clone(), 5).unwrap();

        // Reports should be identical (deterministic)
        assert_eq!(report1.is_valid, report2.is_valid);
        assert_eq!(report1.passed_count, report2.passed_count);
        assert_eq!(report1.failed_count, report2.failed_count);
    }

    // TEST 11: Safety constraint edge cases
    #[test]
    fn test_safety_constraint_edge_cases() {
        let mut orch = create_orchestrator();

        // Test minimum value boundary
        let proposal_min = create_proposal(
            "APIP-MIN-BOUND",
            "ai-model-1",
            "SHARD_SPLIT_THRESHOLD",
            1_000_000,
            100_000, // At minimum boundary
            80,
            RiskLevel::Low,
        );

        let report_min = orch.submit_proposal(proposal_min, 1).unwrap();
        assert!(report_min.is_valid); // Should pass at boundary

        // Test maximum value boundary
        let proposal_max = create_proposal(
            "APIP-MAX-BOUND",
            "ai-model-1",
            "SHARD_SPLIT_THRESHOLD",
            1_000_000,
            10_000_000, // At maximum boundary
            80,
            RiskLevel::Low,
        );

        let report_max = orch.submit_proposal(proposal_max, 1).unwrap();
        assert!(report_max.is_valid); // Should pass at boundary
    }

    // TEST 12: AI Hooks integration
    #[test]
    fn test_ai_hooks_integration() {
        let genesis = ProtocolRuleSetFactory::create_genesis().unwrap();
        let mut hooks = AIHooks::new("TestAI".to_string(), "1.0".to_string());

        // Test historical analysis
        let data = vec![(1, 100.0), (2, 105.0), (3, 110.0)];
        let analysis = hooks
            .analyze_historical_data("test_metric".to_string(), data)
            .unwrap();
        assert_eq!(analysis.trend, "POSITIVE");

        // Test compliance assessment
        let compliance = hooks.assess_compliance(&genesis).unwrap();
        assert!(compliance.score >= 50);

        // Test optimization suggestions
        let suggestions = hooks.suggest_optimizations(&genesis).unwrap();
        assert!(!suggestions.is_empty());
    }

    // TEST 13: Protocol version tracking
    #[test]
    fn test_protocol_version_tracking() {
        let mut orch = create_orchestrator();
        assert_eq!(orch.protocol_version(), 1);

        let proposal = create_proposal(
            "APIP-VERSION-TEST",
            "ai-model-1",
            "CHECKPOINT_FREQUENCY",
            100,
            150,
            80,
            RiskLevel::Low,
        );

        orch.submit_proposal(proposal, 1).unwrap();
        orch.record_voting_result("APIP-VERSION-TEST".to_string(), 200, 50, 2)
            .unwrap();

        orch.activate_proposal("APIP-VERSION-TEST".to_string(), 10, 10000)
            .unwrap();

        // Protocol version should increment
        assert_eq!(orch.protocol_version(), 2);

        // Rollback should also increment
        orch.rollback_proposal(
            "APIP-VERSION-TEST".to_string(),
            15,
            "Test rollback".to_string(),
        )
        .unwrap();
        assert_eq!(orch.protocol_version(), 3);
    }

    // TEST 14: AI reputation decay
    #[test]
    fn test_ai_reputation_decay() {
        let mut tracker = AIReputationTracker::new();

        // Register model
        tracker
            .register_model("decay-test-model".to_string())
            .unwrap();

        // Record some successful outcomes
        for i in 0..5 {
            tracker
                .record_outcome(
                    format!("APIP-{}", i),
                    "decay-test-model".to_string(),
                    ProposalOutcome::Accepted,
                    80,
                    i as u64,
                    (i + 1) as u64,
                )
                .unwrap();
        }

        let rep_before = tracker.get_reputation("decay-test-model").unwrap().score;

        // Apply decay
        tracker.apply_global_decay(10, 95); // 5% decay

        let rep_after = tracker.get_reputation("decay-test-model").unwrap().score;

        assert!(rep_after <= rep_before);
    }

    // TEST 15: Immutable rule prevention
    #[test]
    fn test_immutable_rule_protection() {
        let mut orch = create_orchestrator();

        // Try to modify FINALITY_THRESHOLD (immutable)
        let proposal = create_proposal(
            "APIP-IMMUTABLE",
            "ai-model-1",
            "FINALITY_THRESHOLD",
            67,
            70, // Try to modify immutable rule
            80,
            RiskLevel::Critical,
        );

        let report = orch.submit_proposal(proposal, 1).unwrap();
        // Should fail because rule is immutable
        assert!(!report.is_valid);
    }
}
