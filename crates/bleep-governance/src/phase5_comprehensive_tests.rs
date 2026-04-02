// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// Comprehensive Integration Tests
//
// TESTING OBJECTIVES:
// ✓ Deterministic proposal submission and validation
// ✓ Machine-verifiable safety constraints
// ✓ Governance voting with validator stake weighting
// ✓ Deterministic activation mechanism
// ✓ Emergency rollback on invariant violation
// ✓ AI reputation tracking
// ✓ Protocol version tracking and synchronization
// ✓ Fork prevention through protocol versioning
// ✓ Real-world adversarial scenarios

#[cfg(test)]
mod phase5_comprehensive_tests {
    use crate::{
        ai_reputation::{AIReputationTracker, ProposalOutcome},
        apip::{AIModelMetadata, APIPBuilder, RiskLevel, RuleChange, SafetyBounds},
        deterministic_activation::DeterministicActivationManager,
        governance_voting::{GovernanceVotingEngine, ValidatorVote},
        invariant_monitoring::{
            GlobalInvariantMonitor, InvariantSeverity, InvariantThreshold, InvariantType,
        },
        protocol_evolution::ProtocolEvolutionOrchestrator,
        protocol_rules::{ProtocolRule, ProtocolRuleSetFactory, RuleBounds},
        safety_constraints::SafetyConstraintsEngine,
    };
    use std::collections::HashMap;

    fn setup_orchestrator() -> ProtocolEvolutionOrchestrator {
        let genesis = ProtocolRuleSetFactory::create_genesis().unwrap();
        ProtocolEvolutionOrchestrator::new(genesis)
    }

    fn setup_voting_engine() -> GovernanceVotingEngine {
        let mut engine = GovernanceVotingEngine::new();

        // Add validators with stake
        let mut validators = HashMap::new();
        validators.insert(vec![1, 2, 3], 1000); // Validator 1
        validators.insert(vec![4, 5, 6], 2000); // Validator 2
        validators.insert(vec![7, 8, 9], 3000); // Validator 3
        engine.update_validators(validators);

        engine
    }

    fn create_ai_model(id: &str) -> AIModelMetadata {
        AIModelMetadata::new(
            id.to_string(),
            "1.0.0".to_string(),
            format!("Model {}", id),
            "BLEEP AI Research".to_string(),
        )
    }

    // TEST 1: End-to-end proposal submission and validation
    #[test]
    fn test_e2e_proposal_submission_and_validation() {
        let mut orch = setup_orchestrator();

        let model = create_ai_model("ai-model-1");

        let proposal = APIPBuilder::new(
            "APIP-E2E-001".to_string(),
            model,
            "Increase Shard Split Threshold".to_string(),
            "Increase threshold to reduce unnecessary splits".to_string(),
            5,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000,
            1_200_000,
            Default::default(),
            "Reduce splitting overhead".to_string(),
        ))
        .unwrap()
        .confidence(85)
        .unwrap()
        .risk(
            RiskLevel::Low,
            "Minimal impact, tested on testnet".to_string(),
        )
        .unwrap()
        .expected_impact("Better shard utilization".to_string())
        .unwrap()
        .rollback_strategy("Revert to 1M threshold".to_string())
        .unwrap()
        .ai_signature(vec![42, 43, 44, 45])
        .unwrap()
        .build()
        .unwrap();

        // Submit and validate
        let report = orch.submit_proposal(proposal, 1).unwrap();

        assert!(report.is_valid);
        assert!(report.passed_count > 0);
        assert_eq!(report.failed_count, 0);
    }

    // TEST 2: Reject unsafe proposals (out of bounds)
    #[test]
    fn test_reject_unsafe_proposal_out_of_bounds() {
        let mut orch = setup_orchestrator();

        let model = create_ai_model("ai-model-2");

        let proposal = APIPBuilder::new(
            "APIP-UNSAFE-001".to_string(),
            model,
            "Dangerous Proposal".to_string(),
            "Try to set invalid values".to_string(),
            5,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000,
            100_000_000_000, // Way out of bounds!
            Default::default(),
            "Evil change".to_string(),
        ))
        .unwrap()
        .confidence(50)
        .unwrap()
        .risk(RiskLevel::Critical, "Invalid values".to_string())
        .unwrap()
        .expected_impact("Boom".to_string())
        .unwrap()
        .rollback_strategy("Hope".to_string())
        .unwrap()
        .ai_signature(vec![1, 2, 3])
        .unwrap()
        .build()
        .unwrap();

        let report = orch.submit_proposal(proposal, 1).unwrap();

        assert!(!report.is_valid);
        assert!(report.failed_count > 0);
    }

    // TEST 3: Governance voting with stake weighting
    #[test]
    fn test_governance_voting_stake_weighted() {
        let mut voting_engine = setup_voting_engine();

        // Create dummy signatures for testing
        let mut sig1_sig2 = vec![1u8, 2u8];
        let mut sig3_sig4 = vec![3u8, 4u8];
        let mut sig5_sig6 = vec![5u8, 6u8];

        // Start voting
        voting_engine
            .start_voting("APIP-VOTE-001".to_string(), 1, 5)
            .unwrap();

        // Validator 1 votes yes (1000 stake)
        voting_engine
            .cast_vote(
                "APIP-VOTE-001".to_string(),
                vec![1, 2, 3],
                true,
                2,
                sig1_sig2,
            )
            .unwrap();

        // Validator 2 votes yes (2000 stake)
        voting_engine
            .cast_vote(
                "APIP-VOTE-001".to_string(),
                vec![4, 5, 6],
                true,
                2,
                sig3_sig4,
            )
            .unwrap();

        // Validator 3 votes no (3000 stake)
        voting_engine
            .cast_vote(
                "APIP-VOTE-001".to_string(),
                vec![7, 8, 9],
                false,
                3,
                sig5_sig6,
            )
            .unwrap();

        // Finalize voting at epoch 6
        let result = voting_engine.finalize_voting("APIP-VOTE-001", 6).unwrap();

        // 3000 for, 3000 against = 50% approval
        assert_eq!(result.stake_for, 3000);
        assert_eq!(result.stake_against, 3000);
        assert_eq!(result.approval_percentage, 50);
        assert_eq!(result.voter_count, 3);
    }

    // TEST 4: Deterministic activation
    #[test]
    fn test_deterministic_activation() {
        let genesis = ProtocolRuleSetFactory::create_genesis().unwrap();
        let mut activation_mgr = DeterministicActivationManager::new(genesis.clone(), 1);

        let model = create_ai_model("ai-model-3");

        let proposal = APIPBuilder::new(
            "APIP-ACTIVATE-001".to_string(),
            model,
            "Activate new rules".to_string(),
            "Test activation".to_string(),
            5,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000,
            1_100_000,
            Default::default(),
            "Increase threshold".to_string(),
        ))
        .unwrap()
        .confidence(80)
        .unwrap()
        .risk(RiskLevel::Low, "Safe".to_string())
        .unwrap()
        .expected_impact("Better".to_string())
        .unwrap()
        .rollback_strategy("Revert".to_string())
        .unwrap()
        .ai_signature(vec![1, 2, 3])
        .unwrap()
        .build()
        .unwrap();

        // Create activation plan
        let plan = activation_mgr
            .create_activation_plan(&proposal, 2, 4)
            .unwrap();

        assert_eq!(plan.new_protocol_version, 2);
        assert_eq!(plan.target_epoch, 5);
        assert_eq!(plan.rule_changes.len(), 1);

        // Check ready
        assert!(activation_mgr.check_activation_ready("APIP-ACTIVATE-001", 5));

        // Activate
        let records = activation_mgr
            .activate("APIP-ACTIVATE-001", 5, 500)
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(activation_mgr.protocol_version(), 2);

        // Verify rule was updated
        let new_ruleset = activation_mgr.get_ruleset();
        let rule = new_ruleset.get_rule("SHARD_SPLIT_THRESHOLD").unwrap();
        assert_eq!(rule.value, 1_100_000);
    }

    // TEST 5: Emergency rollback on invariant violation
    #[test]
    fn test_emergency_rollback_on_violation() {
        let genesis = ProtocolRuleSetFactory::create_genesis().unwrap();
        let mut activation_mgr = DeterministicActivationManager::new(genesis, 1);

        let model = create_ai_model("ai-model-4");

        let proposal = APIPBuilder::new(
            "APIP-ROLLBACK-001".to_string(),
            model,
            "Test rollback".to_string(),
            "Proposal that will fail".to_string(),
            5,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            "CHECKPOINT_FREQUENCY".to_string(),
            100,
            50,
            Default::default(),
            "Increase checkpoint frequency".to_string(),
        ))
        .unwrap()
        .confidence(60)
        .unwrap()
        .risk(RiskLevel::Medium, "Moderate impact".to_string())
        .unwrap()
        .expected_impact("More checkpoints".to_string())
        .unwrap()
        .rollback_strategy("Revert frequency".to_string())
        .unwrap()
        .ai_signature(vec![1, 2, 3])
        .unwrap()
        .build()
        .unwrap();

        // Create and activate
        let plan = activation_mgr
            .create_activation_plan(&proposal, 2, 4)
            .unwrap();
        activation_mgr
            .activate("APIP-ROLLBACK-001", 5, 500)
            .unwrap();

        // Verify activation
        assert_eq!(activation_mgr.protocol_version(), 2);

        // Trigger rollback
        let rollback_records = activation_mgr
            .emergency_rollback(
                "APIP-ROLLBACK-001",
                6,
                "Invariant violation detected".to_string(),
            )
            .unwrap();

        // Verify rollback
        assert_eq!(rollback_records.len(), 1);
        assert!(rollback_records[0].was_rolled_back);
        assert_eq!(activation_mgr.protocol_version(), 1);

        let ruleset = activation_mgr.get_ruleset();
        let rule = ruleset.get_rule("CHECKPOINT_FREQUENCY").unwrap();
        assert_eq!(rule.value, 100); // Restored to original
    }

    // TEST 6: AI reputation tracking
    #[test]
    fn test_ai_reputation_tracking() {
        let mut reputation_tracker = AIReputationTracker::new();

        // Register models
        reputation_tracker
            .register_model("ai-model-a".to_string())
            .unwrap();
        reputation_tracker
            .register_model("ai-model-b".to_string())
            .unwrap();

        // Record outcomes
        reputation_tracker
            .record_outcome(
                "APIP-001".to_string(),
                "ai-model-a".to_string(),
                ProposalOutcome::Accepted,
                90,
                1,
                5,
            )
            .unwrap();

        reputation_tracker
            .record_outcome(
                "APIP-002".to_string(),
                "ai-model-a".to_string(),
                ProposalOutcome::Accepted,
                85,
                2,
                6,
            )
            .unwrap();

        reputation_tracker
            .record_outcome(
                "APIP-003".to_string(),
                "ai-model-b".to_string(),
                ProposalOutcome::RolledBack,
                50,
                1,
                7,
            )
            .unwrap();

        // Check reputation
        let rep_a = reputation_tracker.get_reputation("ai-model-a").unwrap();
        assert_eq!(rep_a.accepted_count, 2);
        assert!(rep_a.acceptance_rate() > 50.0);

        let rep_b = reputation_tracker.get_reputation("ai-model-b").unwrap();
        assert_eq!(rep_b.rollback_count, 1);
        assert!(rep_b.score < 500); // Should be negative impact
    }

    // TEST 7: Protocol version synchronization
    #[test]
    fn test_protocol_version_synchronization() {
        // Simulate two nodes
        let genesis = ProtocolRuleSetFactory::create_genesis().unwrap();
        let mut node1 = DeterministicActivationManager::new(genesis.clone(), 1);
        let mut node2 = DeterministicActivationManager::new(genesis.clone(), 1);

        // Both nodes should start with same version
        assert_eq!(node1.protocol_version(), 1);
        assert_eq!(node2.protocol_version(), 1);

        // Create identical proposal
        let model = create_ai_model("ai-model-sync");

        let proposal = APIPBuilder::new(
            "APIP-SYNC-001".to_string(),
            model,
            "Sync test".to_string(),
            "Test synchronization".to_string(),
            5,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            "VALIDATOR_ROTATION_CADENCE".to_string(),
            10,
            15,
            Default::default(),
            "Change rotation cadence".to_string(),
        ))
        .unwrap()
        .confidence(75)
        .unwrap()
        .risk(RiskLevel::Low, "Safe".to_string())
        .unwrap()
        .expected_impact("Better".to_string())
        .unwrap()
        .rollback_strategy("Revert".to_string())
        .unwrap()
        .ai_signature(vec![1, 2, 3])
        .unwrap()
        .build()
        .unwrap();

        // Both nodes activate identically
        node1.create_activation_plan(&proposal, 2, 4).unwrap();
        node2.create_activation_plan(&proposal, 2, 4).unwrap();

        node1.activate("APIP-SYNC-001", 5, 500).unwrap();
        node2.activate("APIP-SYNC-001", 5, 500).unwrap();

        // Both should have same version and ruleset
        assert_eq!(node1.protocol_version(), node2.protocol_version());
        assert_eq!(
            node1
                .get_ruleset()
                .get_rule_value("VALIDATOR_ROTATION_CADENCE")
                .unwrap(),
            node2
                .get_ruleset()
                .get_rule_value("VALIDATOR_ROTATION_CADENCE")
                .unwrap()
        );
    }

    // TEST 8: Multiple proposals in sequence
    #[test]
    fn test_sequential_proposal_activation() {
        let mut orch = setup_orchestrator();

        // Submit first proposal
        let model1 = create_ai_model("ai-model-seq-1");
        let proposal1 = APIPBuilder::new(
            "APIP-SEQ-001".to_string(),
            model1,
            "First proposal".to_string(),
            "Test sequence".to_string(),
            5,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000,
            1_100_000,
            Default::default(),
            "Increase".to_string(),
        ))
        .unwrap()
        .confidence(80)
        .unwrap()
        .risk(RiskLevel::Low, "Safe".to_string())
        .unwrap()
        .expected_impact("Better".to_string())
        .unwrap()
        .rollback_strategy("Revert".to_string())
        .unwrap()
        .ai_signature(vec![1, 2, 3])
        .unwrap()
        .build()
        .unwrap();

        let report1 = orch.submit_proposal(proposal1.clone(), 1).unwrap();
        assert!(report1.is_valid);

        // Submit second proposal
        let model2 = create_ai_model("ai-model-seq-2");
        let proposal2 = APIPBuilder::new(
            "APIP-SEQ-002".to_string(),
            model2,
            "Second proposal".to_string(),
            "Test sequence".to_string(),
            10,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            "CHECKPOINT_FREQUENCY".to_string(),
            100,
            150,
            Default::default(),
            "Increase".to_string(),
        ))
        .unwrap()
        .confidence(75)
        .unwrap()
        .risk(RiskLevel::Low, "Safe".to_string())
        .unwrap()
        .expected_impact("Better".to_string())
        .unwrap()
        .rollback_strategy("Revert".to_string())
        .unwrap()
        .ai_signature(vec![1, 2, 3])
        .unwrap()
        .build()
        .unwrap();

        let report2 = orch.submit_proposal(proposal2, 1).unwrap();
        assert!(report2.is_valid);

        // Both proposals should be stored
        assert!(orch.get_proposal("APIP-SEQ-001").is_some());
        assert!(orch.get_proposal("APIP-SEQ-002").is_some());
    }
}
