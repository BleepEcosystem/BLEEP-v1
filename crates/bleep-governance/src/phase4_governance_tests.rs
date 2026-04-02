// PHASE 4: CONSTITUTIONAL GOVERNANCE LAYER
// Comprehensive Integration Tests - Adversarial Testing Scenarios
//
// Tests cover:
// - Constitutional enforcement
// - ZK voting correctness
// - Double-vote prevention
// - Forkless upgrade safety
// - Governance-consensus binding
// - Attack resistance

#[cfg(test)]
mod phase4_governance_tests {
    use crate::constitution::*;
    use crate::forkless_upgrades::*;
    use crate::governance_binding::*;
    use crate::proposal_lifecycle::*;
    use crate::zk_voting::*;

    // ============================================================================
    // CONSTITUTIONAL ENFORCEMENT TESTS
    // ============================================================================

    #[test]
    fn test_constitution_genesis_immutability() -> Result<(), ConstitutionError> {
        let constitution = BLEEPConstitution::genesis()?;

        // Verify all immutable constraints are marked as such
        let protected = constitution.protected_constraints();
        assert!(!protected.is_empty());

        for constraint in protected {
            assert!(constraint.is_immutable);
        }

        Ok(())
    }

    #[test]
    fn test_constitutional_supply_cap_enforcement() -> Result<(), ConstitutionError> {
        let constitution = BLEEPConstitution::genesis()?;

        // Attempt to exceed supply cap
        let mut action = GovernanceAction::new(
            "supply_increase".to_string(),
            ConstitutionalScope::EconomicPolicy,
            vec!["token".to_string()],
            "Attempt to exceed supply cap".to_string(),
        );
        action.economic_change = Some(25_000_000_000); // Exceeds 21B cap

        let result = constitution.validate_action(&action)?;
        assert_eq!(
            result,
            ValidationResult::Violation(
                "Action violates constraint rule in EconomicPolicy".to_string()
            )
        );

        Ok(())
    }

    #[test]
    fn test_constitutional_inflation_cap() -> Result<(), ConstitutionError> {
        let constitution = BLEEPConstitution::genesis()?;

        // Inflation within cap
        let mut valid_action = GovernanceAction::new(
            "inflation_1".to_string(),
            ConstitutionalScope::EconomicPolicy,
            vec!["inflation".to_string()],
            "Set inflation".to_string(),
        );
        valid_action.inflation_rate = Some(400); // 4%

        let result = constitution.validate_action(&valid_action)?;
        assert_eq!(result, ValidationResult::Valid);

        // Inflation exceeds cap
        let mut invalid_action = GovernanceAction::new(
            "inflation_2".to_string(),
            ConstitutionalScope::EconomicPolicy,
            vec!["inflation".to_string()],
            "Set inflation beyond cap".to_string(),
        );
        invalid_action.inflation_rate = Some(700); // 7%

        let result = constitution.validate_action(&invalid_action)?;
        assert!(matches!(result, ValidationResult::Violation(_)));

        Ok(())
    }

    #[test]
    fn test_constitutional_slashing_cap() -> Result<(), ConstitutionError> {
        let constitution = BLEEPConstitution::genesis()?;

        // Slashing within cap
        let mut valid_action = GovernanceAction::new(
            "slash_1".to_string(),
            ConstitutionalScope::ValidatorSafety,
            vec!["slashing".to_string()],
            "Slash validator".to_string(),
        );
        valid_action.slashing_percentage = Some(2500); // 25%

        let result = constitution.validate_action(&valid_action)?;
        assert_eq!(result, ValidationResult::Valid);

        // Slashing exceeds cap
        let mut invalid_action = GovernanceAction::new(
            "slash_2".to_string(),
            ConstitutionalScope::ValidatorSafety,
            vec!["slashing".to_string()],
            "Slash validator beyond cap".to_string(),
        );
        invalid_action.slashing_percentage = Some(5000); // 50%

        let result = constitution.validate_action(&invalid_action)?;
        assert!(matches!(result, ValidationResult::Violation(_)));

        Ok(())
    }

    // ============================================================================
    // ZERO-KNOWLEDGE VOTING TESTS
    // ============================================================================

    #[test]
    fn test_zk_voting_double_vote_prevention() -> Result<(), ZKVotingError> {
        let mut engine = ZKVotingEngine::new(0);

        // Create identical ballots from same voter
        let commitment = VoteCommitment::new(
            vec![1, 2, 3],
            "prop_1".to_string(),
            b"voter_key",
            0,
            1,
            1000,
        )?;

        let proof =
            EligibilityProof::new(vec![4, 5, 6], 100, VoterRole::Validator { stake: 1000 })?;

        let ballot = EncryptedBallot::new(vec![7, 8, 9], proof, commitment, vec![10, 11, 12])?;

        let voting_ballot =
            VotingBallot::new("prop_1".to_string(), ballot.clone(), vec![13, 14, 15], 0, 0);

        // First vote succeeds
        assert!(engine.cast_vote(voting_ballot.clone()).is_ok());

        // Second vote fails (double voting)
        let result = engine.cast_vote(voting_ballot);
        assert!(matches!(result, Err(ZKVotingError::DoubleVoteDetected)));

        Ok(())
    }

    #[test]
    fn test_zk_voting_replay_resistance() -> Result<(), ZKVotingError> {
        let mut engine = ZKVotingEngine::new(0);

        // Create ballot with nonce 1
        let commitment1 = VoteCommitment::new(
            vec![1, 2, 3],
            "prop_1".to_string(),
            b"voter_1",
            0,
            1, // nonce 1
            1000,
        )?;

        let proof =
            EligibilityProof::new(vec![4, 5, 6], 100, VoterRole::Validator { stake: 1000 })?;

        let ballot1 =
            EncryptedBallot::new(vec![7, 8, 9], proof.clone(), commitment1, vec![10, 11, 12])?;

        let voting_ballot1 =
            VotingBallot::new("prop_1".to_string(), ballot1, vec![13, 14, 15], 0, 0);

        engine.cast_vote(voting_ballot1)?;

        // Try to reuse same nonce with different voter
        let commitment2 = VoteCommitment::new(
            vec![20, 21, 22],
            "prop_2".to_string(),
            b"voter_2",
            0,
            1, // Same nonce - replay!
            2000,
        )?;

        let ballot2 = EncryptedBallot::new(vec![23, 24, 25], proof, commitment2, vec![26, 27, 28])?;

        let voting_ballot2 =
            VotingBallot::new("prop_2".to_string(), ballot2, vec![29, 30, 31], 0, 1);

        let result = engine.cast_vote(voting_ballot2);
        assert!(matches!(result, Err(ZKVotingError::VoteReplayDetected)));

        Ok(())
    }

    #[test]
    fn test_zk_voting_weighted_tally() -> Result<(), ZKVotingError> {
        let mut engine = ZKVotingEngine::new(0);
        let mut revealed_votes = std::collections::HashMap::new();

        // Create validator (1.0x weight)
        let commitment_validator = VoteCommitment::new(
            vec![1, 2, 3],
            "prop_1".to_string(),
            b"validator",
            0,
            1,
            1000,
        )?;

        let proof_validator =
            EligibilityProof::new(vec![4, 5, 6], 1000, VoterRole::Validator { stake: 1000 })?;

        let ballot_validator = EncryptedBallot::new(
            vec![7, 8, 9],
            proof_validator,
            commitment_validator.clone(),
            vec![10, 11, 12],
        )?;

        let voting_ballot_validator = VotingBallot::new(
            "prop_1".to_string(),
            ballot_validator,
            vec![13, 14, 15],
            0,
            0,
        );

        engine.cast_vote(voting_ballot_validator)?;
        revealed_votes.insert(commitment_validator.commitment_hash.clone(), true); // YES

        // Create delegator (0.5x weight)
        let commitment_delegator = VoteCommitment::new(
            vec![20, 21, 22],
            "prop_1".to_string(),
            b"delegator",
            0,
            2,
            2000,
        )?;

        let proof_delegator =
            EligibilityProof::new(vec![23, 24, 25], 500, VoterRole::Delegator { stake: 1000 })?;

        let ballot_delegator = EncryptedBallot::new(
            vec![26, 27, 28],
            proof_delegator,
            commitment_delegator.clone(),
            vec![29, 30, 31],
        )?;

        let voting_ballot_delegator = VotingBallot::new(
            "prop_1".to_string(),
            ballot_delegator,
            vec![32, 33, 34],
            0,
            1,
        );

        engine.cast_vote(voting_ballot_delegator)?;
        revealed_votes.insert(commitment_delegator.commitment_hash.clone(), false); // NO

        let tally = engine.compute_tally("prop_1", &revealed_votes)?;

        // Validator YES (1000 power) vs Delegator NO (500 power)
        // YES should have 66.7%
        assert!(tally.yes_percentage > 66.0 && tally.yes_percentage < 67.0);
        assert_eq!(tally.voter_count, 2);

        Ok(())
    }

    // ============================================================================
    // PROPOSAL LIFECYCLE TESTS
    // ============================================================================

    #[test]
    fn test_proposal_lifecycle_full() -> Result<(), Box<dyn std::error::Error>> {
        let constitution = BLEEPConstitution::genesis()?;
        let mut manager = ProposalLifecycleManager::new(
            constitution,
            0,
            10,   // 10 epoch voting period
            7000, // 70% threshold
        )?;

        let action = GovernanceAction::new(
            "action_1".to_string(),
            ConstitutionalScope::Governance,
            vec!["governance".to_string()],
            "Test proposal".to_string(),
        );

        // Create proposal
        manager.propose("prop_1".to_string(), "proposer".to_string(), action)?;

        // Validate constitutionally
        let result = manager.validate_proposal("prop_1")?;
        assert_eq!(result, ValidationResult::Valid);

        // Start voting
        manager.start_voting("prop_1")?;

        // Simulate voting
        let tally = VoteTally {
            proposal_id: "prop_1".to_string(),
            yes_votes: 7000,
            no_votes: 3000,
            total_weighted_votes: 10000,
            yes_percentage: 70.0,
            voter_count: 100,
        };

        let proof = TallyProof {
            tally_hash: vec![1, 2, 3],
            yes_votes: 7000,
            no_votes: 3000,
            total_votes: 10000,
            voter_count: 100,
        };

        manager.record_tally("prop_1", tally, proof)?;

        // Schedule activation
        manager.advance_epoch(100);
        manager.schedule_activation("prop_1", 20)?;

        // Execute
        manager.advance_epoch(200);
        manager.execute_proposal("prop_1", vec![1, 2, 3])?;

        let proposal = manager.get_proposal("prop_1").unwrap();
        assert_eq!(proposal.state, ProposalState::Executed);

        Ok(())
    }

    #[test]
    fn test_proposal_constitutional_rejection() -> Result<(), Box<dyn std::error::Error>> {
        let constitution = BLEEPConstitution::genesis()?;
        let mut manager = ProposalLifecycleManager::new(constitution, 0, 10, 7000)?;

        // Create action that violates supply cap
        let mut action = GovernanceAction::new(
            "action_1".to_string(),
            ConstitutionalScope::EconomicPolicy,
            vec!["token".to_string()],
            "Increase supply beyond cap".to_string(),
        );
        action.economic_change = Some(30_000_000_000); // Exceeds cap

        manager.propose("prop_1".to_string(), "proposer".to_string(), action)?;

        // Validate - should fail constitutional check
        let result = manager.validate_proposal("prop_1")?;
        assert!(matches!(result, ValidationResult::Violation(_)));

        let proposal = manager.get_proposal("prop_1").unwrap();
        assert_eq!(proposal.state, ProposalState::Rejected);

        Ok(())
    }

    // ============================================================================
    // FORKLESS UPGRADE TESTS
    // ============================================================================

    #[test]
    fn test_upgrade_version_monotonicity() {
        let mut manager = ProtocolUpgradeManager::genesis();

        let v1_1 = UpgradePayload::new(
            "upgrade_1".to_string(),
            Version::new(1, 1, 0),
            "Minor upgrade".to_string(),
            UpgradePreconditions {
                min_validator_participation: 6600,
                min_epochs_since_last_upgrade: 10,
                requires_finality: true,
                requires_shard_health: true,
            },
        );

        // Approve upgrade
        assert!(manager.approve_upgrade(v1_1, 0, 7000, 3000, 10).is_ok());

        // Try to approve downgrade
        let v1_0 = UpgradePayload::new(
            "upgrade_downgrade".to_string(),
            Version::new(1, 0, 1),
            "Attempt downgrade".to_string(),
            UpgradePreconditions {
                min_validator_participation: 6600,
                min_epochs_since_last_upgrade: 10,
                requires_finality: true,
                requires_shard_health: true,
            },
        );

        // Should fail - version already executed or conflicts
        assert!(manager.approve_upgrade(v1_0, 0, 7000, 3000, 20).is_ok()); // Approval ok

        // But execution should fail
        manager
            .execute_upgrade(Version::new(1, 1, 0), vec![1])
            .unwrap();
        let result = manager.execute_upgrade(Version::new(1, 0, 1), vec![2]);
        assert!(result.is_err()); // Can't downgrade
    }

    #[test]
    fn test_upgrade_checkpoint_and_rollback() -> Result<(), UpgradeError> {
        let mut manager = ProtocolUpgradeManager::genesis();

        // Create checkpoint
        let checkpoint = manager.create_checkpoint(
            vec![1, 2, 3], // state root
            100,
            0,
        )?;

        assert!(checkpoint.verify_hash()?);

        // Simulate upgrade
        let upgrade = UpgradePayload::new(
            "upgrade_1".to_string(),
            Version::new(1, 1, 0),
            "Test upgrade".to_string(),
            UpgradePreconditions {
                min_validator_participation: 6600,
                min_epochs_since_last_upgrade: 10,
                requires_finality: true,
                requires_shard_health: true,
            },
        );

        manager.approve_upgrade(upgrade, 0, 7000, 3000, 10)?;
        manager.activate_upgrade(Version::new(1, 1, 0), 10)?;
        manager.execute_upgrade(Version::new(1, 1, 0), vec![1, 2, 3])?;

        // Rollback
        let rolled_back = manager.rollback(Version::new(1, 0, 0))?;
        assert_eq!(rolled_back.version_before, Version::new(1, 0, 0));
        assert_eq!(manager.current_version, Version::new(1, 0, 0));

        Ok(())
    }

    // ============================================================================
    // GOVERNANCE-CONSENSUS BINDING TESTS
    // ============================================================================

    #[test]
    fn test_governance_consensus_binding_finality() -> Result<(), BindingError> {
        let mut binding = GovernanceConsensusBinding::new(
            Version::new(1, 0, 0),
            0,
            2, // 2 block finality depth
        );

        let action = FinalizedGovernanceAction::new(
            "action_1".to_string(),
            "Test action".to_string(),
            VoteTally {
                proposal_id: "prop_1".to_string(),
                yes_votes: 7000,
                no_votes: 3000,
                total_weighted_votes: 10000,
                yes_percentage: 70.0,
                voter_count: 100,
            },
            true,
            vec![1, 2, 3],
            0,
            2,  // Finality depth = 2
            10, // Activation epoch 10
        );

        binding.record_finalized_action(action)?;

        // Can't activate yet (no finality)
        binding.current_block_height = 5; // 5 blocks, need 2+2=4
        assert!(binding.can_activate("action_1").is_err());

        // With enough blocks, can't activate (not at activation epoch)
        binding.current_epoch = 5;
        binding.current_block_height = 10;
        assert!(!binding.can_activate("action_1")?);

        // At activation epoch with finality
        binding.current_epoch = 10;
        assert!(binding.can_activate("action_1")?);

        Ok(())
    }

    #[test]
    fn test_upgrade_version_enforcement() -> Result<(), BindingError> {
        let mut binding = GovernanceConsensusBinding::new(Version::new(1, 0, 0), 0, 2);

        // Valid upgrade
        assert!(binding
            .verify_upgrade_activation(Version::new(1, 1, 0))
            .is_ok());

        // Record upgrade
        binding.record_upgrade_activation(Version::new(1, 1, 0))?;
        assert_eq!(binding.protocol_version, Version::new(1, 1, 0));

        // Try invalid downgrade
        let result = binding.verify_upgrade_activation(Version::new(1, 0, 5));
        assert!(result.is_err());

        Ok(())
    }

    // ============================================================================
    // ADVERSARIAL TEST CASES
    // ============================================================================

    #[test]
    fn test_adversarial_tally_manipulation() -> Result<(), ZKVotingError> {
        let mut engine = ZKVotingEngine::new(0);
        let mut revealed_votes = std::collections::HashMap::new();

        // Honest votes
        for i in 0..5 {
            let commitment = VoteCommitment::new(
                vec![i as u8, 2, 3],
                "prop_1".to_string(),
                format!("voter_{}", i).as_bytes(),
                0,
                i as u64,
                1000 + i as u64,
            )?;

            let proof =
                EligibilityProof::new(vec![4, 5, 6], 100, VoterRole::Validator { stake: 1000 })?;

            let ballot =
                EncryptedBallot::new(vec![7, 8, 9], proof, commitment.clone(), vec![10, 11, 12])?;

            let voting_ballot =
                VotingBallot::new("prop_1".to_string(), ballot, vec![13, 14, 15], 0, i as u64);

            engine.cast_vote(voting_ballot)?;
            revealed_votes.insert(commitment.commitment_hash.clone(), i % 2 == 0);
            // Alternate YES/NO
        }

        // Try to cast extra vote with forged commitment
        let forged_commitment = VoteCommitment::new(
            vec![255, 254, 253],
            "prop_1".to_string(),
            b"forged_voter",
            0,
            100,
            5000,
        )?;

        let proof = EligibilityProof::new(vec![4, 5, 6], 100, VoterRole::Community { stake: 100 })?;

        let forged_ballot = EncryptedBallot::new(
            vec![7, 8, 9],
            proof,
            forged_commitment.clone(),
            vec![10, 11, 12],
        )?;

        let forged_voting_ballot =
            VotingBallot::new("prop_1".to_string(), forged_ballot, vec![13, 14, 15], 0, 99);

        // Forged vote should succeed (added to engine)
        engine.cast_vote(forged_voting_ballot)?;

        // But tally should fail if we don't include the forged vote in revealed_votes
        let result = engine.compute_tally("prop_1", &revealed_votes);
        assert!(result.is_err()); // Tally count mismatch

        Ok(())
    }
}
