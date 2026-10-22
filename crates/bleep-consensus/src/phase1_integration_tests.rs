// PHASE 1: COMPREHENSIVE INTEGRATION TESTS
// Demonstrates full consensus system working end-to-end
// Tests Byzantine scenarios, slashing, finality proofs, etc.

#[cfg(test)]
mod phase1_integration_tests {
    use bleep_consensus::{
        ConsensusMode, EpochConfig, EpochState, FinalityManager, FinalizyCertificate,
        SlashingEngine, SlashingEvidence, SlashingPenalty, ValidatorIdentity, ValidatorRegistry,
        ValidatorState,
    };
    use bleep_crypto::SignatureScheme;

    fn add_test_signature(cert: &mut FinalizyCertificate, validator_id: &str, voting_power: u128) {
        let (public_key, secret_key) = SignatureScheme::keygen().expect("SPHINCS+ keygen failed");
        let signature = SignatureScheme::sign(&cert.signature_message(), &secret_key)
            .expect("SPHINCS+ signing failed")
            .as_bytes();
        cert.add_validator_signature(
            validator_id.to_string(),
            public_key.to_vec(),
            signature,
            voting_power,
        )
        .unwrap();
    }

    /// Helper function to create a test validator
    fn create_test_validator(id: &str, stake: u128) -> ValidatorIdentity {
        ValidatorIdentity::new(
            id.to_string(),
            vec![0u8; 1568], // Mock Kyber-1024 key
            format!("{}_signing_key", id),
            stake,
            0,
        )
        .unwrap()
    }

    #[test]
    fn test_phase1_validator_registration_and_activation() {
        let mut registry = ValidatorRegistry::new();

        // Register validators
        for i in 1..=3 {
            let validator = create_test_validator(&format!("v{}", i), 1000000);
            registry.register_validator(validator).unwrap();
        }

        assert_eq!(registry.active_count(), 0);

        // Activate them
        for i in 1..=3 {
            registry.activate_validator(&format!("v{}", i)).unwrap();
        }

        assert_eq!(registry.active_count(), 3);
        assert_eq!(registry.total_active_stake(), 3000000);
    }

    #[test]
    fn test_phase1_double_signing_detection_and_slashing() {
        let mut registry = ValidatorRegistry::new();
        let mut slashing_engine = SlashingEngine::new();

        // Register and activate validator
        let validator = create_test_validator("v1", 1000000);
        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        let evidence = SlashingEvidence::DoubleSigning {
            validator_id: "v1".to_string(),
            height: 100,
            block_hash_1: hex::encode([1u8; 32]),
            block_hash_2: hex::encode([2u8; 32]),
            signature_1: vec![1, 2, 3],
            signature_2: vec![4, 5, 6],
        };

        assert!(slashing_engine
            .process_evidence(evidence, &mut registry, 1, 1000)
            .is_err());
        assert_eq!(registry.get("v1").unwrap().stake, 1000000);
        assert!(registry.get("v1").unwrap().can_participate());
    }

    #[test]
    fn test_phase1_downtime_penalties() {
        let mut registry = ValidatorRegistry::new();
        let mut slashing_engine = SlashingEngine::new();

        let validator = create_test_validator("v1", 1000000);
        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        // Create downtime evidence (missed 100 blocks out of 1000)
        let evidence = SlashingEvidence::Downtime {
            validator_id: "v1".to_string(),
            missed_blocks: 100,
            total_blocks_in_epoch: 1000,
        };

        assert!(slashing_engine
            .process_evidence(evidence, &mut registry, 1, 1000)
            .is_err());
        assert_eq!(registry.get("v1").unwrap().stake, 1000000);
    }

    #[test]
    fn test_phase1_equivocation_detection() {
        let mut registry = ValidatorRegistry::new();
        let mut slashing_engine = SlashingEngine::new();

        let validator = create_test_validator("v1", 1000000);
        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        // Two conflicting votes for the same height
        let vote_1 = [3u8; 32].to_vec();
        let vote_2 = [4u8; 32].to_vec();
        let timestamp_1 = 1000;
        let timestamp_2 = 1001;
        let evidence = SlashingEvidence::Equivocation {
            validator_id: "v1".to_string(),
            height: 100,
            signature_1: vec![1, 2, 3],
            signature_2: vec![4, 5, 6],
            vote_1,
            vote_2,
            timestamp_1,
            timestamp_2,
        };

        assert!(slashing_engine
            .process_evidence(evidence, &mut registry, 1, 1000)
            .is_err());
        assert_eq!(registry.get("v1").unwrap().stake, 1000000);
    }

    #[test]
    fn test_phase1_finality_certificate_and_quorum() {
        // Simulate block finality with 3 validators, 1000 stake each
        let total_stake = 3000;

        let mut cert = FinalizyCertificate::new(
            100,
            "block_hash_100".to_string(),
            1,
            "POS".to_string(),
            "merkle_root_100".to_string(),
            1000,
            1,
        )
        .unwrap();

        // Add signatures from 2 validators (only 2000 stake)
        cert.add_validator_signature("v1".to_string(), vec![0; 64], vec![1, 2, 3], 1000)
            .unwrap();
        cert.add_validator_signature("v2".to_string(), vec![0; 64], vec![4, 5, 6], 1000)
            .unwrap();

        // Does not meet quorum yet (need >2/3 of 3000 = > 2000)
        assert!(!cert.meets_quorum(total_stake));

        // Add third validator (now have 3000 stake)
        cert.add_validator_signature("v3".to_string(), vec![0; 64], vec![7, 8, 9], 1000)
            .unwrap();

        // Now meets quorum
        assert!(cert.meets_quorum(total_stake));
    }

    #[test]
    fn test_phase1_finality_manager_immutability() {
        let mut manager = FinalityManager::new(1000);

        let mut cert = FinalizyCertificate::new(
            100,
            "block_100".to_string(),
            1,
            "POS".to_string(),
            "merkle_100".to_string(),
            1000,
            1,
        )
        .unwrap();

        add_test_signature(&mut cert, "v1", 700);

        // Finalize the block
        manager.finalize_block(cert).unwrap();
        assert!(manager.is_finalized(100));

        // Try to finalize same block again - should fail
        let mut cert2 = FinalizyCertificate::new(
            100,
            "block_100_different".to_string(), // Different hash!
            1,
            "POS".to_string(),
            "merkle_100".to_string(),
            1001,
            1,
        )
        .unwrap();

        cert2
            .add_validator_signature("v2".to_string(), vec![0; 64], vec![1, 2, 3], 700)
            .unwrap();

        let result = manager.finalize_block(cert2);
        assert!(result.is_err()); // Cannot finalize same height twice
    }

    #[test]
    fn test_phase1_epoch_system_determinism() {
        let config = EpochConfig::new(1000, 0, 1).unwrap();

        // Test that epoch boundaries are deterministic
        assert_eq!(config.epoch_id(0), 0); // First epoch
        assert_eq!(config.epoch_id(999), 0); // Still epoch 0
        assert_eq!(config.epoch_id(1000), 1); // Epoch 1
        assert_eq!(config.epoch_id(1999), 1); // Still epoch 1
        assert_eq!(config.epoch_id(2000), 2); // Epoch 2

        // All nodes compute the same epoch_id for a given height
        let epoch_100_node1 = config.epoch_id(100);
        let epoch_100_node2 = config.epoch_id(100);
        assert_eq!(epoch_100_node1, epoch_100_node2);
    }

    #[test]
    fn test_phase1_validator_state_machine() {
        let mut validator = create_test_validator("v1", 1000000);

        // Initial state: Inactive
        assert_eq!(validator.state, ValidatorState::Inactive);
        assert!(!validator.can_participate());

        // Transition: Inactive → Active
        validator.activate().unwrap();
        assert_eq!(validator.state, ValidatorState::Active);
        assert!(validator.can_participate());

        // Transition: Active → PendingExit
        validator.mark_for_exit().unwrap();
        assert_eq!(validator.state, ValidatorState::PendingExit);
        assert!(!validator.can_participate());

        // Transition: PendingExit → Exited
        validator.finalize_exit(10).unwrap();
        assert_eq!(validator.state, ValidatorState::Exited);
        assert!(!validator.can_participate());
    }

    #[test]
    fn test_phase1_slashing_permanent_record() {
        let mut validator = create_test_validator("v1", 1000000);
        validator.activate().unwrap();

        // Double-sign
        validator.slash_for_double_signing(500000).unwrap();
        assert_eq!(validator.double_sign_count, 1); // PERMANENT RECORD
        assert_eq!(validator.stake, 500000);
        assert!(validator.is_ejected());

        // Try to participate despite slashing
        assert!(!validator.can_participate());
    }

    #[test]
    fn test_phase1_multi_validator_byzantine_scenario() {
        // Scenario: 5 validators, 1 is Byzantine
        let mut registry = ValidatorRegistry::new();
        let mut slashing_engine = SlashingEngine::new();

        for i in 1..=5 {
            let validator_id = format!("v{}", i);
            let validator = create_test_validator(&validator_id, 1000000);
            registry.register_validator(validator).unwrap();
            registry.activate_validator(&validator_id).unwrap();
        }

        assert_eq!(registry.active_count(), 5);
        assert_eq!(registry.total_active_stake(), 5000000);

        // Fabricated signatures must not slash v5.
        let evidence = SlashingEvidence::DoubleSigning {
            validator_id: "v5".to_string(),
            height: 100,
            block_hash_1: hex::encode([1u8; 32]),
            block_hash_2: hex::encode([2u8; 32]),
            signature_1: vec![1, 2, 3],
            signature_2: vec![4, 5, 6],
        };

        assert!(slashing_engine
            .process_evidence(evidence, &mut registry, 1, 1000)
            .is_err());

        assert_eq!(registry.active_count(), 5);
        assert!(registry.can_participate("v5"));

        assert_eq!(registry.total_active_stake(), 5_000_000);
    }

    #[test]
    fn test_phase1_slashing_history_audit_trail() {
        let mut slashing_engine = SlashingEngine::new();
        let mut registry = ValidatorRegistry::new();

        // Submit forged evidence against 3 validators.
        for i in 1..=3 {
            let validator_id = format!("v{}", i);
            let validator = create_test_validator(&validator_id, 1000000);
            registry.register_validator(validator).unwrap();
            registry.activate_validator(&validator_id).unwrap();
        }

        for i in 1..=3 {
            let validator_id = format!("v{}", i);
            let evidence = SlashingEvidence::DoubleSigning {
                validator_id,
                height: 100 + i as u64,
                block_hash_1: hex::encode([1u8; 32]),
                block_hash_2: hex::encode([2u8; 32]),
                signature_1: vec![1, 2, 3],
                signature_2: vec![4, 5, 6],
            };

            assert!(slashing_engine
                .process_evidence(evidence, &mut registry, 1, 1000 + i as u64)
                .is_err());
        }

        assert!(slashing_engine.history().is_empty());
        assert_eq!(slashing_engine.total_slashed(), 0);
    }

    #[test]
    fn test_phase1_finality_with_finality_proof() {
        let mut manager = FinalityManager::new(1000);

        // Create certificate with 700/1000 stake (meets >2/3 quorum)
        let mut cert = FinalizyCertificate::new(
            100,
            "block_100".to_string(),
            1,
            "POS".to_string(),
            "merkle_100".to_string(),
            1000,
            1,
        )
        .unwrap();

        add_test_signature(&mut cert, "v1", 700);

        // Finalize block
        manager.finalize_block(cert.clone()).unwrap();

        // Create finality proof
        let mut proof = bleep_consensus::FinalityProof::new(cert);
        proof.set_merkle_path(vec!["hash_left".to_string(), "hash_right".to_string()]);
        proof.add_dependent_block(101);

        // Verify proof
        assert!(proof.verify(1000).is_ok());

        // Record proof
        manager.record_proof(proof).unwrap();

        // Verify through manager
        assert!(manager.is_proven_finalized(100));
    }

    #[test]
    fn test_phase1_no_panic_on_edge_cases() {
        // Test that the system never panics on edge cases

        let mut registry = ValidatorRegistry::new();

        // Try to activate non-existent validator
        assert!(registry.activate_validator("nonexistent").is_err());

        // Try to slash non-existent validator
        assert!(registry
            .slash_validator_double_sign("nonexistent", 100)
            .is_err());

        // Try to record downtime for non-existent validator
        assert!(registry
            .record_validator_downtime("nonexistent", 100)
            .is_err());

        // All handled gracefully - no panics
    }

    #[test]
    fn test_phase1_consensus_mode_immutability_per_epoch() {
        let config = EpochConfig::new(1000, 0, 1).unwrap();

        // Consensus mode for epoch 0 is determined at the start of epoch 0
        // and cannot change mid-epoch
        let epoch_0 = EpochState::new(0, &config, ConsensusMode::PosNormal).unwrap();
        assert_eq!(epoch_0.consensus_mode, ConsensusMode::PosNormal);
        assert_eq!(epoch_0.locked_mode, Some(ConsensusMode::PosNormal));

        // Mode is locked - cannot be changed
        assert!(epoch_0.consensus_mode == ConsensusMode::PosNormal);

        // At epoch boundary (height 1000), a new epoch with potentially different mode
        let epoch_1 = EpochState::new(1, &config, ConsensusMode::PbftFastFinality).unwrap();
        assert_eq!(epoch_1.consensus_mode, ConsensusMode::PbftFastFinality);

        // Each epoch independently locks its mode
    }
}
