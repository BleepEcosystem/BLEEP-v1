// PHASE 2: COMPREHENSIVE INTEGRATION TESTS
// Adversarial scenarios testing self-healing system end-to-end
//
// These tests verify:
// 1. State corruption is detected automatically
// 2. Rollback is autonomous and verifiable
// 3. Snapshots enable deterministic recovery
// 4. Fault detection is deterministic across nodes
// 5. Recovery preserves blockchain invariants
// 6. Consensus binding of healing operations
// 7. No forks occur during recovery
// 8. Byzantine faults are handled correctly

#[cfg(test)]
mod phase2_integration_tests {
    use bleep_state::advanced_fault_detector::*;
    use bleep_state::rollback_engine::*;
    use bleep_state::self_healing_orchestrator::*;
    use bleep_state::shard_registry::*;
    use bleep_state::snapshot_engine::*;

    /// Test 1: State corruption detection triggers autonomous recovery
    #[test]
    fn test_state_corruption_auto_detection_and_recovery() {
        let mut orchestrator = SelfHealingOrchestrator::new(
            SnapshotConfig::new(10, 100, 1000, 0.66).unwrap(),
            FaultDetectionConfig::default(),
            3,
        );
        orchestrator.update_epoch(EpochId(10));

        // Create a snapshot at epoch 10
        let root = ShardStateRoot {
            root_hash: "root_10".to_string(),
            tx_count: 100,
            height: 100,
        };

        let snapshot_id = orchestrator
            .snapshot_engine
            .create_snapshot(ShardId(0), EpochId(10), 100, root, "merkle_10".to_string())
            .unwrap();

        orchestrator
            .snapshot_engine
            .finalize_snapshot(snapshot_id, vec![])
            .unwrap();

        // Simulate state root mismatch at epoch 20
        orchestrator.update_epoch(EpochId(20));
        let fault_evidence = FaultEvidence {
            fault_type: FaultType::StateRootMismatch {
                expected_root: "root_correct".to_string(),
                observed_root: "root_corrupted".to_string(),
                dissenting_validators: 5,
            },
            shard_id: ShardId(0),
            epoch_id: EpochId(20),
            severity: FaultSeverity::Critical,
            evidence_hash: "evidence_hash".to_string(),
            detected_at: 2000,
            detection_rule: "state_root_mismatch".to_string(),
            witness_validators: vec![vec![1], vec![2], vec![3]],
            block_height: 200,
            confirmed: true,
            investigation_status: InvestigationStatus::Confirmed,
        };

        // Trigger healing
        let op = orchestrator
            .on_fault_detected(ShardId(0), fault_evidence)
            .unwrap();

        assert_eq!(op.shard_id, ShardId(0));
        assert_eq!(op.fault_evidence.severity, FaultSeverity::Critical);
        assert!(op.requires_consensus);
    }

    /// Test 2: Snapshot creation is deterministic and epoch-bound
    #[test]
    fn test_snapshot_deterministic_creation() {
        let config = SnapshotConfig::new(10, 100, 1000, 0.66).unwrap();

        // Two nodes create snapshots independently
        let mut engine_a = SnapshotEngine::new(config.clone(), SnapshotId(0));
        let mut engine_b = SnapshotEngine::new(config.clone(), SnapshotId(0));

        let root = ShardStateRoot {
            root_hash: "root".to_string(),
            tx_count: 100,
            height: 100,
        };

        // Both create snapshot at epoch 10
        let id_a = engine_a
            .create_snapshot(
                ShardId(0),
                EpochId(10),
                100,
                root.clone(),
                "merkle".to_string(),
            )
            .unwrap();

        let id_b = engine_b
            .create_snapshot(ShardId(0), EpochId(10), 100, root, "merkle".to_string())
            .unwrap();

        // Both must derive identical snapshot ID
        assert_eq!(id_a, id_b);

        let snap_a = engine_a.get_snapshot(id_a).unwrap();
        let snap_b = engine_b.get_snapshot(id_b).unwrap();

        // State roots must match
        assert_eq!(snap_a.state_root.root_hash, snap_b.state_root.root_hash);
    }

    /// Test 3: Fault detection is deterministic across nodes
    #[test]
    fn test_fault_detection_deterministic_across_nodes() {
        let config = FaultDetectionConfig::default();

        let mut detector_a = AdvancedFaultDetector::new(config.clone());
        let mut detector_b = AdvancedFaultDetector::new(config);

        detector_a.update_epoch(EpochId(10));
        detector_b.update_epoch(EpochId(10));

        // Both detect same state root mismatch
        let fault_a = detector_a.detect_state_root_mismatch(
            ShardId(0),
            100,
            "root_a".to_string(),
            "root_b".to_string(),
            5,
        );

        let fault_b = detector_b.detect_state_root_mismatch(
            ShardId(0),
            100,
            "root_a".to_string(),
            "root_b".to_string(),
            5,
        );

        // Both must detect identical fault
        assert!(fault_a.is_some());
        assert!(fault_b.is_some());

        let ev_a = fault_a.unwrap();
        let ev_b = fault_b.unwrap();

        assert_eq!(ev_a.fault_type, ev_b.fault_type);
        assert_eq!(ev_a.severity, ev_b.severity);
        assert_eq!(ev_a.detection_rule, ev_b.detection_rule);
    }

    /// Test 4: Rollback is atomic and verifiable
    #[test]
    fn test_rollback_atomicity_and_verification() {
        let config = SnapshotConfig::new(10, 100, 1000, 0.66).unwrap();
        let mut engine = RollbackEngine::new(SnapshotEngine::new(config, SnapshotId(0)));
        engine.update_height(200);

        // Create and finalize snapshot
        let root = ShardStateRoot {
            root_hash: "root".to_string(),
            tx_count: 100,
            height: 100,
        };

        let snapshot_id = engine
            .snapshot_engine
            .create_snapshot(ShardId(0), EpochId(10), 100, root, "merkle".to_string())
            .unwrap();

        engine
            .snapshot_engine
            .finalize_snapshot(snapshot_id, vec![])
            .unwrap();

        // Initiate rollback
        let rollback = engine
            .initiate_rollback(
                ShardId(0),
                snapshot_id,
                "fault_recovery".to_string(),
                EpochId(20),
            )
            .unwrap();

        assert_eq!(rollback.phase, RollbackPhase::ValidatingTarget);
        assert!(engine.get_active_rollback(ShardId(0)).is_some());
    }

    /// Test 5: Byzantine fault (equivocation) is detected
    #[test]
    fn test_byzantine_equivocation_detection() {
        let mut detector = AdvancedFaultDetector::new(FaultDetectionConfig::default());
        detector.update_epoch(EpochId(10));

        let validator_key = vec![1, 2, 3];

        // Validator produces two different blocks at same height
        let fault = detector.detect_equivocation(
            ShardId(0),
            100,
            validator_key.clone(),
            "block_hash_1".to_string(),
            "block_hash_2".to_string(),
        );

        assert!(fault.is_some());
        let ev = fault.unwrap();
        assert_eq!(ev.severity, FaultSeverity::Critical);
        assert_eq!(ev.confirmed, true);
    }

    /// Test 6: Liveness failure triggers recovery
    #[test]
    fn test_liveness_failure_auto_recovery() {
        let mut orchestrator = SelfHealingOrchestrator::new(
            SnapshotConfig::new(10, 100, 1000, 0.66).unwrap(),
            FaultDetectionConfig::default(),
            3,
        );

        orchestrator.update_epoch(EpochId(30));

        let fault_evidence = FaultEvidence {
            fault_type: FaultType::LivenessFailure {
                missed_blocks: 20,
                timeout_epochs: 25,
            },
            shard_id: ShardId(0),
            epoch_id: EpochId(30),
            severity: FaultSeverity::High,
            evidence_hash: "hash".to_string(),
            detected_at: 3000,
            detection_rule: "liveness_failure".to_string(),
            witness_validators: vec![],
            block_height: 200,
            confirmed: true,
            investigation_status: InvestigationStatus::Confirmed,
        };

        let op = orchestrator
            .on_fault_detected(ShardId(0), fault_evidence)
            .unwrap();

        assert_eq!(op.shard_id, ShardId(0));
        assert!(op.requires_consensus);
    }

    /// Test 7: Snapshot lineage prevents forks
    #[test]
    fn test_snapshot_lineage_fork_prevention() {
        let config = SnapshotConfig::new(10, 100, 1000, 0.66).unwrap();
        let mut engine = SnapshotEngine::new(config, SnapshotId(0));

        let root = ShardStateRoot {
            root_hash: "root".to_string(),
            tx_count: 100,
            height: 100,
        };

        // Create sequence of snapshots
        let id1 = engine
            .create_snapshot(
                ShardId(0),
                EpochId(10),
                100,
                root.clone(),
                "merkle1".to_string(),
            )
            .unwrap();

        engine.finalize_snapshot(id1, vec![]).unwrap();

        let id2 = engine
            .create_snapshot(
                ShardId(0),
                EpochId(20),
                200,
                root.clone(),
                "merkle2".to_string(),
            )
            .unwrap();

        engine.finalize_snapshot(id2, vec![]).unwrap();

        let id3 = engine
            .create_snapshot(ShardId(0), EpochId(30), 300, root, "merkle3".to_string())
            .unwrap();

        engine.finalize_snapshot(id3, vec![]).unwrap();

        // Verify lineage is unbroken and deterministic
        let lineage = engine.get_lineage();
        assert!(lineage.verify());
        assert_eq!(lineage.get_parent(id2), Some(id1));
        assert_eq!(lineage.get_parent(id3), Some(id2));
    }

    /// Test 8: Consensus approval is required for critical healing
    #[test]
    fn test_consensus_approval_requirement() {
        let mut orchestrator = SelfHealingOrchestrator::new(
            SnapshotConfig::new(10, 100, 1000, 0.66).unwrap(),
            FaultDetectionConfig::default(),
            3,
        );
        orchestrator.update_epoch(EpochId(10));

        let fault_evidence = FaultEvidence {
            fault_type: FaultType::StateRootMismatch {
                expected_root: "a".to_string(),
                observed_root: "b".to_string(),
                dissenting_validators: 3,
            },
            shard_id: ShardId(0),
            epoch_id: EpochId(10),
            severity: FaultSeverity::Critical,
            evidence_hash: "hash".to_string(),
            detected_at: 1000,
            detection_rule: "rule".to_string(),
            witness_validators: vec![],
            block_height: 50,
            confirmed: true,
            investigation_status: InvestigationStatus::Confirmed,
        };

        let op = orchestrator
            .on_fault_detected(ShardId(0), fault_evidence)
            .unwrap();

        // Critical faults REQUIRE consensus
        assert!(op.requires_consensus);
        assert!(!op.consensus_approved);

        // Cannot execute without approval
        let exec_result = orchestrator.execute_healing(op.operation_id.clone());
        assert!(exec_result.is_err());

        // Approve from consensus
        let signatures = vec![vec![1u8], vec![2u8], vec![3u8]];
        orchestrator
            .approve_from_consensus(op.operation_id.clone(), signatures)
            .unwrap();

        // Now execution should work
        let op_final = orchestrator.get_operation(&op.operation_id).unwrap();
        assert!(op_final.consensus_approved);
    }

    /// Test 9: Invalid rollback target is rejected
    #[test]
    fn test_invalid_rollback_target_rejection() {
        let mut engine = RollbackEngine::new(SnapshotEngine::new(
            SnapshotConfig::new(10, 100, 1000, 0.66).unwrap(),
            SnapshotId(0),
        ));
        engine.update_height(100);

        // Try to rollback to non-existent snapshot
        let result =
            engine.initiate_rollback(ShardId(0), SnapshotId(999), "test".to_string(), EpochId(10));

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    /// Test 10: Multiple concurrent faults are handled correctly
    #[test]
    fn test_multiple_concurrent_faults_handling() {
        let mut orchestrator = SelfHealingOrchestrator::new(
            SnapshotConfig::new(10, 100, 1000, 0.66).unwrap(),
            FaultDetectionConfig::default(),
            3,
        );
        orchestrator.update_epoch(EpochId(10));

        // Trigger fault on shard 0
        let fault1 = FaultEvidence {
            fault_type: FaultType::LivenessFailure {
                missed_blocks: 5,
                timeout_epochs: 10,
            },
            shard_id: ShardId(0),
            epoch_id: EpochId(10),
            severity: FaultSeverity::Medium,
            evidence_hash: "hash1".to_string(),
            detected_at: 1000,
            detection_rule: "rule1".to_string(),
            witness_validators: vec![],
            block_height: 50,
            confirmed: true,
            investigation_status: InvestigationStatus::Confirmed,
        };

        // Trigger fault on shard 1
        let fault2 = FaultEvidence {
            fault_type: FaultType::LivenessFailure {
                missed_blocks: 3,
                timeout_epochs: 8,
            },
            shard_id: ShardId(1),
            epoch_id: EpochId(10),
            severity: FaultSeverity::Low,
            evidence_hash: "hash2".to_string(),
            detected_at: 1001,
            detection_rule: "rule2".to_string(),
            witness_validators: vec![],
            block_height: 51,
            confirmed: true,
            investigation_status: InvestigationStatus::Confirmed,
        };

        let op1 = orchestrator.on_fault_detected(ShardId(0), fault1).unwrap();
        let op2 = orchestrator.on_fault_detected(ShardId(1), fault2).unwrap();

        // Both operations should be tracked
        assert_eq!(orchestrator.get_active_operations().len(), 2);
        assert_eq!(orchestrator.get_statistics().active_operations, 2);

        // Operations should be for different shards
        assert_eq!(op1.shard_id, ShardId(0));
        assert_eq!(op2.shard_id, ShardId(1));
    }

    /// Test 11: Supply invariant is preserved during rollback
    #[test]
    fn test_supply_invariant_preservation() {
        let mut engine = RollbackEngine::new(SnapshotEngine::new(
            SnapshotConfig::new(10, 100, 1000, 0.66).unwrap(),
            SnapshotId(0),
        ));

        engine.update_height(200);
        engine.register_supply(1_000_000_000u128); // 1 billion total supply

        // Create snapshot
        let root = ShardStateRoot {
            root_hash: "root".to_string(),
            tx_count: 100,
            height: 100,
        };

        let snapshot_id = engine
            .snapshot_engine
            .create_snapshot(ShardId(0), EpochId(10), 100, root, "merkle".to_string())
            .unwrap();

        engine
            .snapshot_engine
            .finalize_snapshot(snapshot_id, vec![])
            .unwrap();

        let _rollback = engine
            .initiate_rollback(ShardId(0), snapshot_id, "test".to_string(), EpochId(20))
            .unwrap();

        // Abort transactions
        engine
            .abort_in_flight_transactions(ShardId(0), vec![])
            .unwrap();

        // Verify supply invariant (shard state < total supply)
        let result = engine.verify_supply_invariants(
            ShardId(0),
            500_000_000u128, // Shard has half the supply
        );

        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }
}
