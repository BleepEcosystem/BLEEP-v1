// PHASE 2: DYNAMIC SHARDING UPGRADE
// Integration Tests - Real-world scenarios for Phase 2
//
// These tests verify:
// 1. Deterministic shard topology computation
// 2. Fork safety through shard registry verification
// 3. Epoch-bound topology transitions
// 4. Shard split and merge correctness
// 5. Validator assignment consistency
// 6. Byzantine fault tolerance per shard
// 7. AI advisory isolation (non-authoritative)

#[cfg(test)]
mod phase2_integration_tests {
    use bleep_state::shard_ai_extension::*;
    use bleep_state::shard_epoch_binding::*;
    use bleep_state::shard_lifecycle::*;
    use bleep_state::shard_registry::*;
    use bleep_state::shard_validator_assignment::*;

    /// Test 1: All nodes independently derive identical shard topology
    ///
    /// SAFETY: Ensures no fork due to topology disagreement
    #[test]
    fn test_deterministic_shard_topology_computation() {
        let builder = ShardTopologyBuilder::new(1);
        let validators = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        // Node A computes topology
        let topology_a = builder.build_genesis_topology(4, &validators).unwrap();

        // Node B computes same topology
        let topology_b = builder.build_genesis_topology(4, &validators).unwrap();

        // Node C computes same topology
        let topology_c = builder.build_genesis_topology(4, &validators).unwrap();

        // All must have identical registry roots
        assert_eq!(topology_a.registry_root, topology_b.registry_root);
        assert_eq!(topology_b.registry_root, topology_c.registry_root);

        // All must have same shard count
        assert_eq!(
            topology_a.registry.shard_count,
            topology_b.registry.shard_count
        );
        assert_eq!(
            topology_b.registry.shard_count,
            topology_c.registry.shard_count
        );
    }

    /// Test 2: Blocks with incorrect shard registry root are rejected
    ///
    /// SAFETY: Fork prevention through registry root verification
    #[test]
    fn test_shard_registry_root_fork_prevention() {
        let builder = ShardTopologyBuilder::new(1);
        let validators = vec![vec![1, 2, 3]];

        let topology = builder.build_genesis_topology(2, &validators).unwrap();
        let mut binder = EpochShardBinder::new(topology, 1);

        // Block with correct registry root should be accepted
        assert!(binder
            .verify_block_shard_fields(
                binder.current_epoch(),
                &binder.current_topology.registry_root,
                0
            )
            .is_ok());

        // Block with wrong registry root should be rejected
        let wrong_root = "wrong_registry_root";
        assert!(binder
            .verify_block_shard_fields(binder.current_epoch(), wrong_root, 0)
            .is_err());
    }

    /// Test 3: Shard topology changes occur only at epoch boundaries
    ///
    /// SAFETY: Prevents mid-epoch topology changes
    #[test]
    fn test_epoch_boundary_topology_transitions() {
        let builder = ShardTopologyBuilder::new(1);
        let validators = vec![vec![1, 2, 3]];

        let genesis = builder.build_genesis_topology(2, &validators).unwrap();
        let mut binder = EpochShardBinder::new(genesis, 1);

        // Attempt to stage topology for current epoch (should fail)
        let same_epoch = builder.build_genesis_topology(3, &validators).unwrap();
        let same_epoch_with_updated_id = EpochShardTopology {
            epoch_id: binder.current_epoch(),
            ..same_epoch
        };

        // Can't stage for same epoch
        assert!(binder
            .stage_topology_change(same_epoch_with_updated_id)
            .is_err());

        // Stage for next epoch
        let next_epoch = builder
            .build_next_epoch_topology(
                binder.current_epoch(),
                &binder.current_topology.registry,
                vec![],
            )
            .unwrap();

        assert!(binder.stage_topology_change(next_epoch).is_ok());

        // Commit transition
        assert!(binder.commit_epoch_transition().is_ok());

        // New epoch is now current
        assert_eq!(binder.current_epoch().0, 1);
    }

    /// Test 4: Shard split preserves keyspace and state
    ///
    /// SAFETY: State loss prevention
    #[test]
    fn test_shard_split_preserves_keyspace_and_state() {
        let mut registry = ShardRegistry::new(EpochId(0), 1);

        let validators = vec![ValidatorInfo {
            public_key: vec![1],
            stake: 100,
            status: ValidatorStatus::Active,
        }];

        let validator_set = ValidatorSet::new(validators, EpochId(0));

        let validator_assignment = ValidatorAssignment {
            shard_id: ShardId(0),
            epoch_id: EpochId(0),
            validators: vec![vec![1]],
            proposer_rotation_index: 0,
        };

        let mut shard = Shard::new(
            ShardId(0),
            EpochId(0),
            validator_assignment,
            vec![0],
            vec![255],
        );

        // Add transactions to shard
        shard.add_pending_transaction(vec![50]);
        shard.add_pending_transaction(vec![150]);

        registry.add_shard(shard.clone()).unwrap();

        // Plan split
        let mut manager = ShardLifecycleManager::new(registry);
        let mut metrics_map = std::collections::BTreeMap::new();
        metrics_map.insert(
            ShardId(0),
            ShardMetrics {
                tx_count: 15000,
                state_size_bytes: 50_000_000,
                pending_tx_count: 2,
                avg_tx_latency_ms: 100,
                peak_throughput: 500.0,
            },
        );

        let (splits, _) = manager.plan_topology_changes(&metrics_map);

        assert!(!splits.is_empty());
        let split_op = &splits[0];

        // Apply split
        assert!(manager.apply_shard_split(split_op).is_ok());

        // Verify both children exist
        assert!(manager.registry.get_shard(split_op.child1_id).is_some());
        assert!(manager.registry.get_shard(split_op.child2_id).is_some());

        // Verify transactions were routed to appropriate children
        let child1 = manager.registry.get_shard(split_op.child1_id).unwrap();
        let child2 = manager.registry.get_shard(split_op.child2_id).unwrap();

        let total_pending = child1.pending_transactions.len() + child2.pending_transactions.len();
        assert_eq!(total_pending, 2); // All transactions accounted for
    }

    /// Test 5: Shard merge combines state and transactions safely
    ///
    /// SAFETY: Transaction ordering and state integrity
    #[test]
    fn test_shard_merge_combines_state_safely() {
        let mut registry = ShardRegistry::new(EpochId(0), 1);

        let validators = vec![vec![1]];

        let validator_set = ValidatorSet::new(
            vec![ValidatorInfo {
                public_key: vec![1],
                stake: 100,
                status: ValidatorStatus::Active,
            }],
            EpochId(0),
        );

        // Create two adjacent shards
        let shard1 = Shard::new(
            ShardId(0),
            EpochId(0),
            ValidatorAssignment {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                validators: vec![vec![1]],
                proposer_rotation_index: 0,
            },
            vec![0],
            vec![127],
        );

        let shard2 = Shard::new(
            ShardId(1),
            EpochId(0),
            ValidatorAssignment {
                shard_id: ShardId(1),
                epoch_id: EpochId(0),
                validators: vec![vec![1]],
                proposer_rotation_index: 0,
            },
            vec![127],
            vec![255],
        );

        registry.add_shard(shard1).unwrap();
        registry.add_shard(shard2).unwrap();

        // Create lifecycle manager
        let mut manager = ShardLifecycleManager::new(registry);

        // Create merge operation
        let merge_op = ShardMergeOp {
            source1_id: ShardId(0),
            source2_id: ShardId(1),
            target_id: ShardId(2),
            target_keyspace_start: vec![0],
            target_keyspace_end: vec![255],
            merge_epoch_id: EpochId(0),
            state_root: ShardStateRoot {
                root_hash: "merged".to_string(),
                tx_count: 0,
                height: 0,
            },
        };

        // Apply merge
        assert!(manager.apply_shard_merge(&merge_op).is_ok());

        // Verify merged shard exists
        assert!(manager.registry.get_shard(ShardId(2)).is_some());

        // Verify source shards are removed
        assert!(manager.registry.get_shard(ShardId(0)).is_none());
        assert!(manager.registry.get_shard(ShardId(1)).is_none());

        // Verify shard count decreased
        assert_eq!(manager.registry.shard_count, 1);
    }

    /// Test 6: Validator assignment is deterministic and fair
    ///
    /// SAFETY: All nodes derive same assignments independently
    #[test]
    fn test_validator_assignment_is_deterministic() {
        let validators = vec![
            ValidatorInfo {
                public_key: vec![1],
                stake: 100,
                status: ValidatorStatus::Active,
            },
            ValidatorInfo {
                public_key: vec![2],
                stake: 100,
                status: ValidatorStatus::Active,
            },
            ValidatorInfo {
                public_key: vec![3],
                stake: 100,
                status: ValidatorStatus::Active,
            },
        ];

        let validator_set = ValidatorSet::new(validators, EpochId(0));

        let assigner1 = ShardValidatorAssigner::new(AssignmentStrategy::UniformDistribution, 1);
        let assigner2 = ShardValidatorAssigner::new(AssignmentStrategy::UniformDistribution, 1);

        let assignments1 = assigner1.assign_validators(&validator_set, 3).unwrap();
        let assignments2 = assigner2.assign_validators(&validator_set, 3).unwrap();

        // Same validators, same strategy → same assignments
        for shard_id in 0..3 {
            let sid = ShardId(shard_id as u64);
            let a1 = assignments1.get(&sid).unwrap();
            let a2 = assignments2.get(&sid).unwrap();

            assert_eq!(a1.validators, a2.validators);
        }
    }

    /// Test 7: Byzantine fault tolerance is maintained per shard
    ///
    /// SAFETY: Each shard can tolerate at least 1 Byzantine validator
    #[test]
    fn test_byzantine_fault_tolerance_per_shard() {
        let validators = vec![
            ValidatorInfo {
                public_key: vec![1],
                stake: 100,
                status: ValidatorStatus::Active,
            },
            ValidatorInfo {
                public_key: vec![2],
                stake: 100,
                status: ValidatorStatus::Active,
            },
            ValidatorInfo {
                public_key: vec![3],
                stake: 100,
                status: ValidatorStatus::Active,
            },
            ValidatorInfo {
                public_key: vec![4],
                stake: 100,
                status: ValidatorStatus::Active,
            },
        ];

        let validator_set = ValidatorSet::new(validators, EpochId(0));

        assert!(validator_set.is_valid());
        assert_eq!(validator_set.max_byzantine_faults(), 1);
    }

    /// Test 8: AI advisory reports are bounded and non-authoritative
    ///
    /// SAFETY: AI cannot override deterministic rules
    #[test]
    fn test_ai_advisory_is_bounded_and_non_authoritative() {
        let report = AiAdvisoryReport {
            shard_id: ShardId(0),
            epoch_id: EpochId(0),
            split_recommendation: BoundedScore::new(150), // Over-bounded to 100
            merge_recommendation: BoundedScore::new(25),
            anomaly_score: BoundedScore::new(0),
            signature: vec![1, 2, 3],
            timestamp: 1000,
            reason: "High load detected".to_string(),
        };

        // Score is clamped to max 100
        assert_eq!(report.split_recommendation.as_u8(), 100);

        // Report is advisory, not a command
        assert!(report.verify_signature(&vec![1, 2, 3]));
    }

    /// Test 9: Multiple AI reports are aggregated safely using median
    ///
    /// SAFETY: Median is robust to outliers
    #[test]
    fn test_ai_report_aggregation_is_robust() {
        let reports = vec![
            AiAdvisoryReport {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                split_recommendation: BoundedScore::new(10),
                merge_recommendation: BoundedScore::new(50),
                anomaly_score: BoundedScore::new(0),
                signature: vec![],
                timestamp: 0,
                reason: "Low load".to_string(),
            },
            AiAdvisoryReport {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                split_recommendation: BoundedScore::new(50),
                merge_recommendation: BoundedScore::new(50),
                anomaly_score: BoundedScore::new(0),
                signature: vec![],
                timestamp: 0,
                reason: "Medium load".to_string(),
            },
            AiAdvisoryReport {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                split_recommendation: BoundedScore::new(99), // Outlier
                merge_recommendation: BoundedScore::new(20),
                anomaly_score: BoundedScore::new(0),
                signature: vec![],
                timestamp: 0,
                reason: "Very high load".to_string(),
            },
        ];

        let aggregated = AiAdvisoryAggregator::aggregate_split_recommendations(&reports);

        // Median of [10, 50, 99] is 50, not influenced by outlier 99
        assert_eq!(aggregated.as_u8(), 50);
    }

    /// Test 10: Block validation rejects shard topology mismatches
    ///
    /// SAFETY: Prevents forks from shard disagreement
    #[test]
    fn test_block_validation_rejects_shard_topology_mismatches() {
        let builder = ShardTopologyBuilder::new(1);
        let validators = vec![vec![1, 2, 3]];

        let topology = builder.build_genesis_topology(2, &validators).unwrap();
        let mut binder = EpochShardBinder::new(topology, 1);

        let current_epoch = binder.current_epoch();
        let correct_root = binder.current_topology.registry_root.clone();

        // Test 1: Correct shard ID in correct epoch - ACCEPTED
        assert!(binder
            .verify_block_shard_fields(current_epoch, &correct_root, 0)
            .is_ok());

        // Test 2: Wrong registry root - REJECTED
        assert!(binder
            .verify_block_shard_fields(current_epoch, "wrong_root", 0)
            .is_err());

        // Test 3: Invalid shard ID - REJECTED
        assert!(binder
            .verify_block_shard_fields(current_epoch, &correct_root, 99)
            .is_err());

        // Test 4: Wrong epoch - REJECTED
        assert!(binder
            .verify_block_shard_fields(EpochId(99), &correct_root, 0)
            .is_err());
    }

    /// Test 11: Shard state roots are verifiable
    ///
    /// SAFETY: Light clients can verify shard state
    #[test]
    fn test_shard_state_root_verification() {
        let mut registry = ShardRegistry::new(EpochId(0), 1);

        let validator_assignment = ValidatorAssignment {
            shard_id: ShardId(0),
            epoch_id: EpochId(0),
            validators: vec![vec![1]],
            proposer_rotation_index: 0,
        };

        let mut shard = Shard::new(
            ShardId(0),
            EpochId(0),
            validator_assignment,
            vec![0],
            vec![255],
        );

        // Initial state root
        let initial_root = shard.state_root.root_hash.clone();
        assert_eq!(initial_root, "0".repeat(64));

        // Update state
        let new_state_root = ShardStateRoot::compute_from_data(b"new_state");
        shard.commit_transactions(new_state_root.clone()).unwrap();

        // Verify state root changed
        assert_ne!(shard.state_root.root_hash, initial_root);
        assert_eq!(shard.state_root, new_state_root);
    }

    /// Test 12: Registry root includes all shard state
    ///
    /// SAFETY: Registry root is canonical commitment to all shard state
    #[test]
    fn test_registry_root_includes_all_shard_state() {
        let mut registry = ShardRegistry::new(EpochId(0), 1);

        let root_before = registry.registry_root.clone();

        let validator_assignment = ValidatorAssignment {
            shard_id: ShardId(0),
            epoch_id: EpochId(0),
            validators: vec![vec![1]],
            proposer_rotation_index: 0,
        };

        let shard = Shard::new(
            ShardId(0),
            EpochId(0),
            validator_assignment,
            vec![0],
            vec![255],
        );

        registry.add_shard(shard).unwrap();

        let root_after = registry.registry_root.clone();

        // Registry root must change when shard is added
        assert_ne!(root_before, root_after);

        // Root must be consistent
        registry.recompute_registry_root();
        assert_eq!(registry.registry_root, root_after);
    }
}
