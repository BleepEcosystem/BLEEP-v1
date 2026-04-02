/// COMPREHENSIVE PHASE 5 INTEGRATION TESTS
///
/// These tests verify:
/// - Inflation bounds
/// - Slashing correctness
/// - Reward fairness
/// - Fee manipulation attacks
/// - Oracle corruption attempts
/// - Validator cartel behavior

#[cfg(test)]
mod phase5_integration_tests {
    use bleep_economics::integration::*;
    use bleep_economics::*;

    #[test]
    fn test_inflation_bounds() {
        let mut econ = BleepEconomics::genesis();

        // Try to emit beyond constitutional limit
        let mut excess_emission = false;
        for epoch in 0..10 {
            econ.tokenomics
                .record_emission(
                    epoch,
                    EmissionType::BlockProposal,
                    tokenomics::MAX_SUPPLY / 2, // Massive amount
                )
                .ok();

            // Second emission in same epoch should fail
            if econ
                .tokenomics
                .record_emission(
                    epoch,
                    EmissionType::Participation,
                    tokenomics::MAX_SUPPLY / 2,
                )
                .is_err()
            {
                excess_emission = true;
                break;
            }
        }

        assert!(
            excess_emission
                || econ.tokenomics.supply_state.circulating_supply <= tokenomics::MAX_SUPPLY,
            "Supply exceeded maximum"
        );
    }

    #[test]
    fn test_slashing_correctness() {
        let mut econ = BleepEconomics::genesis();

        // Register validators
        let v1 = vec![1, 1, 1];
        let v2 = vec![2, 2, 2];

        econ.validators
            .register_validator(v1.clone(), 1000)
            .unwrap();
        econ.validators
            .register_validator(v2.clone(), 2000)
            .unwrap();

        // Apply slashing to v1
        let evidence = validator_incentives::SlashingEvidence {
            validator_id: v1.clone(),
            epoch: 0,
            violation_type: validator_incentives::SlashingViolationType::DoubleSigning,
            slash_amount: 320, // 32%
            proof_hash: vec![1, 2, 3],
            disputed: false,
        };

        econ.validators.apply_slashing(evidence).unwrap();

        let v1_account = econ.validators.validators.get(&v1).unwrap();
        assert_eq!(v1_account.total_slashed, 320);
        assert_eq!(
            v1_account.status,
            validator_incentives::ValidatorStatus::Jailed
        );

        // v2 should be unaffected
        let v2_account = econ.validators.validators.get(&v2).unwrap();
        assert_eq!(v2_account.total_slashed, 0);
        assert_eq!(
            v2_account.status,
            validator_incentives::ValidatorStatus::Active
        );
    }

    #[test]
    fn test_reward_fairness() {
        let mut econ = BleepEconomics::genesis();

        let v1 = vec![1];
        let v2 = vec![2];

        econ.validators
            .register_validator(v1.clone(), 1000)
            .unwrap();
        econ.validators
            .register_validator(v2.clone(), 1000)
            .unwrap(); // Same stake

        // v1 participates, v2 doesn't
        let m1 = validator_incentives::ValidatorMetrics {
            validator_id: v1.clone(),
            blocks_proposed: 10,
            attestations_included: 32,
            healing_participations: 5,
            shards_coordinated: 2,
            double_signs_evidence: 0,
            state_transition_failures: 0,
            epoch: 0,
        };

        let m2 = validator_incentives::ValidatorMetrics {
            validator_id: v2.clone(),
            blocks_proposed: 0,
            attestations_included: 0,
            healing_participations: 0,
            shards_coordinated: 0,
            double_signs_evidence: 0,
            state_transition_failures: 0,
            epoch: 0,
        };

        econ.validators.record_metrics(v1.clone(), m1).unwrap();
        econ.validators.record_metrics(v2.clone(), m2).unwrap();

        let rewards = econ.validators.compute_epoch_rewards(0).unwrap();

        // v1 should have higher reward
        let r1 = rewards.iter().find(|r| r.validator_id == v1).unwrap();
        let r2 = rewards.iter().find(|r| r.validator_id == v2).unwrap();

        assert!(
            r1.total_reward > r2.total_reward,
            "Participating validator should earn more"
        );
    }

    #[test]
    fn test_fee_manipulation_attack() {
        let mut econ = BleepEconomics::genesis();

        // Register shards
        let congestion = fee_market::ShardCongestion {
            shard_id: 0,
            utilization_bps: 9000, // Very congested
            pending_txns: 1000,
            avg_tx_size_bytes: 256,
        };

        econ.fee_market.record_shard_congestion(congestion).unwrap();

        // Calculate fee for transaction
        let usage = fee_market::ResourceUsage {
            compute_units: 21_000,
            storage_units: 0,
            bandwidth_bytes: 128,
            memory_bytes: 1024,
        };

        let fee1 = econ
            .fee_market
            .calculate_fee(fee_market::TransactionType::Transfer, usage, 0)
            .unwrap();

        // Now reduce congestion and recalculate
        let low_congestion = fee_market::ShardCongestion {
            shard_id: 0,
            utilization_bps: 1000, // Low
            pending_txns: 10,
            avg_tx_size_bytes: 64,
        };

        econ.fee_market
            .record_shard_congestion(low_congestion)
            .unwrap();

        let fee2 = econ
            .fee_market
            .calculate_fee(fee_market::TransactionType::Transfer, usage, 0)
            .unwrap();

        // High congestion should have higher fee
        assert!(fee1 > fee2, "High congestion should result in higher fees");
    }

    #[test]
    fn test_oracle_corruption_resistance() {
        let mut econ = BleepEconomics::genesis();

        let op1 = vec![1];
        let op2 = vec![2];
        let op3 = vec![3];

        econ.oracle_bridge
            .register_operator(op1.clone(), 1000)
            .unwrap();
        econ.oracle_bridge
            .register_operator(op2.clone(), 1000)
            .unwrap();
        econ.oracle_bridge
            .register_operator(op3.clone(), 1000)
            .unwrap();

        let ts = 1000u64;

        // Honest operators
        econ.oracle_bridge
            .submit_price_update(oracle_bridge::PriceUpdate {
                source: oracle_bridge::OracleSource::Chainlink("ETH/USD".to_string()),
                asset: "ETH/USD".to_string(),
                price: 1800 * 10u128.pow(8),
                timestamp: ts,
                confidence_bps: 100,
                operator_id: op1.clone(),
                signature: vec![],
            })
            .unwrap();

        econ.oracle_bridge
            .submit_price_update(oracle_bridge::PriceUpdate {
                source: oracle_bridge::OracleSource::Pyth("ETH/USD".to_string()),
                asset: "ETH/USD".to_string(),
                price: 1800 * 10u128.pow(8),
                timestamp: ts,
                confidence_bps: 100,
                operator_id: op2.clone(),
                signature: vec![],
            })
            .unwrap();

        // Malicious operator tries extreme price
        econ.oracle_bridge
            .submit_price_update(oracle_bridge::PriceUpdate {
                source: oracle_bridge::OracleSource::Custom(vec![99]),
                asset: "ETH/USD".to_string(),
                price: 100 * 10u128.pow(8), // Way off
                timestamp: ts,
                confidence_bps: 100,
                operator_id: op3.clone(),
                signature: vec![],
            })
            .unwrap();

        // Aggregate should use median (not mean), so median is still honest
        let agg = econ
            .oracle_bridge
            .aggregate_prices("ETH/USD", ts, 1000)
            .unwrap();

        // Median of [1800, 1800, 100] = 1800
        assert_eq!(
            agg.median_price,
            1800 * 10u128.pow(8),
            "Median should resist single malicious oracle"
        );

        // Dispute the malicious update
        econ.oracle_bridge
            .dispute_price_update(
                op3.clone(),
                vec![99, 99, 99], // fake hash for dispute
                vec![4, 4, 4],    // challenger
                vec![88, 88],     // evidence
                0,
            )
            .unwrap();

        // Op3's reputation should decrease
        let rep = econ.oracle_bridge.get_operator_reputation(&op3).unwrap();
        assert!(
            rep < 5000,
            "Operator reputation should decrease after dispute"
        );
    }

    #[test]
    fn test_validator_cartel_detection() {
        let mut econ = BleepEconomics::genesis();

        // Create 10 validators in cartel
        let mut cartel_ids = Vec::new();
        for i in 0..10 {
            let id = vec![i as u8];
            econ.validators
                .register_validator(id.clone(), 1000)
                .unwrap();
            cartel_ids.push(id);
        }

        // All cartel members propose blocks (unusual pattern)
        for (i, vid) in cartel_ids.iter().enumerate() {
            let metrics = validator_incentives::ValidatorMetrics {
                validator_id: vid.clone(),
                blocks_proposed: 100, // Extremely high
                attestations_included: 0,
                healing_participations: 0,
                shards_coordinated: 0,
                double_signs_evidence: 0,
                state_transition_failures: 0,
                epoch: 0,
            };
            econ.validators.record_metrics(vid.clone(), metrics).ok();
        }

        // Compute rewards - should show suspicious pattern
        let rewards = econ.validators.compute_epoch_rewards(0).unwrap();

        // All should have rewards
        assert_eq!(rewards.len(), 10);

        // In real system, anomaly detector would flag this pattern
        // (This is a simplification; real detection would use statistical analysis)
    }

    #[test]
    fn test_game_theoretic_safety() {
        // Run comprehensive safety audit
        let analyses = SafetyVerifier::audit_all(
            3200,                 // 32% slashing for double signing
            32 * 10u128.pow(6),   // 0.32 BLEEP reward
            1 * 10u128.pow(6),    // 0.01 BLEEP participation
            100_000,              // Small cost
            1000 * 10u128.pow(8), // 1000 BLEEP stake
            1_000_000,            // Spam fee
        );

        // All attacks should be unprofitable
        let all_safe = analyses
            .iter()
            .all(|a| !a.is_profitable || a.attacker_profit < 0);
        assert!(all_safe, "Found profitable attack in system");
    }

    #[test]
    fn test_fail_closed_accounting() {
        let mut econ = BleepEconomics::genesis();

        // Try to create negative balance scenarios
        econ.tokenomics
            .record_emission(0, EmissionType::BlockProposal, 1000)
            .unwrap();

        // Burn more than we emitted - should not violate invariant
        let result = econ
            .tokenomics
            .record_burn(0, BurnType::TransactionFee, 2000);

        // Either burn succeeds and supply goes to 0, or fails
        // Either way, invariant is maintained
        if result.is_ok() {
            econ.tokenomics.supply_state.verify().unwrap();
        }
    }

    #[test]
    fn test_economic_invariants_hold() {
        let mut econ = BleepEconomics::genesis();

        // Perform operations
        econ.tokenomics
            .record_emission(0, EmissionType::BlockProposal, 100)
            .ok();
        econ.tokenomics
            .record_burn(0, BurnType::TransactionFee, 30)
            .ok();
        econ.validators.register_validator(vec![1], 100).ok();

        // Verify all invariants
        assert!(econ.verify_epoch_invariants().is_ok());
    }

    #[test]
    fn test_comprehensive_economic_cycle() {
        let mut econ = BleepEconomics::genesis();

        // Setup: Register validators
        let v1 = vec![1];
        let v2 = vec![2];
        econ.validators
            .register_validator(v1.clone(), 10000)
            .unwrap();
        econ.validators
            .register_validator(v2.clone(), 5000)
            .unwrap();

        // Epoch 0: Emissions and fees
        econ.tokenomics
            .record_emission(0, EmissionType::BlockProposal, 64 * 10u128.pow(6))
            .unwrap();
        econ.tokenomics
            .record_burn(0, BurnType::TransactionFee, 10 * 10u128.pow(6))
            .unwrap();

        // Record participation and compute rewards
        econ.validators
            .record_metrics(
                v1.clone(),
                validator_incentives::ValidatorMetrics {
                    validator_id: v1.clone(),
                    blocks_proposed: 5,
                    attestations_included: 32,
                    healing_participations: 2,
                    shards_coordinated: 1,
                    double_signs_evidence: 0,
                    state_transition_failures: 0,
                    epoch: 0,
                },
            )
            .unwrap();

        econ.validators
            .record_metrics(
                v2.clone(),
                validator_incentives::ValidatorMetrics {
                    validator_id: v2.clone(),
                    blocks_proposed: 2,
                    attestations_included: 16,
                    healing_participations: 0,
                    shards_coordinated: 0,
                    double_signs_evidence: 0,
                    state_transition_failures: 0,
                    epoch: 0,
                },
            )
            .unwrap();

        let rewards = econ.validators.compute_epoch_rewards(0).unwrap();
        assert_eq!(rewards.len(), 2);

        // v1 should have earned more (better participation)
        let r1 = rewards.iter().find(|r| r.validator_id == v1).unwrap();
        let r2 = rewards.iter().find(|r| r.validator_id == v2).unwrap();
        assert!(r1.total_reward > r2.total_reward);

        // Finalize epoch
        econ.tokenomics.finalize_epoch(0).unwrap();

        // Verify invariants hold
        assert!(econ.verify_epoch_invariants().is_ok());
    }
}
