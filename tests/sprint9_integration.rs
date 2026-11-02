//! tests/sprint9_integration.rs
//! Sprint 9 — End-to-End Integration Tests
//!
//! Cross-crate integration tests covering the full Sprint 9 deliverables:
//! chaos testing, MPC ceremony, Layer 3 bridge, live governance, performance benchmark,
//! cross-shard stress, and security audit verification.

// ── Chaos Engine ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod chaos_integration {
    use bleep_consensus::chaos_engine::{ChaosEngine, ContinuousChaosHarness};

    #[test]
    fn chaos_full_suite_7_validators_majority_pass() {
        let mut engine = ChaosEngine::new(7);
        let passed = engine.run_full_suite(10_000);
        let summary = engine.summary();
        assert!(
            summary.pass_rate_pct >= 80.0,
            "expected ≥80% pass rate, got {:.1}%",
            summary.pass_rate_pct
        );
        assert_eq!(
            passed, summary.all_passed,
            "run_full_suite result must match summary"
        );
    }

    #[test]
    fn chaos_72h_harness_iterates() {
        let mut harness = ContinuousChaosHarness::new(7, 72);
        // Run 3 iterations to verify the harness bookkeeping
        for i in 0..3 {
            harness.tick(10_000 + i * 1_000);
        }
        assert_eq!(harness.iterations(), 3);
        assert!(harness.total_passed() > 0);
    }
}

// ── ZKP Circuit Integration ───────────────────────────────────────────────────

#[cfg(test)]
mod zkp_circuit_integration {
    use bleep_zkp::{BlockValidityCircuit, BlockVerifier, BLOCK_CIRCUIT_PUBLIC_INPUTS};

    #[test]
    fn zkp_block_circuit_public_inputs_consistent() {
        let circuit = BlockValidityCircuit::for_verifying(
            0,
            0,
            0,
            "00000000000000000000000000000000",
            &[0u8; 32],
        );

        assert_eq!(circuit.public_inputs().len(), BLOCK_CIRCUIT_PUBLIC_INPUTS);
    }

    #[test]
    fn zkp_block_verifier_rejects_invalid_proof() {
        let verifier = BlockVerifier::new();
        let result = verifier.verify(&[0u8; 16], 0, 0, 0, &[0u8; 32], &[0u8; 32]);
        assert!(
            result.is_err(),
            "invalid proof bytes must fail verification"
        );
    }
}

// ── Layer 3 Bridge ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod layer3_bridge_integration {
    use bleep_interop::layer3_bridge::{Chain, L3State, Layer3Bridge, L3_BATCH_SIZE};
    use bleep_interop::nullifier_store::GlobalNullifierSet;

    #[test]
    fn layer3_batch_32_intents_then_verify_finalize_all() {
        let mut bridge = Layer3Bridge::new("powers-of-tau-bls12-381-bleep-v1")
            .expect("failed to create Layer3Bridge");
        let mut ids = Vec::new();
        for i in 0..L3_BATCH_SIZE {
            let id = bridge.initiate(
                Chain::Bleep,
                Chain::EthereumSepolia,
                &format!("bleep:alice{}", i),
                &format!("0xBob{:04x}", i),
                (i as u128 + 1) * 1_000_000,
                "BLEEP",
                i as u64 + 1,
            );
            ids.push(id);
        }
        let proof = bridge
            .flush_batch([0xCA; 32], [0xFE; 32])
            .expect("failed to flush batch");
        assert_eq!(proof.batch_ids.len(), L3_BATCH_SIZE);
        assert!(
            proof.proof_bytes.len() >= 192,
            "proof bytes must be nontrivial"
        );

        // Ensure all intents are ready after batch flush.
        for id in &ids {
            assert_eq!(bridge.intent_state(id), Some(&L3State::ProofReady));
        }

        for id in &ids {
            let p = proof.clone();
            assert!(bridge.submit_proof(id, p));
            assert!(bridge.finalize(id));
        }
        assert_eq!(bridge.finalized_count(), L3_BATCH_SIZE);
    }

    #[test]
    fn nullifier_set_prevents_all_double_spends() {
        let ns = GlobalNullifierSet::open_temp();
        let nullifiers: Vec<[u8; 32]> = (0..10u8).map(|i| [i; 32]).collect();

        // First spend of each succeeds
        for n in &nullifiers {
            ns.spend(*n).expect("first spend must succeed");
        }
        assert_eq!(ns.len(), 10);

        // Second spend of any fails
        for n in &nullifiers {
            assert!(
                ns.spend(*n).is_err(),
                "double spend of {:?} must be rejected",
                n
            );
        }
    }

    #[test]
    fn layer3_full_bleep_to_sepolia_flow_with_nullifier_check() {
        let mut bridge = Layer3Bridge::new("sprint9-srs").expect("failed to create Layer3Bridge");
        let ns = GlobalNullifierSet::open_temp();

        let id = bridge.initiate(
            Chain::Bleep,
            Chain::EthereumSepolia,
            "bleep:pretestnet:alice",
            "0xAlice",
            5_000_000_000,
            "BLEEP",
            1,
        );

        let proof = bridge
            .flush_batch([0x11; 32], [0x22; 32])
            .expect("failed to flush batch");
        assert_eq!(proof.batch_ids.len(), 1);

        // First submission: proof should verify and finalize normally.
        assert!(bridge.submit_proof(&id, proof.clone()));
        assert!(bridge.finalize(&id));

        // Use the intent id as a deterministic 32-byte value for nullifier tracking.
        let nullifier = proof.batch_ids[0];
        assert!(!ns.is_spent(&nullifier));
        ns.spend(nullifier).unwrap();
        assert!(
            ns.spend(nullifier).is_err(),
            "replay must be blocked by nullifier store"
        );
    }
}

// ── Live Governance ───────────────────────────────────────────────────────────

#[cfg(test)]
mod governance_live_integration {
    use bleep_governance::live_governance::{
        GovernableParam, GovernanceConfig, LiveGovernanceEngine, ProposalState, Vote,
    };

    fn engine() -> LiveGovernanceEngine {
        LiveGovernanceEngine::new(GovernanceConfig::default(), 1_000)
    }

    #[test]
    fn governance_parameter_change_full_lifecycle() {
        let mut gov = engine();
        let min_deposit = gov.config.min_deposit;
        let total_staked = gov.config.total_staked;
        let voting_period = gov.config.voting_period_blocks;

        // Submit: reduce max inflation from 5% to 4%
        let pid = gov
            .submit(
                "bleep:pretestnet:foundation",
                "Reduce max inflation to 4% (400 bps)",
                "Proposal to lower the epoch inflation cap from 500 to 400 bps.",
                Some(GovernableParam::MaxInflationBps(400)),
                min_deposit,
            )
            .unwrap();

        // Participating validators each with 10% of total stake vote YES
        let stake_per_validator = total_staked / 10;
        for i in 0..7 {
            gov.vote(
                pid,
                &format!("validator-{}", i),
                Vote::Yes,
                stake_per_validator,
            )
            .unwrap();
        }

        gov.advance_block(voting_period + 1);

        let state = gov.tally(pid).unwrap();
        assert_eq!(
            state,
            ProposalState::Passed,
            "Participating validators with 70% stake must pass proposal"
        );

        let result = gov.execute(pid).unwrap();
        assert_eq!(gov.proposal(pid).unwrap().state, ProposalState::Executed);
        assert_eq!(result.param_applied.as_deref(), Some("max_inflation_bps"));
        assert!(result.tx_hash.starts_with("0x"));

        // Verify event log completeness
        let kinds: Vec<&str> = gov.event_log().iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"proposal_submitted"));
        assert!(kinds.iter().filter(|&&k| k == "vote_cast").count() == 7);
        assert!(kinds.contains(&"proposal_passed"));
        assert!(kinds.contains(&"proposal_executed"));
    }

    #[test]
    fn constitutional_guard_blocks_inflation_above_5_pct() {
        let mut gov = engine();
        // 600 bps = 6% — violates constitutional 500 bps hard cap
        let err = gov.submit(
            "malicious-actor",
            "Break the inflation cap",
            "Set max inflation to 6%",
            Some(GovernableParam::MaxInflationBps(600)),
            gov.config.min_deposit,
        );
        assert!(
            err.is_err(),
            "6% inflation must be rejected by constitutional guard"
        );
    }

    #[test]
    fn veto_mechanism_blocks_controversial_proposals() {
        let mut gov = engine();
        let total = gov.config.total_staked;
        let pid = gov
            .submit(
                "alice",
                "Controversial change",
                "...",
                None,
                gov.config.min_deposit,
            )
            .unwrap();

        // 40% of stake veto — exceeds 33.33% veto threshold
        gov.vote(pid, "v0", Vote::Yes, total / 5).unwrap(); // 20% yes
        gov.vote(pid, "v1", Vote::Veto, total * 2 / 5).unwrap(); // 40% veto

        gov.advance_block(gov.config.voting_period_blocks + 1);
        assert_eq!(gov.tally(pid).unwrap(), ProposalState::Vetoed);
    }

    #[test]
    fn first_pretestnet_proposal_executes_fee_burn_change() {
        // Mirror the production Sprint 9 pretestnet proposal-001
        let mut gov = engine();
        let pid = gov
            .submit(
                "bleep:pretestnet:foundation",
                "Reduce fee burn to 20% (proposal-pretestnet-001)",
                "Lower the base fee burn from 25% to 20% to increase validator rewards.",
                Some(GovernableParam::FeeBurnBps(2_000)),
                gov.config.min_deposit,
            )
            .unwrap();

        let stake = gov.config.total_staked / 10;
        for i in 0..7 {
            gov.vote(pid, &format!("validator-{}", i), Vote::Yes, stake)
                .unwrap();
        }
        gov.advance_block(gov.config.voting_period_blocks + 1);
        assert_eq!(gov.tally(pid).unwrap(), ProposalState::Passed);
        let r = gov.execute(pid).unwrap();
        assert_eq!(r.param_applied.as_deref(), Some("fee_burn_bps"));
    }
}

// ── Cross-Shard Stress Test ───────────────────────────────────────────────────

#[cfg(test)]
mod shard_stress_integration {
    use bleep_consensus::shard_coordinator::{
        ShardCoordinator, CROSS_SHARD_CONCURRENT_TARGET, NUM_SHARDS, STRESS_EPOCH_COUNT,
    };

    #[test]
    fn cross_shard_stress_1000_concurrent_over_100_epochs() {
        let mut coord = ShardCoordinator::new();
        let result = coord.run_stress_test();

        assert_eq!(
            result.total_epochs, STRESS_EPOCH_COUNT,
            "must complete all {} epochs",
            STRESS_EPOCH_COUNT
        );
        assert!(
            result.total_xs_txs >= CROSS_SHARD_CONCURRENT_TARGET as u64,
            "must process at least {} cross-shard txs",
            CROSS_SHARD_CONCURRENT_TARGET
        );
        assert_eq!(
            result.committed_xs + result.rolledback_xs,
            result.total_xs_txs,
            "every XS tx must be either committed or rolled back"
        );
        assert!(result.total_txs > 0, "total transactions must be non-zero");
    }

    #[test]
    fn all_10_shards_produce_blocks() {
        let mut coord = ShardCoordinator::new();
        coord.tick_epoch();
        for shard in coord.shards.values() {
            assert!(
                shard.block_height > 0,
                "shard {:?} must have produced blocks",
                shard.shard_id
            );
            assert!(shard.txs_processed > 0);
        }
    }

    #[test]
    fn shard_assignment_is_stable_and_covers_all_shards() {
        // Verify that with enough addresses, all NUM_SHARDS shards get assigned
        use bleep_consensus::shard_coordinator::ShardId;
        use std::collections::HashSet;
        let mut assigned: HashSet<u8> = HashSet::new();
        for i in 0..1000 {
            let id = ShardId::from_address(&format!("bleep:pretestnet:addr{:05}", i));
            assigned.insert(id.0);
        }
        // With 1000 addresses we should cover all 10 shards
        assert_eq!(
            assigned.len(),
            NUM_SHARDS,
            "1000 addresses should distribute across all {} shards",
            NUM_SHARDS
        );
    }
}

// ── Performance Benchmark ─────────────────────────────────────────────────────

#[cfg(test)]
mod performance_integration {
    use bleep_consensus::performance_bench::{
        PerformanceBenchmark, MAX_TXS_PER_BLOCK, NUM_SHARDS, TARGET_TPS,
    };

    #[test]
    fn theoretical_max_tps_exceeds_10k_target() {
        // 10 shards × 4096 tx/block ÷ 3s = 13,653 TPS theoretical maximum
        let theoretical = NUM_SHARDS as u64 * MAX_TXS_PER_BLOCK as u64 / 3;
        assert!(
            theoretical >= TARGET_TPS,
            "theoretical max {}tps must exceed {}tps target",
            theoretical,
            TARGET_TPS
        );
    }

    #[test]
    fn benchmark_60s_simulation_produces_valid_result() {
        let mut bench = PerformanceBenchmark::new(NUM_SHARDS, 60, TARGET_TPS);
        let result = bench.run_simulated();
        assert!(result.total_txs > 0);
        assert!(result.avg_tps > 0);
        assert_eq!(result.num_shards, NUM_SHARDS);
        assert_eq!(result.target_tps, TARGET_TPS);
        assert!(result.avg_block_time_ms >= 2_500 && result.avg_block_time_ms <= 3_500);
    }

    #[test]
    fn benchmark_summary_string_contains_key_fields() {
        let mut bench = PerformanceBenchmark::new(NUM_SHARDS, 10, TARGET_TPS);
        let result = bench.run_simulated();
        let summary = result.summary();
        assert!(summary.contains("avg_tps="), "summary must contain avg_tps");
        assert!(
            summary.contains("target_met="),
            "summary must contain target_met"
        );
        assert!(summary.contains("blocks="), "summary must contain blocks");
    }
}

// ── Security Audit ────────────────────────────────────────────────────────────

#[cfg(test)]
mod security_audit_integration {
    use bleep_consensus::security_audit::{AuditReport, FindingStatus, Severity};

    #[test]
    fn sprint9_audit_complete_14_findings() {
        let report = AuditReport::report();
        let summary = report.summary();
        assert_eq!(
            summary.total, 14,
            "Sprint 9 audit must have exactly 14 findings"
        );
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.high, 3);
        assert_eq!(summary.medium, 4);
        assert_eq!(summary.low, 3);
        assert_eq!(summary.informational, 2);
    }

    #[test]
    fn critical_findings_resolved_and_open_high_findings_reported() {
        let report = AuditReport::report();
        let unresolved_critical: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .filter(|f| !matches!(f.status, FindingStatus::Resolved { .. }))
            .collect();
        assert!(
            unresolved_critical.is_empty(),
            "unresolved critical findings: {:?}",
            unresolved_critical
                .iter()
                .map(|f| &f.id)
                .collect::<Vec<_>>()
        );
        for id in ["SA-H1", "SA-H3"] {
            let finding = report.findings.iter().find(|f| f.id == id).unwrap();
            assert!(matches!(finding.status, FindingStatus::Open { .. }));
        }
    }

    #[test]
    fn audit_report_crate_coverage_includes_all_sprint9_scope() {
        let report = AuditReport::report();
        let crates: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.crate_name.as_str())
            .collect();
        for expected in &[
            "bleep-crypto",
            "bleep-consensus",
            "bleep-state",
            "bleep-interop",
            "bleep-auth",
            "bleep-rpc",
        ] {
            assert!(
                crates.contains(expected),
                "audit must cover crate {}",
                expected
            );
        }
    }

    #[test]
    fn sa_c1_nullifier_fix_is_in_correct_crate() {
        let report = AuditReport::report();
        let c1 = report.findings.iter().find(|f| f.id == "SA-C1").unwrap();
        assert_eq!(c1.crate_name, "bleep-interop");
        assert!(matches!(c1.status, FindingStatus::Resolved { .. }));
    }

    #[test]
    fn sa_c2_jwt_entropy_fix_is_in_correct_crate() {
        let report = AuditReport::report();
        let c2 = report.findings.iter().find(|f| f.id == "SA-C2").unwrap();
        assert_eq!(c2.crate_name, "bleep-auth");
        assert!(matches!(c2.status, FindingStatus::Resolved { .. }));
    }
}
