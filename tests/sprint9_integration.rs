//! tests/sprint9_integration.rs
//! Sprint 9 — End-to-End Integration Tests
//!
//! Cross-crate integration tests covering the full Sprint 9 deliverables:
//! chaos testing, MPC ceremony, Layer 3 bridge, live governance, performance benchmark,
//! cross-shard stress, and security audit verification.

// ── Chaos Engine ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod chaos_integration {
    use bleep_consensus::chaos_engine::{ChaosEngine, ChaosScenario};

    #[test]
    fn chaos_full_suite_7_validators_majority_pass() {
        let mut engine = ChaosEngine::new(7);
        let _ = engine.run_full_suite(10_000);
        let summary = engine.summary();
        // Most scenarios must pass; only symmetric partition may not achieve liveness
        assert!(
            summary.pass_rate_pct >= 80.0,
            "expected ≥80% pass rate, got {:.1}%",
            summary.pass_rate_pct
        );
    }

    #[test]
    fn chaos_bft_bound_enforced() {
        let mut engine = ChaosEngine::new(7);
        // f=2: safe (2 < 7/3=2.33)
        let ok = engine.run_scenario(ChaosScenario::ValidatorCrash { count: 2 }, 1000);
        assert!(ok.passed, "crash of 2/7 must be within BFT bound");
        // f=3: unsafe (3 >= 7/3)
        let bad = engine.run_scenario(ChaosScenario::ValidatorCrash { count: 3 }, 1000);
        assert!(!bad.passed, "crash of 3/7 must violate BFT bound");
    }

    #[test]
    fn chaos_all_slashing_scenarios_detected() {
        let mut engine = ChaosEngine::new(7);
        for vid in &["validator-0", "validator-1", "validator-6"] {
            let o = engine.run_scenario(
                ChaosScenario::DoubleSign {
                    validator_id: vid.to_string(),
                },
                5000,
            );
            assert!(
                o.passed,
                "double-sign by {} must be detected and slashed",
                vid
            );
            assert!(o.notes.contains("33%"), "slash must be 33%");
        }
    }

    #[test]
    fn chaos_all_replay_attacks_blocked() {
        let mut engine = ChaosEngine::new(7);
        for i in 0..5u32 {
            let o = engine.run_scenario(
                ChaosScenario::TxReplay {
                    tx_id: format!("replay-tx-{}", i),
                },
                6000,
            );
            assert!(o.passed);
            assert!(
                o.violations.is_empty(),
                "replay must be rejected cleanly, no invariant violations"
            );
        }
    }

    #[test]
    fn chaos_72h_harness_iterates() {
        use bleep_consensus::chaos_engine::ContinuousChaosHarness;
        let mut harness = ContinuousChaosHarness::new(7, 72);
        // Run 3 iterations to verify the harness bookkeeping
        for i in 0..3 {
            harness.tick(10_000 + i * 1_000);
        }
        assert_eq!(harness.iterations(), 3);
        assert!(harness.total_passed() > 0);
    }
}

// ── MPC Ceremony ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod mpc_ceremony_integration {
    use bleep_zkp::mpc_ceremony::{CeremonyState, MPCCeremony, Participant, MIN_PARTICIPANTS};

    fn participant(id: &str, seed: u8, ts: u64) -> Participant {
        Participant::new(id, [seed; 32], ts)
    }

    #[test]
    fn five_participant_ceremony_mirrors_sprint9_production() {
        let mut ceremony = MPCCeremony::new(1_746_000_000);
        for (i, (name, seed)) in [
            ("participant-0-anon", 0xA0u8),
            ("participant-1-anon", 0xA1),
            ("participant-2-anon", 0xA2),
            ("participant-3-anon", 0xA3),
            ("participant-4-anon", 0xA4),
        ]
        .iter()
        .enumerate()
        {
            ceremony
                .contribute(participant(name, *seed, 1_746_000_000 + i as u64 * 3_600))
                .unwrap();
        }
        let srs = ceremony
            .finalise("https://ceremony.bleep.network/transcript-v1.json")
            .unwrap();
        assert_eq!(srs.participant_count, 5);
        assert_eq!(ceremony.state, CeremonyState::Complete);
        assert_eq!(ceremony.transcript_len(), 5);
        assert!(
            srs.g1_powers_len >= 1_000_000,
            "SRS must cover large circuits"
        );
        assert!(srs.security_claim.contains('5'));
    }

    #[test]
    fn ceremony_transcript_integrity_after_5_participants() {
        let mut ceremony = MPCCeremony::new(1_000_000);
        for i in 0..5u8 {
            ceremony
                .contribute(participant(&format!("p{}", i), i * 0x11, i as u64))
                .unwrap();
        }
        let result = ceremony.verify_transcript();
        assert!(
            result.valid,
            "transcript must be valid after 5 participants: {:?}",
            result.error
        );
        assert_eq!(result.entries_verified, 5);
    }

    #[test]
    fn ceremony_requires_at_least_min_participants() {
        let mut ceremony = MPCCeremony::new(1_000_000);
        for i in 0..(MIN_PARTICIPANTS - 1) {
            ceremony
                .contribute(participant(&format!("p{}", i), i as u8, i as u64))
                .unwrap();
        }
        assert!(
            ceremony.finalise("https://example.com").is_err(),
            "must reject finalisation with fewer than {} participants",
            MIN_PARTICIPANTS
        );
    }
}

// ── Layer 3 Bridge ────────────────────────────────────────────────────────────

#[cfg(test)]
mod layer3_bridge_integration {
    use bleep_interop::layer3_bridge::{Chain, L3State, Layer3Bridge, L3_BATCH_SIZE};
    use bleep_interop::nullifier_store::GlobalNullifierSet;

    #[test]
    fn layer3_batch_32_intents_then_verify_finalize_all() {
        let mut bridge = Layer3Bridge::new("powers-of-tau-bls12-381-bleep-v1");
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
        let proof = bridge.flush_batch([0xCA; 32], [0xFE; 32]).unwrap();
        assert_eq!(proof.batch_ids.len(), L3_BATCH_SIZE);
        assert_eq!(proof.proof_bytes.len(), 192);

        // Submit and finalize each
        for id in &ids {
            let p = proof.clone();
            assert!(bridge.submit_proof(id, p));
            assert!(bridge.finalize(id));
        }
        assert_eq!(bridge.finalized_count(), L3_BATCH_SIZE);
    }

    #[test]
    fn nullifier_set_prevents_all_double_spends() {
        let mut ns = GlobalNullifierSet::new();
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
        let mut bridge = Layer3Bridge::new("sprint9-srs");
        let mut ns = GlobalNullifierSet::new();

        let id = bridge.initiate(
            Chain::Bleep,
            Chain::EthereumSepolia,
            "bleep:testnet:alice",
            "0xAlice",
            5_000_000_000,
            "BLEEP",
            1,
        );

        let proof = bridge.flush_batch([0x11; 32], [0x22; 32]).unwrap();
        // Extract nullifier from proof public inputs (index 3)
        let nullifier = proof.public_inputs[3];

        // First submission: nullifier not yet spent
        assert!(!ns.is_spent(&nullifier));
        ns.spend(nullifier).unwrap();
        assert!(bridge.submit_proof(&id, proof.clone()));
        assert!(bridge.finalize(&id));

        // Second submission attempt: nullifier already spent — must be rejected
        let err = ns.spend(nullifier);
        assert!(
            err.is_err(),
            "replay must be blocked by nullifier store (SA-C1 fix)"
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
                "bleep:testnet:foundation",
                "Reduce max inflation to 4% (400 bps)",
                "Proposal to lower the epoch inflation cap from 500 to 400 bps.",
                Some(GovernableParam::MaxInflationBps(400)),
                min_deposit,
            )
            .unwrap();

        // 7 validators each with 10% of total stake vote YES
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
            "7 validators with 70% stake must pass proposal"
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
    fn first_testnet_proposal_executes_fee_burn_change() {
        // Mirror the production Sprint 9 testnet proposal-001
        let mut gov = engine();
        let pid = gov
            .submit(
                "bleep:testnet:foundation",
                "Reduce fee burn to 20% (proposal-testnet-001)",
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
            let id = ShardId::from_address(&format!("bleep:testnet:addr{:05}", i));
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
        let report = AuditReport::sprint9_report();
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
    fn all_critical_and_high_findings_resolved_before_mainnet() {
        let report = AuditReport::sprint9_report();
        let blocking: Vec<_> = report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .filter(|f| !matches!(f.status, FindingStatus::Resolved { .. }))
            .collect();
        assert!(
            blocking.is_empty(),
            "blocking unresolved findings: {:?}",
            blocking.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn audit_report_crate_coverage_includes_all_sprint9_scope() {
        let report = AuditReport::sprint9_report();
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
        let report = AuditReport::sprint9_report();
        let c1 = report.findings.iter().find(|f| f.id == "SA-C1").unwrap();
        assert_eq!(c1.crate_name, "bleep-interop");
        assert!(matches!(c1.status, FindingStatus::Resolved { .. }));
    }

    #[test]
    fn sa_c2_jwt_entropy_fix_is_in_correct_crate() {
        let report = AuditReport::sprint9_report();
        let c2 = report.findings.iter().find(|f| f.id == "SA-C2").unwrap();
        assert_eq!(c2.crate_name, "bleep-auth");
        assert!(matches!(c2.status, FindingStatus::Resolved { .. }));
    }
}
