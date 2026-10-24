# BLEEP Protocol — Chaos Testing (Sprint 9)

**Suite:** 14 adversarial scenarios  
**Validators:** 7 (bleep-testnet-1)  
**Continuous run:** 72 hours  
**Result:** ✅ All applicable scenarios PASS

The `LoadStress` entries are arithmetic block-capacity model checks in `ChaosEngine`; they do
not submit transactions, run a sustained load, or measure TPS. They must not be read as achieved
throughput. See [benchmark.md](../benchmark.md) for measured single-node CLI results and their
limitations.

---

## BFT Safety Bound

BLEEP consensus tolerates up to `f < n/3` Byzantine faults. With `n = 7` validators, `f_max = 2`.

| Scenario | Crashed | Remaining | Quorum | Result |
|---|---|---|---|---|
| ValidatorCrash(1) | 1 | 6 | 5 | ✅ PASS |
| ValidatorCrash(2) | 2 | 5 | 5 | ✅ PASS |
| ValidatorCrash(3) | 3 | 4 | 5 | ❌ Liveness halted (expected — f ≥ n/3) |

---

## Scenario Results

| Scenario | Result | Key Invariant |
|---|---|---|
| ValidatorCrash(1) | ✅ PASS | Consensus resumed within recovery window |
| ValidatorCrash(2) | ✅ PASS | Consensus resumed within recovery window |
| NetworkPartition(4/3) | ✅ PASS | Majority partition produced blocks; healed cleanly |
| NetworkPartition(5/2) | ✅ PASS | Majority partition produced blocks; healed cleanly |
| LongRangeReorg(10) | ✅ PASS | Rejected at FinalityManager (I-CON3) |
| LongRangeReorg(50) | ✅ PASS | Rejected at FinalityManager (I-CON3) |
| DoubleSign(validator-0) | ✅ PASS | 33% slashed; evidence committed; tombstoned |
| DoubleSign(validator-3) | ✅ PASS | 33% slashed; evidence committed; tombstoned |
| TxReplay | ✅ PASS | Rejected by nonce check (I-S5) |
| EclipseAttack(validator-6) | ✅ PASS | Mitigated by Kademlia k=20 and DNS seeds |
| InvalidBlockFlood(1000) | ✅ PASS | Rejected at SPHINCS+ gate; peer rate-limited |
| LoadStress(1,000 TPS, 60s) | ✅ Model check | Arithmetic capacity estimate; no transaction load executed |
| LoadStress(5,000 TPS, 60s) | ✅ Model check | Arithmetic capacity estimate; no transaction load executed |
| LoadStress(10,000 TPS, 60s) | ✅ Model check | Block-capacity saturation branch; not a TPS measurement |

---

## Continuous 72-Hour Harness

The `ContinuousChaosHarness` iterates the full 14-scenario suite in a loop for the target duration. Each iteration:
1. Runs all 14 scenarios against the live chain height
2. Records pass/fail per scenario
3. Sleeps for one epoch (100 blocks × 3s = 300s) before the next iteration

**72-hour result:** All critical safety invariants held continuously. Liveness scenarios with symmetric partitions (by design, not a violation) are noted separately.

---

## Running the Chaos Suite

```bash
# Unit test (fast, in-process simulation)
cargo test --package bleep-consensus chaos -- --nocapture

# Integration test
cargo test --test sprint9_integration chaos_integration -- --nocapture

# CI smoke job
cargo test --package bleep-consensus \
  validator_crash_within_bft_bound_passes \
  double_sign_always_detected \
  load_stress_10k_tps_passes_with_4096_cap \
  -- --nocapture
```
