# BLEEP Benchmark Report

## Three-Node Mesh and 1,000-Transaction Run

### Connectivity

On 2026-10-04, three release-built BLEEP nodes were run on loopback with separate state directories. Node 2 bootstrapped to node 1; node 3 bootstrapped to nodes 1 and 2, forming a full mesh. Each `/rpc/health` response reported `peers: 2` before and after the workload.

The focused P2P test `cargo test -p bleep-p2p test_three_nodes_exchange_authenticated_gossip -- --nocapture` passed. It established authenticated sessions among all pairs and delivered transaction, block, and signature-availability messages in both directions.

The full-node run exposed an application-level block propagation failure despite successful peer connectivity and gossip delivery (`attempted=2 delivered=2`). Receivers rejected JSON blocks because validation used the receiver's local validator key; the separate `GossipBridge` also sent a compact binary payload to an inbound handler that only decodes JSON. RPC transaction submissions were not broadcast to the other nodes: nodes 2 and 3 remained at height 0 and processed 0 transactions. This is therefore a local-node TPS measurement, not network-wide execution or consensus throughput.

The run also exposed a Tokio runtime panic in the synchronous signature-availability cache adapter, which called `Handle::block_on` from a runtime worker. The adapter now uses `block_in_place`; `cargo test --release -p bleep-root --bin bleep cache_can_be_called_from_runtime_worker` passed. A post-fix two-node smoke run accepted 100/100 transactions in 10.278 seconds, produced blocks on node 1, and left node 2 healthy with one peer. Node 2 still rejected those blocks at validator-signature verification, so this fix does not change the network-wide limitation above.

### TPS Measurement

The sequential CLI workload ran from 2026-10-04 03:57:24 UTC for 103.084 seconds. It submitted 1,000 unique, SPHINCS+-signed transfers of amount `1` to node 1 over authenticated RPC.

| Result | Measurement |
|---|---:|
| Accepted submissions | 1,000 / 1,000 |
| Failed submissions | 0 |
| Submission duration | 103.084 s |
| Accepted submission throughput | 9.701 TPS |
| Settled node-1 transactions processed | 1,000 |
| Node-1 blocks produced / final height | 36 / 36 |
| Node-1 peers | 2 |
| Node-2 height / processed transactions | 0 / 0 |
| Node-3 height / processed transactions | 0 / 0 |

At the immediate end-of-loop scrape, node 1 had processed 968 transactions; a later scrape showed all 1,000 processed. The benchmark harness reports the immediate counter, so use `/rpc/telemetry` after pending work drains for the settled total.

### Reproduction

Build the binaries and start each node in a separate terminal, using the same local JWT secret and distinct state directories:

```bash
cargo build --release -p bleep-root --bin bleep -p bleep-cli --bin bleep-cli
export BLEEP_JWT_SECRET='<base64 secret of at least 32 bytes>'

BLEEP_STATE_DIR=/tmp/bleep-mesh/node1 BLEEP_P2P_LISTEN_ADDR=127.0.0.1:17700 BLEEP_RPC_LISTEN_ADDR=127.0.0.1:18540 ./target/release/bleep
BLEEP_STATE_DIR=/tmp/bleep-mesh/node2 BLEEP_P2P_LISTEN_ADDR=127.0.0.1:17701 BLEEP_P2P_SEEDS=127.0.0.1:17700 BLEEP_RPC_LISTEN_ADDR=127.0.0.1:18541 ./target/release/bleep
BLEEP_STATE_DIR=/tmp/bleep-mesh/node3 BLEEP_P2P_LISTEN_ADDR=127.0.0.1:17702 BLEEP_P2P_SEEDS=127.0.0.1:17700,127.0.0.1:17701 BLEEP_RPC_LISTEN_ADDR=127.0.0.1:18542 ./target/release/bleep
```

Create a wallet against node 1, then run the configurable harness:

```bash
BLEEP_RPC=http://127.0.0.1:18540 ./target/release/bleep-cli wallet create
BLEEP_CLI=./target/release/bleep-cli BLEEP_RPC=http://127.0.0.1:18540 BLEEP_TPS_COUNT=1000 ./test_tps.sh
```

`test_tps.sh` defaults to 1,000 transactions and counts a submission only when its RPC response has `status: accepted`. Set `BLEEP_TPS_COUNT` to change the run size. Keep the shared JWT secret out of shell history and repository files.

## Executive Summary

This document records a measured 10,000-transaction benchmark against a single local BLEEP node. The workload used the release-built `bleep-cli`, a funded quantum-secure wallet, authenticated HTTP submission, and unique receiver addresses.

| Result | Measurement |
|---|---:|
| Transactions submitted | 10,000 / 10,000 |
| CLI failures | 0 |
| Wall-clock duration | 1,554.489 s (25m 54.489s) |
| Client submission throughput | 6.432982 TPS |
| Settled node processing throughput | 6.432982 TPS |
| Blocks produced during benchmark | 519 |
| Average block interval | 2.995 s |
| Average transactions per block | 19.27 |
| Final settled chain height | 520 |
| Peers | 0 |

The submission loop completed all 10,000 requests successfully. The node's immediate post-loop scrape showed 9,982 processed benchmark transactions; a final settled scrape showed 10,001 total processed transactions, including the one transaction that existed before the benchmark. Therefore, the settled benchmark delta is exactly 10,000 processed transactions.

## Scope and Workload

- Network: local single-node development instance
- Node binary: `target/release/bleep`
- RPC endpoint: `http://127.0.0.1:8545`
- CLI binary: `target/release/bleep-cli`
- Workload: 10,000 transfers of `1 BLEEP`
- Receivers: unique deterministic addresses derived from iteration numbers
- Submission mode: sequential, one CLI process per transaction
- Authentication: JWT via `BLEEP_JWT_SECRET`, supplied through the shell and not recorded here
- Wallet: SPHINCS+-SHAKE-256 signing wallet funded by the local faucet
- Benchmark period: `2026-09-12T10:43:08Z` to `2026-09-12T11:09:02Z`

The wallet was created before the benchmark and received 10 BLEEP from the faucet. At the end of the run its nonce was `10,001` and its reported balance was `999,989,999 BLEEP`.

## Reproduction

Build the CLI in release mode:

```bash
cargo build -p bleep-cli --release
```

Start the local node separately:

```bash
cargo run --bin bleep --release
```

Create and fund a wallet:

```bash
./target/release/bleep-cli wallet create
```

Set the JWT secret to the value configured for the running node. Do not commit the value:

```bash
export BLEEP_JWT_SECRET='<base64-encoded-node-secret>'
```

The following harness records health, Prometheus metrics, timing, process resources, transaction output, and errors. It uses Bash's `time` builtin because `/usr/bin/time` was not installed in the benchmark environment.

```bash
rm -rf /tmp/bleep-benchmark-10000
mkdir -p /tmp/bleep-benchmark-10000

printf 'benchmark_start_utc=' > /tmp/bleep-benchmark-10000/meta.txt
date -u +%Y-%m-%dT%H:%M:%SZ >> /tmp/bleep-benchmark-10000/meta.txt
curl -sS http://127.0.0.1:8545/rpc/health \
  > /tmp/bleep-benchmark-10000/health-before.json
curl -sS http://127.0.0.1:8545/metrics \
  > /tmp/bleep-benchmark-10000/metrics-before.txt
ps -p "$(pgrep -n -f 'target/release/bleep')" \
  -o pid,etime,%cpu,%mem,rss,vsz \
  > /tmp/bleep-benchmark-10000/process-before.txt

TIMEFORMAT='real_seconds=%3R user_seconds=%3U sys_seconds=%3S'
{
  time for i in $(seq 1 10000); do
    ./target/release/bleep-cli tx send \
      "BLEEP$(printf '%040x' "$((i + 2))")" 1 \
      >> /tmp/bleep-benchmark-10000/transactions.log \
      2>> /tmp/bleep-benchmark-10000/errors.log
    rc=$?
    if [[ $rc -ne 0 ]]; then
      printf 'iteration=%s exit=%s\n' "$i" "$rc" \
        >> /tmp/bleep-benchmark-10000/failures.log
    fi
    if (( i % 1000 == 0 )); then
      printf 'completed=%s\n' "$i" >&2
    fi
  done
} 2> /tmp/bleep-benchmark-10000/time.txt

printf 'benchmark_end_utc=' >> /tmp/bleep-benchmark-10000/meta.txt
date -u +%Y-%m-%dT%H:%M:%SZ >> /tmp/bleep-benchmark-10000/meta.txt
curl -sS http://127.0.0.1:8545/rpc/health \
  > /tmp/bleep-benchmark-10000/health-after.json
curl -sS http://127.0.0.1:8545/metrics \
  > /tmp/bleep-benchmark-10000/metrics-after.txt
ps -p "$(pgrep -n -f 'target/release/bleep')" \
  -o pid,etime,%cpu,%mem,rss,vsz \
  > /tmp/bleep-benchmark-10000/process-after.txt
```

After the loop, wait for the node to settle before taking the final counters. The settled snapshot is required because the immediate scrape can lag behind accepted submissions.

## Chain Readings

### Baseline before the workload

```json
{"status":"ok","height":1,"peers":0,"uptime_secs":1081,"version":"1.0.0"}
```

| Metric | Baseline |
|---|---:|
| Chain height | 1 |
| Blocks produced | 1 |
| Transactions processed | 1 |
| Peers | 0 |
| Node uptime | 1,081 s |

### Immediate post-loop snapshot

```json
{"status":"ok","height":519,"peers":0,"uptime_secs":2635,"version":"1.0.0"}
```

| Metric | Immediate value | Delta from baseline |
|---|---:|---:|
| Chain height | 519 | +518 |
| Blocks produced | 519 | +518 |
| Transactions processed | 9,982 | +9,981 |
| Peers | 0 | 0 |

### Settled post-run snapshot

The final scrape was taken after the submission loop stopped and pending work had drained:

```json
{"status":"ok","height":520,"peers":0,"uptime_secs":2684,"version":"1.0.0"}
```

| Metric | Settled value | Delta from baseline |
|---|---:|---:|
| Chain height | 520 | +519 |
| Blocks produced | 520 | +519 |
| Transactions processed | 10,001 | +10,000 |
| Peers | 0 | 0 |
| Node uptime | 2,684 s | +1,603 s |

The settled delta is the authoritative result for completion and block production.

## Prometheus Metrics

The node exposed the following metrics at `/metrics`:

| Metric | Baseline | Immediate post-loop | Settled post-run |
|---|---:|---:|---:|
| `bleep_chain_height` | 1 | 519 | 520 |
| `bleep_blocks_produced_total` | 1 | 519 | 520 |
| `bleep_transactions_processed_total` | 1 | 9,982 | 10,001 |
| `bleep_peer_count` | 0 | 0 | 0 |
| `bleep_node_uptime_seconds` | 1,081 | 2,635 | 2,684 |
| `bleep_faucet_drips_total` | 1 | 1 | 1 |
| `bleep_faucet_balance_micro` | 9,999,000,000,000 | 9,999,000,000,000 | 9,999,000,000,000 |
| `bleep_jwt_rotations_total` | 0 | 0 | 0 |

## Timing and Derived Metrics

The Bash timing output was:

```text
real_seconds=1554.489 user_seconds=663.905 sys_seconds=182.084
```

Calculations use the settled benchmark delta of 10,000 transactions and 519 blocks over 1,554.489 seconds.

| Derived metric | Formula | Result |
|---|---|---:|
| Submission throughput | 10,000 / 1,554.489 | 6.432982 TPS |
| Settled processing throughput | 10,000 / 1,554.489 | 6.432982 TPS |
| Block production rate | 519 / 1,554.489 | 0.333872 blocks/s |
| Average block interval | 1,554.489 / 519 | 2.995 s |
| Average transactions per block | 10,000 / 519 | 19.268 transactions/block |
| Submission completion | 10,000 / 10,000 | 100% |
| Settled processing completion | 10,000 / 10,000 | 100% |
| User CPU time | recorded by Bash `time` | 663.905 s |
| System CPU time | recorded by Bash `time` | 182.084 s |

## Node Resource Readings

These are process samples for the node process, not averages over the full benchmark window.

| Reading | Before | After | Change |
|---|---:|---:|---:|
| PID | 33350 | 33350 | unchanged |
| Process elapsed time | 33:48 | 59:42 | +25:54 |
| CPU percentage sample | 1.4% | 5.3% | +3.9 pp |
| Memory percentage sample | 0.1% | 3.9% | +3.8 pp |
| RSS | 22,768 KB | 652,244 KB | +629,476 KB |
| VSZ | 822,128 KB | 1,285,240 KB | +463,112 KB |

## Integrity Checks

- Transaction output contained 10,000 `Transaction submitted` records.
- CLI error count was zero.
- Failed iteration count was zero.
- The node remained healthy with HTTP status `200` from `/rpc/health`.
- The node remained a single-node network throughout the run: peers stayed at `0`.
- The settled wallet nonce advanced to `10,001`, consistent with the one pre-benchmark transaction plus 10,000 benchmark transactions.
- The repository worktree was unchanged by the benchmark.

## Interpretation

This is an end-to-end local CLI benchmark, not a raw protocol or maximum-capacity benchmark. Every transaction launched a new `bleep-cli` process, loaded and unlocked the wallet, generated a SPHINCS+ signature, generated an authenticated request, and waited for the RPC response. The measured `6.43 TPS` therefore includes client startup, signing, serialization, HTTP, validation, and node processing overhead.

The 519 blocks produced during the workload were approximately three seconds apart and contained about 19.27 transactions each on average. Because the node had zero peers, the result measures a single validator/node under local conditions and says nothing about multi-node propagation, consensus convergence, network bandwidth, or cross-validator behavior.

The increase in RSS from approximately 22.8 MB to 652.2 MB should be investigated before using this configuration for a long-running production workload. The samples are not a memory profile and do not identify the allocation source.

## Limitations and Follow-up Measurements

For a production-grade capacity study, repeat this benchmark with:

1. A persistent client that signs and submits without spawning 10,000 CLI processes.
2. Multiple concurrent submitters and controlled concurrency levels.
3. A clean node state and a fixed-duration warm-up before measurement.
4. At least four validators with measured peer count and propagation latency.
5. Separate measurements for signing time, RPC round-trip latency, mempool admission, block inclusion, and finality.
6. CPU and memory sampling at regular intervals, preferably through cgroups or Prometheus rather than two process snapshots.
7. Several repetitions with median, p95, and p99 latency and throughput reporting.
8. Explicit transaction status polling so accepted, included, committed, rejected, and expired transactions are counted separately.

## Concurrent Stress Test

After the sequential benchmark, a second run stressed the same live single-node instance with 10,000 transfers and 32 concurrent CLI submitters. This is a burst/concurrency test, not a direct comparison of protocol capacity: each worker still launched a separate `bleep-cli` process and performed SPHINCS+ signing.

### Workload and outcome

| Result | Measurement |
|---|---:|
| Concurrency | 32 workers |
| Transactions submitted | 10,000 / 10,000 |
| Result files | 10,000 |
| Application errors | 0 |
| Wall-clock duration | 379.831 s (6m 19.831s) |
| Concurrent submission throughput | 26.327498 TPS |
| Start time UTC | 2026-09-12T11:31:43Z |
| End time UTC | 2026-09-12T11:38:03Z |

The shell emitted this harness warning because `xargs` was given both `--max-args` and replacement mode:

```text
xargs: warning: options --max-args and --replace/-I/-i are mutually exclusive, ignoring previous --max-args value
```

This did not reduce concurrency: replacement mode still launched one command per input item and `-P 32` limited active commands to 32. The warning should be removed in a future harness revision by dropping `-n 1` when using `-I`.

### Chain and processing readings

The immediate post-run scrape reported height 578 while final blocks were still being produced. The settled scrape after the workload drained reported:

```json
{"status":"ok","height":580,"peers":0,"uptime_secs":4407,"version":"1.0.0"}
```

| Metric | Before stress | Settled after stress | Delta |
|---|---:|---:|---:|
| Chain height | 520 | 580 | +60 |
| Blocks produced | 520 | 580 | +60 |
| Transactions processed | 10,001 | 20,001 | +10,000 |
| Peers | 0 | 0 | 0 |

Derived settled rates for the 379.831-second run:

| Derived metric | Result |
|---|---:|
| Transaction throughput | 26.327498 TPS |
| Block production rate | 0.157965 blocks/s |
| Average block interval | 6.331 s |
| Average transactions per block | 166.667 |
| Submission completion | 100% |
| Settled processing completion | 100% |

The lower apparent block rate and higher transactions-per-block value reflect batching under concurrent load. The node continued processing blocks after the submission command returned, so the settled values must be used for completion accounting.

### Resource readings

| Reading | Before | After | Change |
|---|---:|---:|---:|
| CPU percentage sample | 4.0% | 6.0% | +2.0 pp |
| Memory percentage sample | 3.9% | 7.8% | +3.9 pp |
| RSS | 652,244 KB | 1,286,500 KB | +634,256 KB |
| VSZ | 1,285,240 KB | 1,944,744 KB | +659,504 KB |

The shell timing output was `real_seconds=379.831 user_seconds=991.123 sys_seconds=222.727`. User and system CPU seconds exceed wall time because the 32 workers ran concurrently. The RSS increase is significant and should be investigated before treating this workload shape as production-ready.

### Stress-test interpretation

Compared with the sequential CLI run at 6.432982 TPS, this 32-worker run achieved 26.327498 TPS, a 4.092581x throughput increase. The result is still dominated by CLI process startup, wallet loading, SPHINCS+ signing, and local RPC behavior. It does not establish multi-validator throughput, network propagation capacity, or finality latency.

### Stress-test artifacts

```text
/tmp/bleep-stress-10000-c32/start.utc
/tmp/bleep-stress-10000-c32/end.utc
/tmp/bleep-stress-10000-c32/time.txt
/tmp/bleep-stress-10000-c32/summary.txt
/tmp/bleep-stress-10000-c32/health-before.json
/tmp/bleep-stress-10000-c32/health-after.json
/tmp/bleep-stress-10000-c32/metrics-before.txt
/tmp/bleep-stress-10000-c32/metrics-after.txt
/tmp/bleep-stress-10000-c32/process-before.txt
/tmp/bleep-stress-10000-c32/process-after.txt
/tmp/bleep-stress-10000-c32/out/
/tmp/bleep-stress-10000-c32/err/
```

The per-request stderr files contain CLI debug diagnostics, so their non-zero file count is not an application-error count. The authoritative stress result is the summary's `submitted=10000` and `application_errors=0`, corroborated by the settled node counter delta.

## Raw Artifacts

The raw files from this run were written outside the repository at:

```text
/tmp/bleep-benchmark-10000/meta.txt
/tmp/bleep-benchmark-10000/summary.txt
/tmp/bleep-benchmark-10000/time.txt
/tmp/bleep-benchmark-10000/health-before.json
/tmp/bleep-benchmark-10000/health-after.json
/tmp/bleep-benchmark-10000/metrics-before.txt
/tmp/bleep-benchmark-10000/metrics-after.txt
/tmp/bleep-benchmark-10000/process-before.txt
/tmp/bleep-benchmark-10000/process-after.txt
/tmp/bleep-benchmark-10000/transactions.log
/tmp/bleep-benchmark-10000/errors.log
```

These files are temporary host artifacts and are not included in the repository by this document.
