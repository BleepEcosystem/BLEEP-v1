# BLEEP Testnet Validator Guide
**Network:** `bleep-testnet-1` | **Sprint:** 8 | **Protocol Version:** 3

This guide walks external operators through staking, configuring, and running a BLEEP validator on the public testnet. Follow every step in order — a single misconfigured parameter will prevent your node from finalising blocks.

---

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 100 GB SSD | 500 GB NVMe |
| Network | 100 Mbps | 1 Gbps |
| OS | Ubuntu 22.04 | Ubuntu 22.04 LTS |
| Rust | 1.76.0 | stable (latest) |
| Docker | 24.0+ | 24.0+ |
| Open ports | 7700/tcp (P2P), 8545/tcp (RPC) | — |

**Stake requirement:** Minimum 1,000,000 microBLEEP (0.01 BLEEP). Recommended: 10,000,000 (0.1 BLEEP) to receive meaningful rewards.

---

## Step 1 — Install dependencies

```bash
# System packages
sudo apt-get update && sudo apt-get install -y \
  build-essential clang libclang-dev libssl-dev pkg-config curl git

# Rust (skip if already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.76.0
source "$HOME/.cargo/env"

# Verify
rustc --version   # should print: rustc 1.76.0
cargo --version
```

---

## Step 2 — Build the BLEEP node binary

```bash
git clone https://github.com/bleep-network/bleep-v1.git
cd bleep-v1
git checkout main     # or the latest tagged release

cargo build --release --bin bleep
sudo install -m 755 target/release/bleep /usr/local/bin/bleep

bleep --version       # prints: bleep 0.8.0 (sprint-8)
```

---

## Step 3 — Generate your validator keypair

BLEEP validators use **SPHINCS+-shake-256s** for block signing (post-quantum secure).

```bash
# Generates validator keypair and prints your validator ID
bleep keygen --output ~/.bleep/keys/validator.key

# Output example:
#   Validator ID:  validator-abc123...
#   Public key:    (hex)
#   Key file:      ~/.bleep/keys/validator.key
#   IMPORTANT: Back up ~/.bleep/keys/validator.key — it cannot be recovered!
```

> **Security:** Never share your `validator.key` file. Store a backup in cold storage (encrypted USB + paper backup of the seed hex). Loss of this key means loss of your staked BLEEP.

---

## Step 4 — Fund your validator account

Your validator needs staked BLEEP to participate in consensus.

**Testnet faucet** (for testing only — not real value):
```bash
# Request 1,000 test BLEEP (usable for staking on testnet)
curl -X POST https://val0.testnet.bleep.network:8545/faucet/<YOUR_BLEEP_ADDRESS>

# Or use the block explorer faucet UI:
# https://explorer.testnet.bleep.network
```

**Stake your tokens:**
```bash
curl -X POST http://localhost:8545/rpc/validator/stake \
  -H "Content-Type: application/json" \
  -d '{
    "validator_id": "<your-validator-id>",
    "stake_amount": 10000000,
    "delegator_address": "<your-bleep-address>"
  }'
```

---

## Step 5 — Configure your node

Create `/etc/bleep/config.toml`:

```toml
[node]
chain_id         = "bleep-testnet-1"
genesis_file     = "/etc/bleep/testnet-genesis.toml"
state_dir        = "/var/lib/bleep/state"
validator_key    = "/etc/bleep/keys/validator.key"

[p2p]
listen_addr      = "0.0.0.0:7700"
external_addr    = "<YOUR_PUBLIC_IP>:7700"
bootstrap_peers  = [
  "seed0.testnet.bleep.network:7700",
  "seed1.testnet.bleep.network:7700",
  "seed2.testnet.bleep.network:7700",
]
max_peers        = 50

[rpc]
listen_addr      = "0.0.0.0:8545"
# For public validators, protect this port with nginx + TLS + auth.

[consensus]
validator_id     = "<your-validator-id>"
# Must match the ID registered via /rpc/validator/stake.

[telemetry]
prometheus_port  = 9090
log_level        = "info"
```

Copy the testnet genesis file:
```bash
sudo mkdir -p /etc/bleep
curl -o /etc/bleep/testnet-genesis.toml \
  https://raw.githubusercontent.com/bleep-network/bleep-v1/main/devnet/testnet-genesis.toml
```

---

## Step 6 — Start your node

For a local or testnet validator, the repository includes a launcher that
assigns the node's ports and state directory and connects it to seed peers:

```bash
./scripts/run-validator.sh \
  --name validator-1 \
  --p2p-port 7701 \
  --rpc-port 8546 \
  --seeds "<SEED_IP>:7700"
```

Build automatically before starting with `--build`. Run one validator per
machine, use a different state directory for additional local validators, and
allow inbound TCP traffic on the P2P port.

**Option A — systemd (recommended for production):**

```ini
# /etc/systemd/system/bleep-validator.service
[Unit]
Description=BLEEP Validator Node
After=network-online.target
Wants=network-online.target

[Service]
User=bleep
Group=bleep
ExecStart=/usr/local/bin/bleep node --config /etc/bleep/config.toml
Restart=on-failure
RestartSec=10
LimitNOFILE=65535
Environment=RUST_LOG=info,bleep=debug

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable bleep-validator
sudo systemctl start bleep-validator
sudo journalctl -fu bleep-validator
```

**Option B — Docker:**
```bash
docker run -d \
  --name bleep-validator \
  --restart unless-stopped \
  -p 7700:7700 -p 8545:8545 \
  -v /etc/bleep:/config:ro \
  -v /var/lib/bleep:/data \
  -e BLEEP_VALIDATOR_ID=<your-id> \
  -e BLEEP_GENESIS_FILE=/config/testnet-genesis.toml \
  bleepnetwork/bleep-node:sprint-8
```

---

## Step 7 — Verify your node is joining consensus

Check your node is producing blocks and syncing:

```bash
# Health check
curl http://localhost:8545/rpc/health
# Expected: {"status":"ok","height":N,"peers":>0,...}

# Check you appear in the validator list
curl http://localhost:8545/rpc/validator/list

# Watch logs for block production
sudo journalctl -fu bleep-validator | grep -E "produced|signed|epoch"
```

**Definition of joined:** Your node appears in `/rpc/validator/list` with status `active`, signs ≥80% of blocks in the first epoch, and your stake is reflected in `/rpc/economics/supply`.

---

## Step 8 — Configure Prometheus + Grafana (optional but recommended)

Your node exposes metrics at `GET /metrics` in Prometheus text format.

```yaml
# prometheus.yml scrape addition:
- job_name: 'my-bleep-validator'
  static_configs:
    - targets: ['localhost:8545']
  metrics_path: '/metrics'
  scrape_interval: 6s
```

Import the BLEEP dashboard from `devnet/grafana/dashboards/bleep-testnet-overview.json` into your Grafana instance.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `peers: 0` after 5 minutes | Firewall blocking 7700/tcp | Open port 7700 inbound/outbound |
| `InvalidSignature` on block proposals | Validator key file wrong path | Check `validator_key` in config.toml |
| Node stuck at height 0 | Genesis file mismatch | Re-download testnet-genesis.toml |
| `StakeInsufficient` error | Stake below minimum | Request more from faucet; re-stake |
| High memory (>8 GB) | State DB growth | Increase `max_open_files` in RocksDB config |

---

## Slashing conditions

The following actions result in automatic stake slashing:

- **Double-sign (equivocation):** 33% of stake slashed immediately and irrecoverably.
- **Downtime >10 consecutive missed blocks:** 1% of stake slashed per epoch.
- **BLEEP Connect executor timeout:** 30% of executor bond slashed.

Monitor your validator uptime via the Grafana dashboard and set up PagerDuty/alerting on `bleep_node_uptime_seconds`.

---

## Getting help

- GitHub Issues: https://github.com/bleep-network/bleep-v1/issues
- Discord: https://discord.gg/bleep-network (#validators channel)
- Testnet status: https://status.testnet.bleep.network
