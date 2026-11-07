# BLEEP Validator Guide

The repository launcher is the operator interface. It creates the post-quantum validator identity, registers it, and starts the node.

## Prerequisites

Build the release node and install `curl`, `python3`, and `xxd`:

```bash
cargo build --release --bin bleep
```

Choose a seed peer supplied by the network operator. A seed is simply an existing BLEEP node address used to discover peers; it is not a private key or a special flag order.

Before starting a node, provision a unique random JWT secret for it and export it as standard base64-encoded `BLEEP_JWT_SECRET` (at least 32 decoded bytes). Never reuse the repository's old development secret. Operator registration is restricted to a system administrator, so also set `BLEEP_ADMIN_TOKEN` to a valid administrator token before running `init`. For example, generate secret material with `openssl rand -base64 32` and store it in your deployment secret manager.

## First run

```bash
./scripts/run-validator.sh init \
  --name validator-1 \
  --seed seed.example.org:7700 \
  --rpc-url https://seed.example.org:8545 \
  --p2p-port 7700 \
  --rpc-port 8545 \
  --stake 1000000 \
  --address <YOUR_BLEEP_ADDRESS>
```

`init` performs the following steps:

- Creates `~/.bleep/validators/validator-1/state/`.
- Generates real ML-KEM-1024 and SPHINCS+-SHAKE-256f-simple keys if they are absent. Re-running it never regenerates existing keys. The key files in the state directory are stored with mode `0600`.
- Creates an operator session and performs registration through RPC.
- On testnet, requests one faucet drip when the configured account balance is below the requested stake. Faucet top-up is never attempted on mainnet.
- Writes `~/.bleep/validators/validator-1/config.toml`.
- Prints one prominent backup instruction for `validator.key`.
- Starts the validator.

The validator key files are in the state directory. Back up `validator.key` and `sphincs.secret` securely; losing the signing key loses the validator identity and stake. On startup, the node checks that the signing key matches the registered validator ID and refuses to start if they differ.

## Restart

The saved configuration supplies the ports, state directory, binary, RPC endpoint, seed, network, and stake. The node reuses its persisted keys and chain state on restart:

```bash
./scripts/run-validator.sh run --name validator-1
```

The restart path runs the preflight checks before starting the node.

## Preflight and status

```bash
./scripts/run-validator.sh doctor --name validator-1
./scripts/run-validator.sh status --name validator-1
```

`doctor` checks the binary, both local ports, seed/RPC reachability, clock synchronization, and account balance when an address is configured. It stops with one concise sentence on failure.

`status` reports active/inactive state, current stake, peer count, and the latest chain height exposed by the node.

## Start at boot

Install a per-user systemd unit during initialization:

```bash
./scripts/run-validator.sh init --name validator-1 --seed seed.example.org:7700 --install-service
```

The unit restarts the validator after failures and survives terminal closure. The launcher stores `BLEEP_JWT_SECRET` in a mode-0600 environment file for that unit; protect the validator state directory. On systems without systemd, configure `BLEEP_JWT_SECRET` in the platform's secret manager and run the launcher from the service manager using the `run --name validator-1` command.

## Configuration

The generated TOML is the source of truth for restarts. Change it deliberately, then run `doctor` before restarting. The node also supports these environment settings:

- `BLEEP_SNAPSHOT_INTERVAL` — snapshot every N committed blocks (default `1000`).
- `BLEEP_SNAPSHOT_RETAIN` — number of newest snapshots to keep (default `3`; must be positive). Old snapshots are pruned only after a new snapshot completes.
- `BLEEP_TX_REPLAY_WINDOW_SECS` — maximum accepted client timestamp skew in either direction (default `30`; must be positive).

Snapshots require at least the estimated database size plus 64 MiB free before writing. `/metrics` exposes `bleep_disk_free_bytes`, `bleep_disk_total_bytes`, and `bleep_disk_usage_percent`; the node logs an alert at 85% filesystem usage.

Transactions accepted by `/rpc/tx` are durably stored in RocksDB before the node responds with `accepted_durable`. Pending transactions are replayed on startup. If recovery rejects an expired or invalid entry, it is removed and logged as an explicit drop.

Do not commit the state directory, `validator.key`, or the generated operator password.
