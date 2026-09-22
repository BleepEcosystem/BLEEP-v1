# BLEEP Validator Guide

The repository launcher is the operator interface. It creates the post-quantum validator identity, registers it, and starts the node.

## Prerequisites

Build the release node and install `curl`, `python3`, and `xxd`:

```bash
cargo build --release --bin bleep
```

Choose a seed peer supplied by the network operator. A seed is simply an existing BLEEP node address used to discover peers; it is not a private key or a special flag order.

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
- Generates real Kyber-1024 and SPHINCS+-SHAKE-256f-simple keys if they are absent. Re-running it never regenerates existing keys.
- Creates an operator session and performs registration through RPC.
- On testnet, requests one faucet drip when the configured account balance is below the requested stake. Faucet top-up is never attempted on mainnet.
- Writes `~/.bleep/validators/validator-1/config.toml`.
- Prints one prominent backup instruction for `validator.key`.
- Starts the validator.

The private key files are in the state directory. Back up `validator.key` and protect the backup. Losing it loses the validator identity and stake.

## Restart

The saved configuration supplies the ports, state directory, binary, RPC endpoint, seed, network, and stake:

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

The unit restarts the validator after failures and survives terminal closure. On systems without systemd, run the launcher from the platform's service manager using the `run --name validator-1` command.

## Configuration

The generated TOML is the source of truth for restarts. Change it deliberately, then run `doctor` before restarting. Do not commit the state directory, `validator.key`, or the generated operator password.
