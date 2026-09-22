#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
NAME=${BLEEP_VALIDATOR_NAME:-validator}; BASE=${HOME}/.bleep/validators
RPC_URL=${BLEEP_RPC_URL:-http://127.0.0.1:8545}; SEED=${BLEEP_P2P_SEEDS:-}
P2P_PORT=${BLEEP_P2P_PORT:-7700}; RPC_PORT=${BLEEP_RPC_PORT:-8545}
STATE_DIR=${BLEEP_STATE_DIR:-}; NODE_BIN=${BLEEP_NODE_BIN:-$ROOT_DIR/target/release/bleep}
STAKE=${BLEEP_VALIDATOR_STAKE:-1000000}; NETWORK=${BLEEP_NETWORK:-testnet}; ADDRESS=${BLEEP_VALIDATOR_ADDRESS:-}; SERVICE=0
VALIDATOR_ID=${BLEEP_VALIDATOR_ID:-}
CONFIG_FILE=
fail() { echo "validator: $*" >&2; exit 1; }
usage() { cat <<EOF
Usage: $(basename "$0") init|run|doctor|status [options]
  --name NAME --seed HOST:PORT --rpc-url URL --p2p-port PORT --rpc-port PORT
  --state-dir DIR --binary PATH --stake MICROBLEEP --network testnet|mainnet
  --address ADDRESS --install-service
EOF
}
COMMAND=${1:-run}; [[ "$COMMAND" == -* ]] && COMMAND=run || shift || true
while (($#)); do case "$1" in
  --name) NAME=${2:?missing --name}; shift 2;; --seed|--seeds) SEED=${2:?missing --seed}; shift 2;;
  --rpc-url) RPC_URL=${2:?missing --rpc-url}; shift 2;; --p2p-port) P2P_PORT=${2:?missing --p2p-port}; shift 2;;
  --rpc-port) RPC_PORT=${2:?missing --rpc-port}; shift 2;; --state-dir) STATE_DIR=${2:?missing --state-dir}; shift 2;;
  --binary) NODE_BIN=${2:?missing --binary}; shift 2;; --stake|--amount) STAKE=${2:?missing --stake}; shift 2;;
  --network) NETWORK=${2:?missing --network}; shift 2;; --address) ADDRESS=${2:?missing --address}; shift 2;;
  --install-service) SERVICE=1; shift;; -h|--help) usage; exit 0;; *) fail "unknown option: $1";; esac; done
CONFIG_FILE="$BASE/$NAME/config.toml"; STATE_DIR=${STATE_DIR:-$BASE/$NAME/state}
load_config() {
  [[ -f "$CONFIG_FILE" ]] || return 0
  while IFS='=' read -r key value; do value=${value#\"}; value=${value%\"}; case "$key" in
    name) NAME=$value;; rpc_url) RPC_URL=$value;; seed) SEED=$value;; p2p_port) P2P_PORT=$value;; rpc_port) RPC_PORT=$value;;
    state_dir) STATE_DIR=$value;; binary) NODE_BIN=$value;; stake) STAKE=$value;; network) NETWORK=$value;; address) ADDRESS=$value;; validator_id) VALIDATOR_ID=$value;; esac
  done < <(sed -n '/^\[validator\]/,/^\[/p' "$CONFIG_FILE" | sed -n 's/^\([a-z_]*\) *= *"\{0,1\}\([^"#]*\)"*.*/\1=\2/p')
}
save_config() { mkdir -p "$(dirname "$CONFIG_FILE")"; umask 077; cat >"$CONFIG_FILE" <<EOF
[validator]
name = "$NAME"
rpc_url = "$RPC_URL"
seed = "$SEED"
p2p_port = "$P2P_PORT"
rpc_port = "$RPC_PORT"
state_dir = "$STATE_DIR"
binary = "$NODE_BIN"
stake = "$STAKE"
network = "$NETWORK"
address = "$ADDRESS"
validator_id = "$VALIDATOR_ID"
EOF
}
port_free() { ! (command -v ss >/dev/null && ss -H -ltn "sport = :$1" | grep -q .); }
doctor() {
  load_config; [[ -x "$NODE_BIN" ]] || fail "binary is not built: $NODE_BIN"
  port_free "$P2P_PORT" || fail "P2P port $P2P_PORT is already in use"; port_free "$RPC_PORT" || fail "RPC port $RPC_PORT is already in use"
  [[ -n "$SEED" ]] || fail "seed peer is not configured"; curl -fsS --connect-timeout 3 "$RPC_URL/rpc/health" >/dev/null || fail "seed/RPC endpoint is unreachable: $RPC_URL"
  if command -v timedatectl >/dev/null && ! timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes; then fail "system clock is not synchronized"; fi
  if [[ -n "$ADDRESS" ]]; then balance=$(curl -fsS "$RPC_URL/rpc/state/$ADDRESS" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("balance", "0"))') || fail "account balance could not be checked"; (( balance >= STAKE )) || fail "account balance $balance is below requested stake $STAKE"; fi
  echo "validator doctor: ready"
}
install_service() {
  command -v systemctl >/dev/null || fail "systemd is unavailable"; unit="$HOME/.config/systemd/user/bleep-validator-$NAME.service"; mkdir -p "$(dirname "$unit")"
  cat >"$unit" <<EOF
[Unit]
Description=BLEEP validator $NAME
After=network-online.target
[Service]
ExecStart=$SCRIPT_DIR/run-validator.sh run --name $NAME
Restart=on-failure
RestartSec=10
[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload; systemctl --user enable --now "bleep-validator-$NAME.service"; echo "validator: installed bleep-validator-$NAME"
}
init_validator() {
  [[ -n "$SEED" ]] || fail "a seed peer is required; use --seed HOST:PORT"; [[ -x "$NODE_BIN" ]] || fail "binary is not built: $NODE_BIN"
  mkdir -p "$STATE_DIR"; [[ -x "$ROOT_DIR/target/release/bleep-validator-keygen" ]] || cargo build --release --bin bleep-validator-keygen >/dev/null
  "$ROOT_DIR/target/release/bleep-validator-keygen" "$STATE_DIR" >/dev/null
  if [[ ! -f "$STATE_DIR/validator-password" ]]; then umask 077; head -c 32 /dev/urandom | base64 >"$STATE_DIR/validator-password"; fi
  operator="validator-$NAME"; password=$(cat "$STATE_DIR/validator-password"); public_key=$(cat "$STATE_DIR/kyber.public"); signing_public_key=$(cat "$STATE_DIR/sphincs.public")
  if [[ -n "$ADDRESS" ]]; then
    balance=$(curl -fsS "$RPC_URL/rpc/state/$ADDRESS" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("balance", "0"))') || fail "account balance could not be checked"
    if (( balance < STAKE )); then
      [[ "$NETWORK" != "mainnet" ]] || fail "account balance $balance is below requested stake $STAKE"
      curl -fsS -X POST "$RPC_URL/faucet/$ADDRESS" >/dev/null || fail "testnet faucet top-up failed"
    fi
  fi
  kyber_b64=$(printf %s "$public_key" | xxd -r -p | base64 -w0)
  token=$(curl -fsS -X POST "$RPC_URL/rpc/auth/register/operator" -H 'Content-Type: application/json' --data "{\"operator_handle\":\"$operator\",\"display_name\":\"$NAME\",\"password\":\"$password\",\"kyber_public_key_b64\":\"$kyber_b64\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token", ""))') || fail "RPC operator registration failed"
  [[ -n "$token" ]] || fail "RPC did not return an authentication token"; timestamp=$(date +%s); proof=$("$ROOT_DIR/target/release/bleep-validator-keygen" sign "$STATE_DIR" "$NAME" "$STAKE" "$timestamp")
  response=$(curl -fsS -X POST "$RPC_URL/rpc/validator/stake" -H 'Content-Type: application/json' -H "Authorization: Bearer $token" --data "{\"tx_type\":\"stake\",\"amount\":$STAKE,\"label\":\"$NAME\",\"timestamp\":$timestamp,\"signing_public_key\":\"$signing_public_key\",\"kyber_public_key\":\"$public_key\",\"proof\":\"$proof\"}") || fail "validator registration failed"
  VALIDATOR_ID=$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("validator_id", ""))'); [[ -n "$VALIDATOR_ID" ]] || fail "RPC did not return a validator ID"
  save_config; echo "IMPORTANT: back up $STATE_DIR/validator.key somewhere safe; losing it loses this validator identity and stake."; (( SERVICE )) && install_service; exec "$SCRIPT_DIR/run-validator.sh" run --name "$NAME"
}
status() { load_config; health=$(curl -fsS "$RPC_URL/rpc/health") || fail "RPC endpoint is unreachable: $RPC_URL"; echo "$health" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("state: " + ("active" if d.get("status")=="ok" else "inactive")); print("peer count: " + str(d.get("peers", 0))); print("last-proposed-block height: " + str(d.get("height", 0)))'; [[ -n "${VALIDATOR_ID:-}" ]] || fail "validator ID is not saved; run init first"; curl -fsS "$RPC_URL/rpc/validator/status/$VALIDATOR_ID" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("current stake: " + str(d.get("stake", 0)))'; }
case "$COMMAND" in init) init_validator;; doctor) doctor;; status) status;; run) load_config; doctor; export BLEEP_VALIDATOR_NAME="$NAME" BLEEP_STATE_DIR="$STATE_DIR" BLEEP_P2P_LISTEN_ADDR="0.0.0.0:$P2P_PORT" BLEEP_RPC_LISTEN_ADDR="0.0.0.0:$RPC_PORT" BLEEP_P2P_SEEDS="$SEED"; exec "$NODE_BIN";; *) usage; exit 2;; esac
