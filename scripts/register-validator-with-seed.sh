#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

NAME=${BLEEP_VALIDATOR_NAME:-validator-1}
P2P_PORT=${BLEEP_P2P_PORT:-7701}
RPC_PORT=${BLEEP_RPC_PORT:-8546}
RPC_URL=${BLEEP_RPC_URL:-http://127.0.0.1:8545}
SEED=${BLEEP_P2P_SEEDS:-}
STAKE=${BLEEP_VALIDATOR_STAKE:-1000000}
LABEL=${BLEEP_VALIDATOR_LABEL:-${NAME}}
STATE_DIR=${BLEEP_STATE_DIR:-$HOME/.bleep/validators/$NAME/state}
NODE_BIN=${BLEEP_NODE_BIN:-"$ROOT_DIR/target/release/bleep"}

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Register a validator against an existing BLEEP node and then start a validator
node that peers to a seed/initial node.

Options:
  --name NAME           Validator name (default: $NAME)
  --seed HOST:PORT      Required seed peer to connect to, e.g. 127.0.0.1:7700
  --rpc-url URL         Existing node RPC URL (default: $RPC_URL)
  --p2p-port PORT      Local validator P2P port (default: $P2P_PORT)
  --rpc-port PORT      Local validator RPC port (default: $RPC_PORT)
  --amount AMOUNT      Validator stake to register (default: $STAKE)
  --label LABEL        Label to register under the validator registry (default: $LABEL)
  --state-dir DIR      Persistent state dir (default: $STATE_DIR)
  --binary PATH         Node binary path (default: $NODE_BIN)
  -h, --help            Show this help

Examples:
  $(basename "$0") --seed 127.0.0.1:7700
  $(basename "$0") --seed seed.example.com:7700 --rpc-url http://seed.example.com:8545 --name validator-2 --p2p-port 7702 --rpc-port 8547
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Required command not found: $1" >&2
        exit 1
    }
}

is_valid_seed() {
    [[ "$1" =~ ^[^:]+:[0-9]+$ ]]
}

while (($# > 0)); do
    case "$1" in
        --name)
            NAME=${2:?Missing value for --name}
            shift 2
            ;;
        --seed)
            SEED=${2:?Missing value for --seed}
            shift 2
            ;;
        --rpc-url)
            RPC_URL=${2:?Missing value for --rpc-url}
            shift 2
            ;;
        --p2p-port)
            P2P_PORT=${2:?Missing value for --p2p-port}
            shift 2
            ;;
        --rpc-port)
            RPC_PORT=${2:?Missing value for --rpc-port}
            shift 2
            ;;
        --amount)
            STAKE=${2:?Missing value for --amount}
            shift 2
            ;;
        --label)
            LABEL=${2:?Missing value for --label}
            shift 2
            ;;
        --state-dir)
            STATE_DIR=${2:?Missing value for --state-dir}
            shift 2
            ;;
        --binary)
            NODE_BIN=${2:?Missing value for --binary}
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$SEED" ]]; then
    echo "A seed peer is required. Example: --seed 127.0.0.1:7700" >&2
    usage >&2
    exit 2
fi

if ! is_valid_seed "$SEED"; then
    echo "Seed must be in host:port format, got: $SEED" >&2
    exit 2
fi

require_cmd curl

if [[ ! -x "$NODE_BIN" ]]; then
    echo "Node binary not found or not executable: $NODE_BIN" >&2
    echo "Build it with: cargo build --release --bin bleep" >&2
    exit 1
fi

echo "Checking existing node health at $RPC_URL..."
curl -fsS "$RPC_URL/rpc/health" >/dev/null || {
    echo "Unable to reach the existing BLEEP node at $RPC_URL." >&2
    echo "Start the initial/seed node first, then rerun this script." >&2
    exit 1
}

TIMESTAMP=$(date +%s)
PAYLOAD=$(printf '{"tx_type":"stake","amount":%s,"label":"%s","timestamp":%s}' "$STAKE" "$LABEL" "$TIMESTAMP")

echo "Registering validator: name=$NAME label=$LABEL amount=$STAKE on $RPC_URL"
REGISTER_RESPONSE=$(curl -fsS -X POST "$RPC_URL/rpc/validator/stake" \
    -H 'Content-Type: application/json' \
    --data "$PAYLOAD") || {
    echo "Validator registration failed against $RPC_URL" >&2
    exit 1
}

echo "$REGISTER_RESPONSE"

echo "Starting validator node: $NAME"
echo "  P2P listen: 0.0.0.0:$P2P_PORT"
echo "  RPC listen: http://127.0.0.1:$RPC_PORT"
echo "  Seed: $SEED"
echo "  State: $STATE_DIR"

exec "$SCRIPT_DIR/run-validator.sh" \
    --name "$NAME" \
    --p2p-port "$P2P_PORT" \
    --rpc-port "$RPC_PORT" \
    --state-dir "$STATE_DIR" \
    --binary "$NODE_BIN" \
    --seeds "$SEED"
