#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

NAME=${BLEEP_VALIDATOR_NAME:-validator}
P2P_PORT=${BLEEP_P2P_PORT:-7700}
RPC_PORT=${BLEEP_RPC_PORT:-8545}
STATE_DIR=${BLEEP_STATE_DIR:-}
STATE_DIR_SET=0
if [[ -n "$STATE_DIR" ]]; then
    STATE_DIR_SET=1
fi
SEEDS=${BLEEP_P2P_SEEDS:-}
NODE_BIN=${BLEEP_NODE_BIN:-"$ROOT_DIR/target/release/bleep"}

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Run a BLEEP validator and connect it to existing BLEEP peers.

Options:
  --name NAME          Validator name (default: $NAME)
  --p2p-port PORT      P2P listen port (default: $P2P_PORT)
  --rpc-port PORT      RPC listen port (default: $RPC_PORT)
  --state-dir DIR      Persistent state directory
  --seeds ADDRS        Comma-separated peers, for example 10.0.0.2:7700,10.0.0.3:7700
  --binary PATH        Path to the bleep binary
  --build              Build the release node before starting
  -h, --help           Show this help

Examples:
  $(basename "$0") --seeds 127.0.0.1:7701
  $(basename "$0") --p2p-port 7702 --rpc-port 8547 --seeds seed.example:7700
EOF
}

is_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

BUILD=0
while (($# > 0)); do
    case "$1" in
        --name)
            NAME=${2:?Missing value for --name}
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
        --state-dir)
            STATE_DIR=${2:?Missing value for --state-dir}
            STATE_DIR_SET=1
            shift 2
            ;;
        --seeds)
            SEEDS=${2:?Missing value for --seeds}
            shift 2
            ;;
        --binary)
            NODE_BIN=${2:?Missing value for --binary}
            shift 2
            ;;
        --build)
            BUILD=1
            shift
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

if ! is_port "$P2P_PORT" || ! is_port "$RPC_PORT"; then
    echo "P2P and RPC ports must be integers from 1 to 65535." >&2
    exit 2
fi

if [[ "$P2P_PORT" == "$RPC_PORT" ]]; then
    echo "P2P and RPC ports must be different." >&2
    exit 2
fi

if ((STATE_DIR_SET == 0)); then
    STATE_DIR="$HOME/.bleep/validators/$NAME/state"
fi

if ((BUILD)); then
    cargo build --release --bin bleep
fi

if [[ ! -x "$NODE_BIN" ]]; then
    echo "Node binary not found or not executable: $NODE_BIN" >&2
    echo "Build it with: cargo build --release --bin bleep" >&2
    exit 1
fi

mkdir -p "$STATE_DIR"

export BLEEP_VALIDATOR_NAME="$NAME"
export BLEEP_STATE_DIR="$STATE_DIR"
export BLEEP_P2P_LISTEN_ADDR="0.0.0.0:$P2P_PORT"
export BLEEP_RPC_LISTEN_ADDR="0.0.0.0:$RPC_PORT"
if [[ -n "$SEEDS" ]]; then
    export BLEEP_P2P_SEEDS="$SEEDS"
else
    unset BLEEP_P2P_SEEDS
fi

echo "Starting validator: $NAME"
echo "  P2P: 0.0.0.0:$P2P_PORT"
echo "  RPC: http://127.0.0.1:$RPC_PORT"
echo "  State: $STATE_DIR"
if [[ -n "$SEEDS" ]]; then
    echo "  Seeds: $SEEDS"
else
    echo "  Seeds: none (start a seed validator first)"
fi
echo "  Health: http://127.0.0.1:$RPC_PORT/rpc/health"

exec "$NODE_BIN"