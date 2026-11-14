#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
COUNT=${1:-${BLEEP_TPS_SENDER_COUNT:-500}}
OUTPUT_DIR=${2:-${BLEEP_TPS_PREPARE_DIR:-"$HOME/.bleep/tps"}}
BALANCE_MICRO=${3:-${BLEEP_TPS_FUND_MICRO:-1000000000}}
CHAIN_ID=${4:-${BLEEP_CHAIN_ID:-BLEEP-PreTestnet-001}}

if [[ ! "$COUNT" =~ ^[1-9][0-9]*$ ]]; then
  echo "sender count must be a positive integer" >&2
  exit 2
fi
if [[ ! "$BALANCE_MICRO" =~ ^[1-9][0-9]*$ ]]; then
  echo "balance in microBLEEP must be a positive integer" >&2
  exit 2
fi
if [[ -z "$CHAIN_ID" ]]; then
  echo "chain ID must not be empty" >&2
  exit 2
fi

(umask 077; mkdir -p "$OUTPUT_DIR")
cd "$ROOT"
cargo run --release --locked --bin bleep-tps-prepare -- \
  "$COUNT" \
  "$OUTPUT_DIR/senders.json" \
  "$OUTPUT_DIR/prefund.json" \
  "$BALANCE_MICRO" \
  "$CHAIN_ID"
