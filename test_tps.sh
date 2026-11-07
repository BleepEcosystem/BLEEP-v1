#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export BLEEP_RPC=${BLEEP_RPC:-"http://127.0.0.1:8545"}
export BLEEP_TPS_SENDERS=${BLEEP_TPS_SENDERS:-}
export BLEEP_ADMIN_PUBLIC_KEY_HEX=${BLEEP_ADMIN_PUBLIC_KEY_HEX:-}
export BLEEP_ADMIN_SECRET_KEY_FILE=${BLEEP_ADMIN_SECRET_KEY_FILE:-}

if [[ -z "$BLEEP_TPS_SENDERS" || ! -r "$BLEEP_TPS_SENDERS" ]]; then
  echo "Set BLEEP_TPS_SENDERS to a readable JSON file containing funded sender keys." >&2
  exit 2
fi
if [[ -z "$BLEEP_ADMIN_PUBLIC_KEY_HEX" || -z "$BLEEP_ADMIN_SECRET_KEY_FILE" ]]; then
  echo "Set BLEEP_ADMIN_PUBLIC_KEY_HEX and BLEEP_ADMIN_SECRET_KEY_FILE for admin challenge login." >&2
  exit 2
fi
if [[ ! -r "$BLEEP_ADMIN_SECRET_KEY_FILE" ]]; then
  echo "Admin secret key file is not readable: $BLEEP_ADMIN_SECRET_KEY_FILE" >&2
  exit 2
fi

cd "$ROOT"
cargo build --release --locked --bin bleep-loadgen

if [[ -n "${BLEEP_TPS_PROFILE_PID:-}" ]]; then
  if ! command -v perf >/dev/null 2>&1; then
    echo "BLEEP_TPS_PROFILE_PID was set but perf is unavailable." >&2
    exit 2
  fi
  PROFILE_SECS=${BLEEP_TPS_PROFILE_SECS:-1800}
  if [[ ! "$PROFILE_SECS" =~ ^[1-9][0-9]*$ ]]; then
    echo "BLEEP_TPS_PROFILE_SECS must be a positive integer." >&2
    exit 2
  fi
  PROFILE=${BLEEP_TPS_PROFILE_OUTPUT:-"$ROOT/tps-profile.data"}
  perf record -F 99 -g -p "$BLEEP_TPS_PROFILE_PID" -o "$PROFILE" -- sleep "$PROFILE_SECS" &
  PROFILE_PROCESS=$!
  cleanup_profile() {
    kill -INT "$PROFILE_PROCESS" 2>/dev/null || true
    wait "$PROFILE_PROCESS" 2>/dev/null || true
    if [[ -s "$PROFILE" ]]; then
      perf report --stdio -i "$PROFILE" \
        > "${BLEEP_TPS_PROFILE_REPORT:-"$ROOT/tps-profile.txt"}" || true
    fi
  }
  trap cleanup_profile EXIT INT TERM
fi

"$ROOT/target/release/bleep-loadgen"
