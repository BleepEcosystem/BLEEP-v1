#!/usr/bin/env bash
set -euo pipefail

CLI=${BLEEP_CLI:-"./target/release/bleep-cli"}
RPC=${BLEEP_RPC:-"http://127.0.0.1:8545"}
COUNT=${BLEEP_TPS_COUNT:-1000}
AMOUNT=${BLEEP_TPS_AMOUNT:-1}

if [[ ! "$COUNT" =~ ^[1-9][0-9]*$ ]]; then
  echo "BLEEP_TPS_COUNT must be a positive integer" >&2
  exit 2
fi
if [[ ! -x "$CLI" ]]; then
  echo "CLI binary is not executable: $CLI" >&2
  exit 2
fi

HEALTH_BEFORE=$(curl -fsS "$RPC/rpc/health")
PROCESSED_BEFORE=$(curl -fsS "$RPC/rpc/telemetry" | python3 -c 'import json,sys; print(json.load(sys.stdin)["transactions_processed"])')
RUN_PREFIX=$(printf '%08x' "$(( $(date +%s) % 4294967296 ))")
ACCEPTED=0
FAILED=0
START=$(date +%s%N)

echo "Starting $COUNT signed transactions at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
for ((i = 1; i <= COUNT; i++)); do
  TO=$(printf 'BLEEP%s%032x' "$RUN_PREFIX" "$i")
  if OUTPUT=$("$CLI" tx send "$TO" "$AMOUNT" 2>&1) && grep -Eq '"status"[[:space:]]*:[[:space:]]*"accepted"' <<<"$OUTPUT"; then
    ACCEPTED=$((ACCEPTED + 1))
  else
    FAILED=$((FAILED + 1))
    printf 'transaction %s failed: %s\n' "$i" "$OUTPUT" >&2
  fi
  if (( i % 100 == 0 )); then
    printf 'completed=%s accepted=%s failed=%s\n' "$i" "$ACCEPTED" "$FAILED"
  fi
done

END=$(date +%s%N)
DURATION_NS=$((END - START))
DURATION_MS=$((DURATION_NS / 1000000))
TPS=$(awk -v accepted="$ACCEPTED" -v duration_ns="$DURATION_NS" 'BEGIN { printf "%.3f", accepted * 1000000000 / duration_ns }')
PROCESSED_AFTER=$(curl -fsS "$RPC/rpc/telemetry" | python3 -c 'import json,sys; print(json.load(sys.stdin)["transactions_processed"])')
HEALTH_AFTER=$(curl -fsS "$RPC/rpc/health")

echo "Accepted: $ACCEPTED/$COUNT"
echo "Failed: $FAILED"
echo "Duration: ${DURATION_MS}ms"
echo "Accepted submission TPS: $TPS"
echo "Processed before/after: $PROCESSED_BEFORE/$PROCESSED_AFTER"
echo "Health before: $HEALTH_BEFORE"
echo "Health after: $HEALTH_AFTER"

(( FAILED == 0 ))