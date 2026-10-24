#!/usr/bin/env bash
set -euo pipefail

CLI=${BLEEP_CLI:-"./target/release/bleep-cli"}
RPC=${BLEEP_RPC:-"http://127.0.0.1:8545"}
COUNT=${BLEEP_TPS_COUNT:-1000}
AMOUNT=${BLEEP_TPS_AMOUNT:-1}
MIN_PEERS=${BLEEP_TPS_MIN_PEERS:-0}
MIN_VALIDATORS=${BLEEP_TPS_MIN_VALIDATORS:-1}
SETTLE_TIMEOUT=${BLEEP_TPS_SETTLE_TIMEOUT:-120}
REQUIRE_ALL_PEERS=${BLEEP_TPS_REQUIRE_ALL_PEERS:-0}

if [[ ! "$COUNT" =~ ^[1-9][0-9]*$ ]]; then
  echo "BLEEP_TPS_COUNT must be a positive integer" >&2
  exit 2
fi
if [[ ! "$AMOUNT" =~ ^[1-9][0-9]*$ ]]; then
  echo "BLEEP_TPS_AMOUNT must be a positive integer" >&2
  exit 2
fi
if [[ ! "$MIN_PEERS" =~ ^[0-9]+$ ]]; then
  echo "BLEEP_TPS_MIN_PEERS must be a non-negative integer" >&2
  exit 2
fi
if [[ ! "$MIN_VALIDATORS" =~ ^[1-9][0-9]*$ ]]; then
  echo "BLEEP_TPS_MIN_VALIDATORS must be a positive integer" >&2
  exit 2
fi
if [[ ! "$SETTLE_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
  echo "BLEEP_TPS_SETTLE_TIMEOUT must be a positive integer" >&2
  exit 2
fi
if [[ "$REQUIRE_ALL_PEERS" != "0" && "$REQUIRE_ALL_PEERS" != "1" ]]; then
  echo "BLEEP_TPS_REQUIRE_ALL_PEERS must be 0 or 1" >&2
  exit 2
fi
if [[ ! -x "$CLI" ]]; then
  echo "CLI binary is not executable: $CLI" >&2
  exit 2
fi

json_field() {
  python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    value = value[key]
print(value)
' "$1" <<<"$2"
}

RPCS=("$RPC")
if [[ -n "${BLEEP_TPS_PEERS:-}" ]]; then
  IFS=',' read -r -a PEER_RPCS <<<"$BLEEP_TPS_PEERS"
  for endpoint in "${PEER_RPCS[@]}"; do
    endpoint=${endpoint//[[:space:]]/}
    [[ -n "$endpoint" ]] || continue
    already_listed=0
    for current in "${RPCS[@]}"; do
      if [[ "$current" == "$endpoint" ]]; then
        already_listed=1
        break
      fi
    done
    (( already_listed )) || RPCS+=("$endpoint")
  done
fi

declare -a BEFORE_TXS BEFORE_PEERS BEFORE_HEIGHTS BEFORE_BLOCKS VALIDATOR_COUNTS
TOTAL_ACTIVE_VALIDATORS=0
for index in "${!RPCS[@]}"; do
  endpoint=${RPCS[$index]}
  HEALTH=$(curl -fsS --connect-timeout 5 "$endpoint/rpc/health") || {
    echo "RPC health check failed: $endpoint" >&2
    exit 2
  }
  if [[ "$(json_field status "$HEALTH")" != "ok" ]]; then
    echo "RPC is not healthy: $endpoint ($HEALTH)" >&2
    exit 2
  fi
  BEFORE_PEERS[$index]=$(json_field peers "$HEALTH")
  if (( BEFORE_PEERS[index] < MIN_PEERS )); then
    echo "RPC $endpoint reports ${BEFORE_PEERS[index]} peers; minimum is $MIN_PEERS" >&2
    exit 2
  fi
  BEFORE_HEIGHTS[$index]=$(json_field height "$HEALTH")
  TELEMETRY=$(curl -fsS --connect-timeout 5 "$endpoint/rpc/telemetry") || {
    echo "RPC telemetry check failed: $endpoint" >&2
    exit 2
  }
  BEFORE_TXS[$index]=$(json_field transactions_processed "$TELEMETRY")
  BEFORE_BLOCKS[$index]=$(json_field blocks_produced "$TELEMETRY")
  VALIDATORS=$(curl -fsS --connect-timeout 5 "$endpoint/rpc/validator/list") || {
    echo "Validator status check failed: $endpoint" >&2
    exit 2
  }
  VALIDATOR_COUNTS[$index]=$(json_field active_count "$VALIDATORS")
  if (( VALIDATOR_COUNTS[index] < MIN_VALIDATORS )); then
    echo "RPC $endpoint reports ${VALIDATOR_COUNTS[index]} active validators; minimum is $MIN_VALIDATORS" >&2
    exit 2
  fi
  TOTAL_ACTIVE_VALIDATORS=$((TOTAL_ACTIVE_VALIDATORS + VALIDATOR_COUNTS[index]))
done

echo "Monitoring ${#RPCS[@]} nodes with $TOTAL_ACTIVE_VALIDATORS active validators reported in total."
if [[ -z "${BLEEP_JWT_TOKEN:-}" ]]; then
  RUN_ID=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
  AUTH_BODY=$(RUN_ID="$RUN_ID" python3 -c '
import json, os, secrets
print(json.dumps({
    "developer_handle": "bleep-bench-" + os.environ["RUN_ID"],
    "display_name": "BLEEP TPS benchmark",
    "password": secrets.token_urlsafe(32),
}))
')
  AUTH_RESPONSE=$(curl -fsS --connect-timeout 5 \
    -H 'Content-Type: application/json' \
    -X POST "$RPC/rpc/auth/register/dapp" \
    --data "$AUTH_BODY") || {
      echo "Could not obtain a server-issued RPC session from $RPC" >&2
      exit 2
    }
  BLEEP_JWT_TOKEN=$(python3 -c \
    'import json,sys; print(json.load(sys.stdin).get("token", ""))' \
    <<<"$AUTH_RESPONSE")
  if [[ -z "$BLEEP_JWT_TOKEN" ]]; then
    echo "RPC authentication registration returned no token: $AUTH_RESPONSE" >&2
    exit 2
  fi
  export BLEEP_JWT_TOKEN
fi

RUN_PREFIX=$(printf '%08x' "$(( $(date +%s) % 4294967296 ))")
ACCEPTED=0
FAILED=0
START=$(date +%s%N)

echo "Starting $COUNT signed transactions at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
for ((i = 1; i <= COUNT; i++)); do
  TO=$(printf 'BLEEP%s%032x' "$RUN_PREFIX" "$i")
  if OUTPUT=$("$CLI" tx send "$TO" "$AMOUNT" 2>&1); then
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

echo "Waiting up to ${SETTLE_TIMEOUT}s for processed transaction counters to settle..."
DEADLINE=$((SECONDS + SETTLE_TIMEOUT))
while (( SECONDS < DEADLINE )); do
  settled=1
  for index in "${!RPCS[@]}"; do
    if (( index > 0 )) && [[ "$REQUIRE_ALL_PEERS" != "1" ]]; then
      continue
    fi
    TELEMETRY=$(curl -fsS --connect-timeout 5 "${RPCS[$index]}/rpc/telemetry") || {
      settled=0
      break
    }
    PROCESSED=$(json_field transactions_processed "$TELEMETRY")
    DELTA=$((PROCESSED - BEFORE_TXS[index]))
    if (( DELTA < ACCEPTED )); then
      settled=0
      break
    fi
  done
  (( settled )) && break
  sleep 2
done

PRIMARY_MISMATCH=0
PEER_MISMATCHES=0
for index in "${!RPCS[@]}"; do
  endpoint=${RPCS[$index]}
  HEALTH_AFTER=$(curl -fsS --connect-timeout 5 "$endpoint/rpc/health") || {
    echo "RPC became unreachable during the benchmark: $endpoint" >&2
    if (( index == 0 )); then PRIMARY_MISMATCH=1; else PEER_MISMATCHES=1; fi
    continue
  }
  TELEMETRY_AFTER=$(curl -fsS --connect-timeout 5 "$endpoint/rpc/telemetry") || {
    echo "RPC telemetry became unreachable during the benchmark: $endpoint" >&2
    if (( index == 0 )); then PRIMARY_MISMATCH=1; else PEER_MISMATCHES=1; fi
    continue
  }
  PROCESSED_AFTER=$(json_field transactions_processed "$TELEMETRY_AFTER")
  PROCESSED_DELTA=$((PROCESSED_AFTER - BEFORE_TXS[index]))
  PEERS_AFTER=$(json_field peers "$HEALTH_AFTER")
  HEIGHT_AFTER=$(json_field height "$HEALTH_AFTER")
  BLOCKS_AFTER=$(json_field blocks_produced "$TELEMETRY_AFTER")
  BLOCKS_DELTA=$((BLOCKS_AFTER - BEFORE_BLOCKS[index]))
  VALIDATORS_AFTER=$(curl -fsS --connect-timeout 5 "$endpoint/rpc/validator/list") || {
    echo "Validator status became unreachable during the benchmark: $endpoint" >&2
    if (( index == 0 )); then PRIMARY_MISMATCH=1; else PEER_MISMATCHES=1; fi
    continue
  }
  ACTIVE_AFTER=$(json_field active_count "$VALIDATORS_AFTER")
  printf 'Node %s: peers=%s->%s validators=%s->%s height=%s->%s blocks=%s processed_delta=%s\n' \
    "$endpoint" "${BEFORE_PEERS[index]}" "$PEERS_AFTER" \
    "${VALIDATOR_COUNTS[index]}" "$ACTIVE_AFTER" "${BEFORE_HEIGHTS[index]}" \
    "$HEIGHT_AFTER" "$BLOCKS_DELTA" "$PROCESSED_DELTA"
  if (( ACTIVE_AFTER < MIN_VALIDATORS )); then
    echo "RPC $endpoint fell below the minimum active validator count." >&2
    if (( index == 0 )); then
      PRIMARY_MISMATCH=1
    else
      PEER_MISMATCHES=1
    fi
  fi
  if (( PROCESSED_DELTA != ACCEPTED )); then
    if (( index == 0 )); then
      PRIMARY_MISMATCH=1
    else
      PEER_MISMATCHES=1
    fi
  fi
done

echo "Accepted: $ACCEPTED/$COUNT"
echo "Failed: $FAILED"
echo "Submission duration: ${DURATION_MS}ms"
echo "Accepted submission TPS: $TPS"

if (( FAILED != 0 )); then
  exit 1
fi
if (( PRIMARY_MISMATCH != 0 )); then
  echo "The primary node did not process exactly the benchmark transaction delta." >&2
  exit 1
fi
if [[ "$REQUIRE_ALL_PEERS" == "1" ]] && (( PEER_MISMATCHES != 0 )); then
  echo "One or more monitored nodes did not process exactly the benchmark transaction delta." >&2
  exit 1
fi
