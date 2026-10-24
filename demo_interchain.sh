#!/usr/bin/env bash
set -euo pipefail

# BLEEP Interchain Transaction Demo
# This script demonstrates how to perform an interchain transaction between BLEEP and Ethereum

echo "🚀 BLEEP Interchain Transaction Demo"
echo "===================================="

# Check if node is running
echo "📡 Checking BLEEP node status..."
if ! curl -s --connect-timeout 5 http://127.0.0.1:8545/rpc/health >/dev/null; then
    echo "❌ BLEEP node not running. Please start it first:"
    echo "   export SEPOLIA_BLEEP_FULFILL_ADDR=<deployed-sepolia-contract>"
    echo "   ./target/release/bleep"
    exit 1
fi
echo "✅ BLEEP node is running"

# Require a real Sepolia contract address
if [[ -z "${SEPOLIA_BLEEP_FULFILL_ADDR:-}" ]]; then
    echo "❌ SEPOLIA_BLEEP_FULFILL_ADDR must be set to the deployed Sepolia BleepFulfill contract address."
    echo "   export SEPOLIA_BLEEP_FULFILL_ADDR=0x..."
    exit 1
fi
# Normalize address if needed
SEPOLIA_BLEEP_FULFILL_ADDR=$(printf "%s" "$SEPOLIA_BLEEP_FULFILL_ADDR" | tr '[:upper:]' '[:lower:]')
echo "✅ Sepolia contract address: $SEPOLIA_BLEEP_FULFILL_ADDR"

# Generate JWT auth token for protected RPC endpoints
if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "❌ Python is required to generate an RPC auth token."
    exit 1
fi
PYTHON_BIN=python3
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN=python
fi

if [[ -z "${BLEEP_JWT_SECRET:-}" ]]; then
    echo "❌ BLEEP_JWT_SECRET must be set to the node's base64-encoded JWT secret."
    exit 1
fi

JWT_TOKEN=$("$PYTHON_BIN" - <<'PY'
import base64, binascii, json, hmac, hashlib, os, secrets, time
secret_b64 = os.environ["BLEEP_JWT_SECRET"]
try:
    secret = base64.b64decode(secret_b64, validate=True)
except binascii.Error as exc:
    raise SystemExit(f"BLEEP_JWT_SECRET is not valid base64: {exc}")
if len(secret) < 32:
    raise SystemExit("BLEEP_JWT_SECRET must decode to at least 32 bytes")
now = int(time.time())
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "demo-interchain",
    "jti": secrets.token_hex(16),
    "iat": now,
    "exp": now + 3600,
    "roles": ["DappDeveloper"],
    "nonce": secrets.token_hex(16),
}
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
segments = [
    b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
    b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
]
signing_input = ".".join(segments).encode("ascii")
signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
segments.append(b64url(signature))
print(".".join(segments))
PY
)

if [[ -z "$JWT_TOKEN" ]]; then
    echo "❌ Failed to generate JWT token."
    exit 1
fi
echo "✅ RPC auth token generated"

echo ""
echo "📝 Step 1: Submit an interchain intent"
echo "Transferring 1 BLEEP to Ethereum address 0x742d35Cc6634C0532925a3b844Bc454e4438f44e"

INTENT_RESPONSE=$(curl -s -X POST http://127.0.0.1:8545/rpc/connect/intent \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "source_chain": "BLEEP",
    "dest_chain": "Ethereum",
    "source_amount": 1000000000000000000,
    "min_dest_amount": 900000000000000000,
    "sender_address": "BLEEP1test1234567890abcdef1234567890abcdef12345678",
    "recipient_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "max_solver_reward_bps": 50,
    "slippage_tolerance_bps": 100
  }')

echo "Intent submission response:"
echo "$INTENT_RESPONSE" | jq .

INTENT_ID=$(echo "$INTENT_RESPONSE" | jq -r '.intent_id')
if [[ "$INTENT_ID" == "null" || -z "$INTENT_ID" ]]; then
    echo "❌ Failed to submit intent"
    exit 1
fi

echo ""
echo "✅ Intent submitted successfully!"
echo "Intent ID: $INTENT_ID"

echo ""
echo "📡 Step 2: Verify intent is visible in the running node"
PENDING_VISIBLE=false
for i in $(seq 1 10); do
    PENDING_RESPONSE=$(curl -s -H "Authorization: Bearer $JWT_TOKEN" http://127.0.0.1:8545/rpc/connect/intents/pending)
    echo "Pending intents (attempt $i/10):"
    echo "$PENDING_RESPONSE" | jq .
    if echo "$PENDING_RESPONSE" | grep -q "$INTENT_ID"; then
        echo "✅ Intent appears in the node's pending intents"
        PENDING_VISIBLE=true
        break
    fi
    echo "⏳ Intent not visible yet, retrying..."
    sleep 1
done
if [[ "$PENDING_VISIBLE" != "true" ]]; then
    echo "❌ Intent did not appear in the running node's pending intents after waiting."
    exit 1
fi

echo ""
echo "📊 Step 3: Check intent status"
sleep 2
STATUS_RESPONSE=$(curl -s -H "Authorization: Bearer $JWT_TOKEN" http://127.0.0.1:8545/rpc/connect/intent/$INTENT_ID)
echo "Intent status:"
echo "$STATUS_RESPONSE" | jq .

echo ""
echo "🔗 Step 4: Build Sepolia relay transaction"
RELAY_RESPONSE=$(curl -s -H "Authorization: Bearer $JWT_TOKEN" http://127.0.0.1:8545/rpc/connect/intent/$INTENT_ID/relay_tx)
echo "Relay transaction:"
echo "$RELAY_RESPONSE" | jq .

echo ""
echo "🎯 Step 4: Simulate the relay (for demonstration)"
echo "In a real scenario, you would:"
echo "1. Submit the relay transaction to Ethereum Sepolia"
echo "2. Wait for confirmation"
echo "3. The BleepFulfill contract would receive the ETH"
echo "4. The recipient would get their funds"

echo ""
echo "📋 Summary:"
echo "- Intent ID: $INTENT_ID"
echo "- Source: 1 BLEEP on BLEEP chain"
echo "- Destination: ~0.9 ETH on Ethereum Sepolia"
echo "- Contract: $SEPOLIA_BLEEP_FULFILL_ADDR"
echo "- Status: Ready for relay execution"

echo ""
echo "✨ Interchain transaction demonstration complete!"