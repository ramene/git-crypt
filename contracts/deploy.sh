#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${1:-http://127.0.0.1:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

echo "Deploying contracts to $RPC_URL ..."

OUTPUT=$(forge script script/Deploy.s.sol \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast 2>&1)

echo "$OUTPUT"

REGISTRY=$(echo "$OUTPUT" | grep "LicenseRegistry deployed at:" | awk '{print $NF}')
AUDIT=$(echo "$OUTPUT" | grep "MerkleAudit deployed at:" | awk '{print $NF}')

echo ""
echo "=== Deployed Contracts ==="
echo "LicenseRegistry: $REGISTRY"
echo "MerkleAudit:     $AUDIT"
