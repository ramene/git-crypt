#!/bin/bash
#
# E2E test harness for git-crypt-trustless
# Starts Anvil, deploys contracts, runs all commands, validates, cleans up.
#
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
ANVIL_PID=""
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TRUSTLESS_BIN="${REPO_ROOT}/git-crypt-trustless"
CONTRACTS_DIR="${REPO_ROOT}/contracts"
TEST_REPO=""

# Anvil default key 0
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
FROM_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
RPC_URL="http://127.0.0.1:8545"

cleanup() {
    echo -e "\n${BLUE}Cleaning up...${NC}"
    if [ -n "$ANVIL_PID" ]; then
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
    fi
    if [ -n "$TEST_REPO" ] && [ -d "$TEST_REPO" ]; then
        rm -rf "$TEST_REPO"
    fi
}
trap cleanup EXIT

check_test() {
    local name="$1"
    local exit_code="$2"
    local expected="${3:-0}"

    if [ "$exit_code" -eq "$expected" ]; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "  ${RED}FAIL${NC}: $name (exit=$exit_code, expected=$expected)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

check_output() {
    local name="$1"
    local output="$2"
    local pattern="$3"

    if echo "$output" | grep -q "$pattern"; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "  ${RED}FAIL${NC}: $name (pattern '$pattern' not found)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# ---------------------------------------------------------------------------
echo -e "${BLUE}=== git-crypt-trustless E2E Tests ===${NC}\n"

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"
for cmd in anvil forge cast git; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}Error: '$cmd' not found. Install Foundry.${NC}"
        exit 1
    fi
done

if [ ! -f "$TRUSTLESS_BIN" ]; then
    echo -e "${RED}Error: git-crypt-trustless binary not found at $TRUSTLESS_BIN${NC}"
    echo "Run: make -f Makefile.trustless"
    exit 1
fi

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}1. Starting Anvil...${NC}"
anvil --silent &
ANVIL_PID=$!
sleep 2

# Check Anvil is running
if ! kill -0 "$ANVIL_PID" 2>/dev/null; then
    echo -e "${RED}Anvil failed to start${NC}"
    exit 1
fi
echo -e "  ${GREEN}Anvil running (PID: $ANVIL_PID)${NC}"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}2. Installing Foundry dependencies...${NC}"
cd "$CONTRACTS_DIR"
if [ ! -d "lib/forge-std" ]; then
    forge install foundry-rs/forge-std --no-commit --no-git 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}3. Deploying contracts...${NC}"
DEPLOY_OUTPUT=$(GIT_CRYPT_TRUSTLESS_PRIVATE_KEY="$PRIVATE_KEY" \
    "$TRUSTLESS_BIN" deploy --rpc-url "$RPC_URL" --contracts-dir "$CONTRACTS_DIR" 2>&1) || true

REGISTRY_ADDR=$(echo "$DEPLOY_OUTPUT" | grep -i "Registry:" | head -1 | grep -oE '0x[0-9a-fA-F]{40}' || echo "")
AUDIT_ADDR=$(echo "$DEPLOY_OUTPUT" | grep -i "Audit:" | head -1 | grep -oE '0x[0-9a-fA-F]{40}' || echo "")

if [ -z "$REGISTRY_ADDR" ]; then
    echo -e "${YELLOW}  Deploying via deploy.sh fallback...${NC}"
    DEPLOY_OUTPUT=$(cd "$CONTRACTS_DIR" && RPC_URL="$RPC_URL" PRIVATE_KEY="$PRIVATE_KEY" bash deploy.sh 2>&1) || true
    REGISTRY_ADDR=$(echo "$DEPLOY_OUTPUT" | grep -oE '0x[0-9a-fA-F]{40}' | head -1 || echo "")
    AUDIT_ADDR=$(echo "$DEPLOY_OUTPUT" | grep -oE '0x[0-9a-fA-F]{40}' | tail -1 || echo "")
fi

if [ -z "$REGISTRY_ADDR" ]; then
    echo -e "${RED}  Failed to deploy contracts. Output:${NC}"
    echo "$DEPLOY_OUTPUT"
    exit 1
fi
echo -e "  ${GREEN}Registry: $REGISTRY_ADDR${NC}"
echo -e "  ${GREEN}Audit:    $AUDIT_ADDR${NC}"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}4. Creating test repository...${NC}"
TEST_REPO=$(mktemp -d)
cd "$TEST_REPO"
git init -q
git commit --allow-empty -m "init" -q

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}5. Running git-crypt-trustless init...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" init \
    --rpc-url "$RPC_URL" \
    --registry "$REGISTRY_ADDR" \
    --audit "$AUDIT_ADDR" \
    --chain-id 31337 \
    --from "$FROM_ADDRESS" 2>&1) || true
check_output "init sets config" "$OUTPUT" "initialized"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}6. Running config...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" config 2>&1) || true
check_output "config shows RPC" "$OUTPUT" "$RPC_URL"
check_output "config shows registry" "$OUTPUT" "$REGISTRY_ADDR"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}7. Issuing a license...${NC}"
export GIT_CRYPT_TRUSTLESS_PRIVATE_KEY="$PRIVATE_KEY"
OUTPUT=$("$TRUSTLESS_BIN" issue \
    --to "SHA256:test-fingerprint-abc123" \
    --scope "unlock,lock" \
    --expires "90d" 2>&1) || true
check_output "issue succeeds" "$OUTPUT" "issued"

# Extract license ID
LICENSE_ID=$(echo "$OUTPUT" | grep -oE 'ID: +[0-9a-f]{16}' | grep -oE '[0-9a-f]{16}' || echo "")
if [ -z "$LICENSE_ID" ]; then
    LICENSE_ID=$(echo "$OUTPUT" | grep -oE '"id": "[0-9a-f]{16}"' | grep -oE '[0-9a-f]{16}' || echo "")
fi

if [ -z "$LICENSE_ID" ]; then
    echo -e "  ${RED}Could not extract license ID from output${NC}"
    echo "$OUTPUT"
    LICENSE_ID="0000000000000000"  # Use dummy for remaining tests
fi
echo -e "  License ID: $LICENSE_ID"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}8. Verifying the license...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" verify "$LICENSE_ID" 2>&1)
EXIT_CODE=$?
check_test "verify returns 0 for active license" "$EXIT_CODE" 0
check_output "verify shows VALID" "$OUTPUT" "VALID"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}9. Listing licenses...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" list 2>&1)
EXIT_CODE=$?
check_test "list succeeds" "$EXIT_CODE" 0

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}10. Showing license details...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" show "$LICENSE_ID" 2>&1)
EXIT_CODE=$?
check_test "show succeeds" "$EXIT_CODE" 0
check_output "show includes status" "$OUTPUT" "active"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}11. Checking license...${NC}"
# Create a dummy license dir so check can find the ID
mkdir -p .git-crypt/licenses/"$LICENSE_ID"
cat > .git-crypt/licenses/"$LICENSE_ID"/license.txt <<EOF
id	$LICENSE_ID
licensee_fingerprint	SHA256:test-fingerprint-abc123
licensee_wallet
scope	unlock,lock
issued_at	2025-01-01T00:00:00Z
expires_at	2026-01-01T00:00:00Z
status	active
EOF
mkdir -p .git-crypt/licenses
echo "SHA256:test-fingerprint-abc123" > .git-crypt/licenses/issuer.txt

OUTPUT=$("$TRUSTLESS_BIN" check --operation unlock 2>&1)
EXIT_CODE=$?
check_test "check passes for valid license" "$EXIT_CODE" 0

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}12. Exporting license...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" export "$LICENSE_ID" /tmp/test_trustless_export.lic 2>&1)
EXIT_CODE=$?
check_test "export succeeds" "$EXIT_CODE" 0

if [ -f /tmp/test_trustless_export.lic ]; then
    check_output "export file has content" "$(cat /tmp/test_trustless_export.lic)" "content_hash"
    rm -f /tmp/test_trustless_export.lic
fi

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}13. Committing Merkle audit root...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" audit-root 2>&1)
EXIT_CODE=$?
check_test "audit-root succeeds" "$EXIT_CODE" 0
check_output "audit-root shows root" "$OUTPUT" "Root:"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}14. Generating Merkle proof...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" audit-prove --entry 0 2>&1)
EXIT_CODE=$?
check_test "audit-prove succeeds" "$EXIT_CODE" 0
check_output "audit-prove has siblings" "$OUTPUT" "siblings"

# Save proof to file for verification
echo "$OUTPUT" > /tmp/test_trustless_proof.json

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}15. Verifying Merkle proof (local)...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" audit-verify --proof /tmp/test_trustless_proof.json 2>&1)
EXIT_CODE=$?
check_test "audit-verify local succeeds" "$EXIT_CODE" 0
check_output "audit-verify shows VALID" "$OUTPUT" "VALID"
rm -f /tmp/test_trustless_proof.json

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}16. Revoking the license...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" revoke "$LICENSE_ID" 2>&1)
EXIT_CODE=$?
check_test "revoke succeeds" "$EXIT_CODE" 0
check_output "revoke confirms" "$OUTPUT" "revoked"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}17. Verifying after revoke...${NC}"
OUTPUT=$("$TRUSTLESS_BIN" verify "$LICENSE_ID" 2>&1)
EXIT_CODE=$?
check_test "verify returns 1 after revoke" "$EXIT_CODE" 1
check_output "verify shows INVALID" "$OUTPUT" "INVALID"

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}18. Server smoke test...${NC}"
"$TRUSTLESS_BIN" serve --port 8403 &
SERVER_PID=$!
sleep 1

HEALTH=$(curl -s http://127.0.0.1:8403/health 2>/dev/null || echo "")
check_output "server /health returns ok" "$HEALTH" "ok"

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
echo -e "\n${BLUE}=== Results ===${NC}"
TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo -e "  Total:  $TOTAL"
echo -e "  ${GREEN}Passed: $PASS_COUNT${NC}"
echo -e "  ${RED}Failed: $FAIL_COUNT${NC}"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
