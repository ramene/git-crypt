#!/bin/bash
#
# ZK trusted setup script for git-crypt-trustless
#
# Phase 2: Run this script after compiling the circom circuit.
# Performs Powers of Tau ceremony and circuit-specific Groth16 setup.
#
# Prerequisites:
#   - snarkjs: npm install -g snarkjs
#   - circom: https://docs.circom.io/getting-started/installation/
#   - node_modules/circomlib: npm install circomlib
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

echo "=== git-crypt-trustless ZK Trusted Setup ==="
echo ""

# Check prerequisites
for cmd in snarkjs circom node; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' not found."
        echo "Install: npm install -g snarkjs circom"
        exit 1
    fi
done

mkdir -p "$BUILD_DIR"

# Step 1: Compile the circuit
echo "Step 1: Compiling circuit..."
circom "${SCRIPT_DIR}/valid_license.circom" \
    --r1cs \
    --wasm \
    --sym \
    -o "$BUILD_DIR"
echo "  Circuit compiled: $(wc -c < "${BUILD_DIR}/valid_license.r1cs") bytes"

# Step 2: Powers of Tau (one-time ceremony)
echo ""
echo "Step 2: Powers of Tau ceremony..."
if [ ! -f "${BUILD_DIR}/pot14_final.ptau" ]; then
    snarkjs powersoftau new bn128 14 "${BUILD_DIR}/pot14_0000.ptau" -v
    echo "random entropy for contribution" | \
        snarkjs powersoftau contribute "${BUILD_DIR}/pot14_0000.ptau" "${BUILD_DIR}/pot14_0001.ptau" \
            --name="git-crypt-trustless Phase 1" -v
    snarkjs powersoftau prepare phase2 "${BUILD_DIR}/pot14_0001.ptau" "${BUILD_DIR}/pot14_final.ptau" -v
    rm -f "${BUILD_DIR}/pot14_0000.ptau" "${BUILD_DIR}/pot14_0001.ptau"
    echo "  Powers of Tau complete."
else
    echo "  Using existing pot14_final.ptau"
fi

# Step 3: Circuit-specific setup (Groth16)
echo ""
echo "Step 3: Groth16 setup..."
snarkjs groth16 setup \
    "${BUILD_DIR}/valid_license.r1cs" \
    "${BUILD_DIR}/pot14_final.ptau" \
    "${BUILD_DIR}/vl_0000.zkey"

echo "random entropy for zkey contribution" | \
    snarkjs zkey contribute \
        "${BUILD_DIR}/vl_0000.zkey" \
        "${BUILD_DIR}/vl_final.zkey" \
        --name="git-crypt-trustless zkey contribution" -v
rm -f "${BUILD_DIR}/vl_0000.zkey"
echo "  Groth16 setup complete."

# Step 4: Export Solidity verifier
echo ""
echo "Step 4: Exporting Solidity verifier..."
snarkjs zkey export solidityverifier \
    "${BUILD_DIR}/vl_final.zkey" \
    "${SCRIPT_DIR}/../contracts/src/Groth16Verifier.sol"
echo "  Exported to contracts/src/Groth16Verifier.sol"

# Step 5: Export verification key
echo ""
echo "Step 5: Exporting verification key..."
snarkjs zkey export verificationkey \
    "${BUILD_DIR}/vl_final.zkey" \
    "${BUILD_DIR}/verification_key.json"
echo "  Exported to build/verification_key.json"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Artifacts in ${BUILD_DIR}/:"
echo "  valid_license.r1cs          - Circuit constraints"
echo "  valid_license_js/           - WASM prover"
echo "  pot14_final.ptau            - Powers of Tau"
echo "  vl_final.zkey               - Proving key"
echo "  verification_key.json       - Verification key"
echo ""
echo "To generate a proof:"
echo "  snarkjs wtns calculate build/valid_license_js/valid_license.wasm input.json witness.wtns"
echo "  snarkjs groth16 prove build/vl_final.zkey witness.wtns proof.json public.json"
echo ""
echo "To verify a proof:"
echo "  snarkjs groth16 verify build/verification_key.json public.json proof.json"
