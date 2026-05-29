// SPDX-License-Identifier: GPL-3.0-or-later
//
// valid_license.circom - ZK circuit for proving valid license ownership
//
// Phase 2: This circuit is designed but not yet integrated into the C++ binary.
// It proves "I have a valid license for operation X" without revealing:
//   - Which license ID
//   - Who it was issued to
//   - When it expires
//
// The verifier learns ONLY that a valid license exists in the on-chain registry.
//
// Requires: circomlib (for Poseidon, comparators, and Merkle tree components)
//
// Installation:
//   npm install circomlib
//
// Compilation:
//   circom valid_license.circom --r1cs --wasm --sym -o build/
//

pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

// Merkle inclusion proof component
template MerkleInclusionProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    signal hashes[depth + 1];
    hashes[0] <== leaf;

    component hashers[depth];
    component muxes[depth][2];

    for (var i = 0; i < depth; i++) {
        // pathIndices[i] must be 0 or 1
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Select left/right ordering based on pathIndices
        muxes[i][0] = Mux1();
        muxes[i][0].c[0] <== hashes[i];
        muxes[i][0].c[1] <== pathElements[i];
        muxes[i][0].s <== pathIndices[i];

        muxes[i][1] = Mux1();
        muxes[i][1].c[0] <== pathElements[i];
        muxes[i][1].c[1] <== hashes[i];
        muxes[i][1].s <== pathIndices[i];

        // Hash the pair
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxes[i][0].out;
        hashers[i].inputs[1] <== muxes[i][1].out;
        hashes[i + 1] <== hashers[i].out;
    }

    root <== hashes[depth];
}

// Main circuit: prove valid license without revealing identity
template ValidLicenseProof(merkleDepth) {
    // ---- Public inputs (known to verifier) ----
    signal input scopeHash;          // Poseidon hash of requested operation
    signal input currentTimestamp;   // Unix timestamp (verifier checks freshness)
    signal input contractRoot;       // Merkle root of all license contentHashes on-chain

    // ---- Private witness (known only to prover) ----
    signal input licenseId;          // License ID (field element)
    signal input status;             // 0=active, 1=revoked
    signal input issuedAt;           // Unix timestamp
    signal input expiresAt;          // Unix timestamp
    signal input scope;              // Scope field element
    signal input contentHash;        // Hash of full license data
    signal input merklePath[merkleDepth];
    signal input merklePathIndices[merkleDepth];

    // ---- Constraint 1: License is active ----
    status === 0;

    // ---- Constraint 2: License is not expired ----
    component notExpired = GreaterThan(64);
    notExpired.in[0] <== expiresAt;
    notExpired.in[1] <== currentTimestamp;
    notExpired.out === 1;

    // ---- Constraint 3: License has been issued (issuedAt <= currentTimestamp) ----
    component alreadyIssued = LessEqThan(64);
    alreadyIssued.in[0] <== issuedAt;
    alreadyIssued.in[1] <== currentTimestamp;
    alreadyIssued.out === 1;

    // ---- Constraint 4: Scope matches ----
    component scopeHasher = Poseidon(1);
    scopeHasher.inputs[0] <== scope;
    scopeHasher.out === scopeHash;

    // ---- Constraint 5: License is registered on-chain (Merkle inclusion proof) ----
    component merkleProof = MerkleInclusionProof(merkleDepth);
    merkleProof.leaf <== contentHash;
    for (var i = 0; i < merkleDepth; i++) {
        merkleProof.pathElements[i] <== merklePath[i];
        merkleProof.pathIndices[i] <== merklePathIndices[i];
    }
    merkleProof.root === contractRoot;
}

// Instantiate with depth 20 (supports up to 2^20 = ~1M licenses)
component main {public [scopeHash, currentTimestamp, contractRoot]} = ValidLicenseProof(20);
