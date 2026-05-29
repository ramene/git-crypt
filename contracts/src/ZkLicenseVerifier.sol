// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

/// @title ZkLicenseVerifier
/// @notice Wraps LicenseRegistry + Groth16Verifier for ZK-based verification
/// @dev Phase 2: full implementation pending trusted setup
contract ZkLicenseVerifier {
    address public registry;
    address public verifier;

    constructor(address _registry, address _verifier) {
        registry = _registry;
        verifier = _verifier;
    }
}
