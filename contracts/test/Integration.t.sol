// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/LicenseRegistry.sol";
import "../src/MerkleAudit.sol";

contract IntegrationTest is Test {
    LicenseRegistry registry;
    MerkleAudit audit;

    bytes16 constant LIC_ID = bytes16(uint128(0x1234567890abcdef1234567890abcdef));
    bytes32 constant LICENSEE_HASH = keccak256("licensee-fp");
    address constant LICENSEE_WALLET = address(0xA11CE);
    bytes32 constant SCOPE_HASH = keccak256("repo:org/project");
    uint64 constant ISSUED_AT = 1700000000;
    uint64 constant EXPIRES_AT = 1800000000;
    bytes32 constant CONTENT_HASH = keccak256("full-license-data");

    function setUp() public {
        registry = new LicenseRegistry();
        audit = new MerkleAudit();
    }

    function test_full_lifecycle() public {
        // 1. Issue a license
        registry.issue(LIC_ID, LICENSEE_HASH, LICENSEE_WALLET, SCOPE_HASH, ISSUED_AT, EXPIRES_AT, CONTENT_HASH);

        // 2. Verify it's active
        vm.warp(ISSUED_AT + 1);
        (bool valid, uint8 status,) = registry.verify(LIC_ID);
        assertTrue(valid);
        assertEq(status, 0);

        // 3. Commit a Merkle root (simulating C++ audit trail)
        bytes32 auditLeaf = keccak256(abi.encodePacked(LIC_ID, CONTENT_HASH, "active"));
        bytes32 otherLeaf = keccak256("other-entry");
        bytes32 merkleRoot = keccak256(abi.encodePacked(auditLeaf, otherLeaf));
        audit.commitRoot(merkleRoot, 2);

        // Verify the audit entry
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = otherLeaf;
        assertTrue(audit.verifyEntry(auditLeaf, proof, 0, 0));

        // 4. Revoke the license
        registry.revoke(LIC_ID);

        // 5. Verify it's now revoked
        (bool validAfter, uint8 statusAfter,) = registry.verify(LIC_ID);
        assertFalse(validAfter);
        assertEq(statusAfter, 1);

        // 6. Commit updated Merkle root reflecting revocation
        bytes32 revokedLeaf = keccak256(abi.encodePacked(LIC_ID, CONTENT_HASH, "revoked"));
        bytes32 updatedRoot = keccak256(abi.encodePacked(revokedLeaf, otherLeaf));
        audit.commitRoot(updatedRoot, 2);

        // Verify updated audit entry
        proof[0] = otherLeaf;
        assertTrue(audit.verifyEntry(revokedLeaf, proof, 0, 1));
        assertEq(audit.rootCount(), 2);
    }
}
