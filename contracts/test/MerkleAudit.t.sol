// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/MerkleAudit.sol";

contract MerkleAuditTest is Test {
    MerkleAudit audit;
    address nonAuditor = address(0xBEEF);
    address newAuditor = address(0xCAFE);

    function setUp() public {
        audit = new MerkleAudit();
    }

    function test_commit_root() public {
        bytes32 root = keccak256("root");
        audit.commitRoot(root, 10);

        (bytes32 storedRoot, uint256 ts, uint256 leafCount) = audit.latestRoot();
        assertEq(storedRoot, root);
        assertEq(leafCount, 10);
        assertEq(ts, block.timestamp);
    }

    function test_verify_entry_simple() public {
        // Build a 2-leaf Merkle tree
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 root = keccak256(abi.encodePacked(leaf0, leaf1));

        audit.commitRoot(root, 2);

        // Verify leaf0 at index 0 with proof [leaf1]
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;
        assertTrue(audit.verifyEntry(leaf0, proof, 0, 0));

        // Verify leaf1 at index 1 with proof [leaf0]
        proof[0] = leaf0;
        assertTrue(audit.verifyEntry(leaf1, proof, 1, 0));
    }

    function test_verify_entry_invalid_proof() public {
        bytes32 leaf0 = keccak256("leaf0");
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 root = keccak256(abi.encodePacked(leaf0, leaf1));

        audit.commitRoot(root, 2);

        // Wrong proof element
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("wrong");
        assertFalse(audit.verifyEntry(leaf0, proof, 0, 0));
    }

    function test_latest_root() public {
        bytes32 root1 = keccak256("root1");
        bytes32 root2 = keccak256("root2");

        audit.commitRoot(root1, 5);
        vm.warp(block.timestamp + 100);
        audit.commitRoot(root2, 10);

        (bytes32 latest,,uint256 leafCount) = audit.latestRoot();
        assertEq(latest, root2);
        assertEq(leafCount, 10);
    }

    function test_root_count() public {
        assertEq(audit.rootCount(), 0);

        audit.commitRoot(keccak256("r1"), 1);
        assertEq(audit.rootCount(), 1);

        audit.commitRoot(keccak256("r2"), 2);
        assertEq(audit.rootCount(), 2);
    }

    function test_only_auditor() public {
        vm.prank(nonAuditor);
        vm.expectRevert("MerkleAudit: not an auditor");
        audit.commitRoot(keccak256("root"), 1);
    }

    function test_add_remove_auditor() public {
        audit.addAuditor(newAuditor);
        assertTrue(audit.auditors(newAuditor));

        audit.removeAuditor(newAuditor);
        assertFalse(audit.auditors(newAuditor));
    }

    function test_multiple_roots() public {
        bytes32 root1 = keccak256("root1");
        bytes32 root2 = keccak256("root2");
        bytes32 root3 = keccak256("root3");

        audit.commitRoot(root1, 5);
        audit.commitRoot(root2, 10);
        audit.commitRoot(root3, 15);

        assertEq(audit.rootCount(), 3);

        (bytes32 r0,, uint256 lc0,) = audit.roots(0);
        assertEq(r0, root1);
        assertEq(lc0, 5);

        (bytes32 r2,, uint256 lc2,) = audit.roots(2);
        assertEq(r2, root3);
        assertEq(lc2, 15);
    }
}
