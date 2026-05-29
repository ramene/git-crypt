// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

/// @title MerkleAudit
/// @notice On-chain Merkle root commitment for cryptographic audit trails
contract MerkleAudit {
    struct RootCommitment {
        bytes32 root;
        uint256 timestamp;
        uint256 leafCount;
        address committer;
    }

    RootCommitment[] public roots;
    mapping(address => bool) public auditors;
    address public owner;

    event RootCommitted(bytes32 indexed root, uint256 leafCount, address indexed committer);
    event AuditorAdded(address indexed auditor);
    event AuditorRemoved(address indexed auditor);

    modifier onlyOwner() {
        require(msg.sender == owner, "MerkleAudit: not the owner");
        _;
    }

    modifier onlyAuditor() {
        require(auditors[msg.sender], "MerkleAudit: not an auditor");
        _;
    }

    constructor() {
        owner = msg.sender;
        auditors[msg.sender] = true;
        emit AuditorAdded(msg.sender);
    }

    /// @notice Commit a new Merkle root
    /// @param root The Merkle root hash
    /// @param leafCount Number of leaves in the tree
    function commitRoot(bytes32 root, uint256 leafCount) external onlyAuditor {
        roots.push(RootCommitment({
            root: root,
            timestamp: block.timestamp,
            leafCount: leafCount,
            committer: msg.sender
        }));
        emit RootCommitted(root, leafCount, msg.sender);
    }

    /// @notice Verify a leaf exists in a committed Merkle tree
    /// @param leaf The leaf hash to verify
    /// @param proof Array of sibling hashes forming the proof
    /// @param index The leaf's index in the tree
    /// @param rootIndex Which committed root to verify against
    /// @return Whether the proof is valid
    function verifyEntry(
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 index,
        uint256 rootIndex
    ) external view returns (bool) {
        require(rootIndex < roots.length, "MerkleAudit: invalid root index");

        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
            } else {
                computedHash = keccak256(abi.encodePacked(proof[i], computedHash));
            }
            index = index / 2;
        }
        return computedHash == roots[rootIndex].root;
    }

    /// @notice Get the most recent root commitment
    /// @return root The Merkle root
    /// @return timestamp When it was committed
    /// @return leafCount Number of leaves
    function latestRoot() external view returns (bytes32 root, uint256 timestamp, uint256 leafCount) {
        require(roots.length > 0, "MerkleAudit: no roots committed");
        RootCommitment storage latest = roots[roots.length - 1];
        return (latest.root, latest.timestamp, latest.leafCount);
    }

    /// @notice Get total number of committed roots
    /// @return The count of root commitments
    function rootCount() external view returns (uint256) {
        return roots.length;
    }

    /// @notice Add a new auditor
    /// @param auditor Address to grant auditor role
    function addAuditor(address auditor) external onlyOwner {
        auditors[auditor] = true;
        emit AuditorAdded(auditor);
    }

    /// @notice Remove an auditor
    /// @param auditor Address to revoke auditor role
    function removeAuditor(address auditor) external onlyOwner {
        auditors[auditor] = false;
        emit AuditorRemoved(auditor);
    }
}
