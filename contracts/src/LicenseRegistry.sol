// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

/// @title LicenseRegistry
/// @notice On-chain source of truth for trustless git-crypt licenses
contract LicenseRegistry {
    struct OnChainLicense {
        bytes16 id;
        bytes32 licenseeHash;
        address licenseeWallet;
        bytes32 scopeHash;
        uint64 issuedAt;
        uint64 expiresAt;
        uint8 status;
        bytes32 contentHash;
    }

    mapping(bytes16 => OnChainLicense) public licenses;
    mapping(bytes16 => bool) public licenseExists;
    address public owner;
    mapping(address => bool) public issuers;
    uint256 public licenseCount;

    event LicenseIssued(bytes16 indexed id, bytes32 licenseeHash, address licenseeWallet, uint64 expiresAt);
    event LicenseRevoked(bytes16 indexed id);
    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);

    modifier onlyOwner() {
        require(msg.sender == owner, "LicenseRegistry: not the owner");
        _;
    }

    modifier onlyIssuer() {
        require(issuers[msg.sender], "LicenseRegistry: not an issuer");
        _;
    }

    constructor() {
        owner = msg.sender;
        issuers[msg.sender] = true;
        emit IssuerAdded(msg.sender);
    }

    /// @notice Issue a new license
    /// @param id Unique 16-byte license identifier
    /// @param licenseeHash keccak256 of the licensee fingerprint
    /// @param licenseeWallet Ethereum address of the licensee (0x0 if unset)
    /// @param scopeHash keccak256 of the scope string
    /// @param issuedAt Unix timestamp of issuance
    /// @param expiresAt Unix timestamp of expiration
    /// @param contentHash SHA-256 of the full license data
    function issue(
        bytes16 id,
        bytes32 licenseeHash,
        address licenseeWallet,
        bytes32 scopeHash,
        uint64 issuedAt,
        uint64 expiresAt,
        bytes32 contentHash
    ) external onlyIssuer {
        require(!licenseExists[id], "LicenseRegistry: license already exists");

        licenses[id] = OnChainLicense({
            id: id,
            licenseeHash: licenseeHash,
            licenseeWallet: licenseeWallet,
            scopeHash: scopeHash,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            status: 0,
            contentHash: contentHash
        });
        licenseExists[id] = true;
        licenseCount++;

        emit LicenseIssued(id, licenseeHash, licenseeWallet, expiresAt);
    }

    /// @notice Revoke an existing license
    /// @param id License identifier to revoke
    function revoke(bytes16 id) external onlyIssuer {
        require(licenseExists[id], "LicenseRegistry: license does not exist");
        licenses[id].status = 1;
        emit LicenseRevoked(id);
    }

    /// @notice Verify a license's validity
    /// @param id License identifier to verify
    /// @return valid Whether the license is active and not expired
    /// @return status The license status (0=active, 1=revoked)
    /// @return expiresAt The expiration timestamp
    function verify(bytes16 id) external view returns (bool valid, uint8 status, uint64 expiresAt) {
        if (!licenseExists[id]) {
            return (false, 0, 0);
        }
        OnChainLicense storage lic = licenses[id];
        status = lic.status;
        expiresAt = lic.expiresAt;
        valid = (status == 0) && (block.timestamp <= expiresAt);
    }

    /// @notice Get full license data
    /// @param id License identifier
    /// @return The complete OnChainLicense struct
    function getLicense(bytes16 id) external view returns (OnChainLicense memory) {
        return licenses[id];
    }

    /// @notice Get total number of issued licenses
    /// @return The license count
    function getLicenseCount() external view returns (uint256) {
        return licenseCount;
    }

    /// @notice Add a new issuer
    /// @param issuer Address to grant issuer role
    function addIssuer(address issuer) external onlyOwner {
        issuers[issuer] = true;
        emit IssuerAdded(issuer);
    }

    /// @notice Remove an issuer
    /// @param issuer Address to revoke issuer role
    function removeIssuer(address issuer) external onlyOwner {
        issuers[issuer] = false;
        emit IssuerRemoved(issuer);
    }
}
