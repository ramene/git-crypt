// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/LicenseRegistry.sol";

contract LicenseRegistryTest is Test {
    LicenseRegistry registry;
    address deployer = address(this);
    address nonIssuer = address(0xBEEF);
    address newIssuer = address(0xCAFE);

    bytes16 constant LIC_ID = bytes16(uint128(0x1234567890abcdef1234567890abcdef));
    bytes32 constant LICENSEE_HASH = keccak256("licensee-fingerprint");
    address constant LICENSEE_WALLET = address(0xA11CE);
    bytes32 constant SCOPE_HASH = keccak256("repo:org/project");
    uint64 constant ISSUED_AT = 1700000000;
    uint64 constant EXPIRES_AT = 1800000000;
    bytes32 constant CONTENT_HASH = keccak256("full-license-data");

    function setUp() public {
        registry = new LicenseRegistry();
    }

    function _issueLicense() internal {
        registry.issue(LIC_ID, LICENSEE_HASH, LICENSEE_WALLET, SCOPE_HASH, ISSUED_AT, EXPIRES_AT, CONTENT_HASH);
    }

    function test_issue_license() public {
        _issueLicense();

        assertTrue(registry.licenseExists(LIC_ID));
        LicenseRegistry.OnChainLicense memory lic = registry.getLicense(LIC_ID);
        assertEq(lic.id, LIC_ID);
        assertEq(lic.licenseeHash, LICENSEE_HASH);
        assertEq(lic.licenseeWallet, LICENSEE_WALLET);
        assertEq(lic.scopeHash, SCOPE_HASH);
        assertEq(lic.issuedAt, ISSUED_AT);
        assertEq(lic.expiresAt, EXPIRES_AT);
        assertEq(lic.status, 0);
        assertEq(lic.contentHash, CONTENT_HASH);
    }

    function test_revoke_license() public {
        _issueLicense();
        registry.revoke(LIC_ID);

        LicenseRegistry.OnChainLicense memory lic = registry.getLicense(LIC_ID);
        assertEq(lic.status, 1);
    }

    function test_verify_active() public {
        _issueLicense();
        vm.warp(ISSUED_AT + 1);

        (bool valid, uint8 status, uint64 expiresAt) = registry.verify(LIC_ID);
        assertTrue(valid);
        assertEq(status, 0);
        assertEq(expiresAt, EXPIRES_AT);
    }

    function test_verify_revoked() public {
        _issueLicense();
        registry.revoke(LIC_ID);
        vm.warp(ISSUED_AT + 1);

        (bool valid, uint8 status, uint64 expiresAt) = registry.verify(LIC_ID);
        assertFalse(valid);
        assertEq(status, 1);
        assertEq(expiresAt, EXPIRES_AT);
    }

    function test_verify_nonexistent() public view {
        bytes16 fakeId = bytes16(uint128(0xdeadbeef));
        (bool valid, uint8 status, uint64 expiresAt) = registry.verify(fakeId);
        assertFalse(valid);
        assertEq(status, 0);
        assertEq(expiresAt, 0);
    }

    function test_only_issuer_can_issue() public {
        vm.prank(nonIssuer);
        vm.expectRevert("LicenseRegistry: not an issuer");
        registry.issue(LIC_ID, LICENSEE_HASH, LICENSEE_WALLET, SCOPE_HASH, ISSUED_AT, EXPIRES_AT, CONTENT_HASH);
    }

    function test_only_issuer_can_revoke() public {
        _issueLicense();

        vm.prank(nonIssuer);
        vm.expectRevert("LicenseRegistry: not an issuer");
        registry.revoke(LIC_ID);
    }

    function test_add_remove_issuer() public {
        registry.addIssuer(newIssuer);
        assertTrue(registry.issuers(newIssuer));

        registry.removeIssuer(newIssuer);
        assertFalse(registry.issuers(newIssuer));
    }

    function test_duplicate_license_id_reverts() public {
        _issueLicense();

        vm.expectRevert("LicenseRegistry: license already exists");
        _issueLicense();
    }

    function test_get_license_count() public {
        assertEq(registry.getLicenseCount(), 0);
        _issueLicense();
        assertEq(registry.getLicenseCount(), 1);

        bytes16 id2 = bytes16(uint128(0xabcdef));
        registry.issue(id2, LICENSEE_HASH, LICENSEE_WALLET, SCOPE_HASH, ISSUED_AT, EXPIRES_AT, CONTENT_HASH);
        assertEq(registry.getLicenseCount(), 2);
    }

    function test_events() public {
        vm.expectEmit(true, false, false, true);
        emit LicenseRegistry.LicenseIssued(LIC_ID, LICENSEE_HASH, LICENSEE_WALLET, EXPIRES_AT);
        _issueLicense();

        vm.expectEmit(true, false, false, false);
        emit LicenseRegistry.LicenseRevoked(LIC_ID);
        registry.revoke(LIC_ID);
    }
}
