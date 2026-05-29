// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/LicenseRegistry.sol";
import "../src/MerkleAudit.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();

        LicenseRegistry registry = new LicenseRegistry();
        console.log("LicenseRegistry deployed at:", address(registry));

        MerkleAudit audit = new MerkleAudit();
        console.log("MerkleAudit deployed at:", address(audit));

        vm.stopBroadcast();
    }
}
