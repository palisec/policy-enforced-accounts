// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PolicyEnforcedRegistry} from "../src/PolicyEnforcedRegistry.sol";
import {IPolicyEnforcedAccount} from "../src/IPolicyEnforcedAccount.sol";
import {IPolicyEnforcedAccount as IV1} from "../src/v1/IPolicyEnforcedAccount.sol";
import {PolicyEnforcedRegistry as RegistryV2} from "../src/v2/PolicyEnforcedRegistry.sol";
import {IPolicyEnforcedAccount as IV2} from "../src/v2/IPolicyEnforcedAccount.sol";

/// Registry v3 against Robinhood Chain mainnet state: deployed through the deterministic deployer with its
/// published salt, next to the live v2 registry, with the real demo Safe moving to it and the stop hold
/// shown on both (the live v2 lets the publisher lift the Safe's own stop; v3 does not).
/// FORK=1 forge test --match-contract RegistryFork
contract RegistryForkTest is Test {
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address constant V1 = 0x20D6B38B47F7cb765A2318a1f318ed54a6f87e92;
    address constant V2 = 0xCa3bAE26d29a3A2cED7B87Fa996ca4C44367448d;
    address constant SAFE = 0x9aEC761B2F0FdA08C683e8388478C9A2F7C9170c;
    bytes32 constant SALT = keccak256("policy-enforced-accounts registry v3");
    bool skipFork;
    PolicyEnforcedRegistry reg;

    function setUp() public {
        if (vm.envOr("FORK", uint256(0)) != 1) {
            skipFork = true;
            return;
        }
        vm.createSelectFork("mainnet");
        bytes memory init = type(PolicyEnforcedRegistry).creationCode;
        (bool ok,) = CREATE2_DEPLOYER.call(abi.encodePacked(SALT, init));
        require(ok, "deploy");
        reg = PolicyEnforcedRegistry(vm.computeCreate2Address(SALT, keccak256(init), CREATE2_DEPLOYER));
    }

    function test_fork_safeMovesToV3() public {
        if (skipFork) return;
        assertGt(address(reg).code.length, 0);
        IV2.Signers memory old = IV2(V2).policySigner(SAFE);
        assertTrue(old.policySigner != address(0), "the Safe declared on v2");
        IV2.PolicyCommitment memory oldPolicy = IV2(V2).policyOf(SAFE);

        vm.prank(SAFE);
        reg.declare(old.policySigner, old.publisher, old.receiptSigner, old.minDelay, old.signerType);
        IPolicyEnforcedAccount.Signers memory s = reg.policySigner(SAFE);
        assertEq(s.publisher, old.publisher);
        assertEq(s.minDelay, old.minDelay);

        uint64 at = uint64(block.timestamp) + old.minDelay;
        vm.prank(old.publisher);
        reg.setPending(SAFE, oldPolicy.policyHash, oldPolicy.version, at, oldPolicy.policyURI, oldPolicy.schemaURI);
        vm.warp(at);
        vm.prank(old.publisher);
        reg.activate(SAFE, oldPolicy.policyHash, oldPolicy.version, oldPolicy.policyURI, oldPolicy.schemaURI);
        assertEq(reg.policyOf(SAFE).policyHash, oldPolicy.policyHash);
        assertEq(IV2(V2).policyOf(SAFE).policyHash, oldPolicy.policyHash, "v2 is untouched");
        assertTrue(RegistryV2(V2).supportsInterface(type(IV2).interfaceId));
        assertTrue(reg.supportsInterface(type(IPolicyEnforcedAccount).interfaceId));
        assertFalse(reg.supportsInterface(type(IV2).interfaceId));
    }

    /// The forum's case on the live v2 registry and on v3, with the real Safe and its real publisher.
    function test_fork_stopHold() public {
        if (skipFork) return;
        IV2.Signers memory old = IV2(V2).policySigner(SAFE);
        vm.prank(SAFE);
        RegistryV2(V2).setStopped(SAFE, true, "publisher key leaked");
        vm.prank(old.publisher);
        RegistryV2(V2).setStopped(SAFE, false, "");
        assertFalse(IV2(V2).isStopped(SAFE), "live v2: the publisher lifted the Safe's own stop");

        vm.prank(SAFE);
        reg.declare(old.policySigner, old.publisher, old.receiptSigner, old.minDelay, old.signerType);
        vm.prank(SAFE);
        reg.setStopped(SAFE, true, "publisher key leaked");
        vm.prank(old.publisher);
        vm.expectRevert(PolicyEnforcedRegistry.StopHeldByAccount.selector);
        reg.setStopped(SAFE, false, "");
        assertTrue(reg.isStopped(SAFE), "v3: the stop holds");
    }
}
