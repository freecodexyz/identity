// test/OidcFixture.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/**
 * @dev Shared loader for the signed OIDC fixtures produced by `test/fixtures/load-fixture.mjs`.
 *
 * Fixtures are generated rather than committed as blobs so a negative case is a small JSON file
 * instead of a hand-crafted token, and so every payload is a real RSA signature over a realistic
 * GitHub Actions claim set.
 */
abstract contract OidcFixture is Test {
    struct Fixture {
        bytes32 kid;
        bytes headerB64;
        bytes payloadB64;
        bytes signature;
        bytes modulus;
        bytes exponent;
        address wallet;
        uint256 userId;
        uint256 repoId;
        string jobWorkflowRef;
        uint256 exp;
        uint256 nbf;
    }

    /// @dev Loads `name` with the values baked into the fixture file.
    function _fixture(string memory name) internal returns (Fixture memory f) {
        string[] memory inputs = new string[](3);
        inputs[0] = "node";
        inputs[1] = "test/fixtures/load-fixture.mjs";
        inputs[2] = string.concat("test/fixtures/", name);

        f = _runFixture(inputs);
    }

    /// @dev Loads `name`, overriding the actor, audience and repository the token is issued for.
    function _fixture(string memory name, uint256 userId, address wallet, uint256 repoId)
        internal
        returns (Fixture memory f)
    {
        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "test/fixtures/load-fixture.mjs";
        inputs[2] = string.concat("test/fixtures/", name);
        inputs[3] = vm.toString(userId);
        inputs[4] = vm.toString(wallet);
        inputs[5] = vm.toString(repoId);

        f = _runFixture(inputs);
    }

    function _runFixture(string[] memory inputs) private returns (Fixture memory f) {
        string memory json = string(vm.ffi(inputs));
        f.kid = vm.parseJsonBytes32(json, ".kid");
        f.headerB64 = bytes(vm.parseJsonString(json, ".headerB64"));
        f.payloadB64 = bytes(vm.parseJsonString(json, ".payloadB64"));
        f.signature = vm.parseJsonBytes(json, ".signature");
        f.modulus = vm.parseJsonBytes(json, ".modulus");
        f.exponent = vm.parseJsonBytes(json, ".exponent");
        f.wallet = vm.parseJsonAddress(json, ".wallet");
        f.userId = vm.parseJsonUint(json, ".userId");
        f.repoId = vm.parseJsonUint(json, ".repoId");
        f.jobWorkflowRef = vm.parseJsonString(json, ".jobWorkflowRef");
        f.exp = vm.parseJsonUint(json, ".exp");
        f.nbf = vm.parseJsonUint(json, ".nbf");
    }
}
