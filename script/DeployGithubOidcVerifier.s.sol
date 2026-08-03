// script/DeployGithubOidcVerifier.s.sol
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";

import {GithubOidcVerifier} from "../src/GithubOidcVerifier.sol";

contract DeployGithubOidcVerifier is Script {
    function run() external returns (GithubOidcVerifier verifier) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);
        verifier = new GithubOidcVerifier(owner);
        vm.stopBroadcast();
    }
}
