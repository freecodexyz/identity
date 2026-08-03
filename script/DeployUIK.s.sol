// script/DeployUIK.s.sol
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";

import {IJwtVerifier} from "../src/IJwtVerifier.sol";
import {UIK} from "../src/UIK.sol";

/**
 * @dev Deploys {UIK} and pins its attestation source in the same broadcast. A UIK without both
 *      values configured rejects every registration, so they are required rather than optional.
 *
 * Environment:
 *
 * - `PRIVATE_KEY`: deployer key, also the initial owner.
 * - `JWT_VERIFIER_ADDRESS`: an {IJwtVerifier}, normally {GithubOidcVerifier}.
 * - `ATTESTATION_REPO_ID`: GitHub numeric id of the attestation repository.
 * - `JOB_WORKFLOW_REF`: the exact `job_workflow_ref` claim the attestation workflow produces, which
 *   is its `OWNER/REPO/.github/workflows/register.yml` path joined to the ref it runs from. Copy it
 *   from a real token rather than assembling it by hand.
 */
contract DeployUIK is Script {
    function run() external returns (UIK uik) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.addr(deployerPrivateKey);

        IJwtVerifier verifier = IJwtVerifier(vm.envAddress("JWT_VERIFIER_ADDRESS"));
        uint64 attestationRepoId = uint64(vm.envUint("ATTESTATION_REPO_ID"));
        string memory jobWorkflowRef = vm.envString("JOB_WORKFLOW_REF");

        vm.startBroadcast(deployerPrivateKey);
        uik = new UIK(owner, verifier);
        uik.setAttestationRepoId(attestationRepoId);
        uik.setJobWorkflowRef(jobWorkflowRef);
        vm.stopBroadcast();
    }
}
