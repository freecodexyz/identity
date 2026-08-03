// test/UIKSoulbound.invariant.t.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {GithubOidcVerifier} from "../src/GithubOidcVerifier.sol";
import {UIK} from "../src/UIK.sol";
import {OidcFixture} from "./OidcFixture.sol";

/**
 * @dev Drives every holder-reachable mutation on a bound identity. Each attempt is swallowed so the
 *      invariant, not the handler, is what proves the token cannot move.
 */
contract UIKSoulboundHandler is Test {
    UIK private immutable _uik;
    uint256 private immutable _tokenId;
    address private immutable _holder;

    address[4] private _actors;

    uint256 public attempts;

    constructor(UIK uik_, uint256 tokenId_, address holder_) {
        _uik = uik_;
        _tokenId = tokenId_;
        _holder = holder_;
        _actors = [holder_, address(0xA1), address(0xA2), address(0xA3)];
    }

    function _actor(uint256 seed) private view returns (address) {
        return _actors[seed % _actors.length];
    }

    function tryTransferFrom(uint256 callerSeed, uint256 toSeed) external {
        attempts++;
        vm.prank(_actor(callerSeed));
        try _uik.transferFrom(_holder, _actor(toSeed), _tokenId) {} catch {}
    }

    function trySafeTransferFrom(uint256 callerSeed, uint256 toSeed) external {
        attempts++;
        vm.prank(_actor(callerSeed));
        try _uik.safeTransferFrom(_holder, _actor(toSeed), _tokenId) {} catch {}
    }

    function tryApprove(uint256 callerSeed, uint256 spenderSeed) external {
        attempts++;
        vm.prank(_actor(callerSeed));
        try _uik.approve(_actor(spenderSeed), _tokenId) {} catch {}
    }

    function trySetApprovalForAll(uint256 callerSeed, uint256 operatorSeed, bool approved) external {
        attempts++;
        vm.prank(_actor(callerSeed));
        try _uik.setApprovalForAll(_actor(operatorSeed), approved) {} catch {}
    }
}

contract UIKSoulbound_Invariant is OidcFixture {
    uint64 constant ATTESTATION_REPO_ID = 1296269;
    string constant WORKFLOW_REF = "freecodexyz/identity/.github/workflows/register.yml@refs/heads/main";
    uint256 constant USER_ID = 583231;

    GithubOidcVerifier verifier;
    UIK uik;
    UIKSoulboundHandler handler;

    address alice = address(0x1111111111111111111111111111111111111111);

    function setUp() public {
        verifier = new GithubOidcVerifier(address(this));
        uik = new UIK(address(this), verifier);
        uik.setAttestationRepoId(ATTESTATION_REPO_ID);
        uik.setJobWorkflowRef(WORKFLOW_REF);

        Fixture memory f = _fixture("sample-jwt.json");
        verifier.addKey(f.kid, f.modulus, f.exponent);
        uik.register(f.kid, f.headerB64, f.payloadB64, f.signature, USER_ID, alice, f.login);

        handler = new UIKSoulboundHandler(uik, USER_ID, alice);
        targetContract(address(handler));
    }

    /// @dev Only an OIDC proof may move an identity; nothing a holder or operator can call does.
    function invariant_HolderCannotMoveIdentity() public view {
        assertEq(uik.ownerOf(USER_ID), alice);
        assertEq(uik.balanceOf(alice), 1);
    }

    /// @dev Approvals must never take effect, so no operator can ever be mistaken for an owner.
    function invariant_NoApprovalEverExists() public view {
        assertEq(uik.getApproved(USER_ID), address(0));
        assertFalse(uik.isApprovedForAll(alice, address(0xA1)));
        assertFalse(uik.isApprovedForAll(alice, address(0xA2)));
        assertFalse(uik.isApprovedForAll(alice, address(0xA3)));
    }

    /// @dev Guards against a silently no-op handler making the invariants vacuous. Runs once after
    ///      the campaign, unlike an `invariant_` function, which is also evaluated before any call.
    function afterInvariant() public view {
        assertGt(handler.attempts(), 0);
    }
}
