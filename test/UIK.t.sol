// test/UIK.t.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

import {GithubOidcVerifier} from "../src/GithubOidcVerifier.sol";
import {JsonClaim} from "../src/JsonClaim.sol";
import {UIK} from "../src/UIK.sol";
import {OidcFixture} from "./OidcFixture.sol";

contract UIK_T is OidcFixture {
    /// @dev Must match the defaults baked into `test/fixtures/load-fixture.mjs`.
    uint64 constant ATTESTATION_REPO_ID = 1296269;
    string constant WORKFLOW_REF = "freecodexyz/identity/.github/workflows/register.yml@refs/heads/main";

    uint64 constant USER_ID = 583231;

    GithubOidcVerifier verifier;
    UIK uik;

    address owner = address(this);
    address stranger = address(0xBAD);
    address relayer = address(0xFEE);
    address alice = address(0x1111111111111111111111111111111111111111);
    address bob = address(0x2222222222222222222222222222222222222222);

    function setUp() public {
        verifier = new GithubOidcVerifier(owner);
        uik = new UIK(owner, verifier);
        uik.setAttestationRepoId(ATTESTATION_REPO_ID);
        uik.setJobWorkflowRef(WORKFLOW_REF);
    }

    function _addKey(Fixture memory f) internal {
        verifier.addKey(f.kid, f.modulus, f.exponent);
    }

    function _register(Fixture memory f, uint256 userId, address wallet) internal {
        uik.register(f.kid, f.headerB64, f.payloadB64, f.signature, userId, wallet, f.login);
    }

    /// @dev Registers with a login the caller chooses, rather than the one the token attests.
    function _registerAs(Fixture memory f, uint256 userId, address wallet, string memory login) internal {
        uik.register(f.kid, f.headerB64, f.payloadB64, f.signature, userId, wallet, login);
    }

    /// @dev Loads the happy-path fixture and installs its signing key.
    function _ready(string memory name) internal returns (Fixture memory f) {
        f = _fixture(name);
        _addKey(f);
    }

    function _ready(string memory name, uint256 userId, address wallet, uint256 repoId)
        internal
        returns (Fixture memory f)
    {
        f = _fixture(name, userId, wallet, repoId);
        _addKey(f);
    }

    function _ready(string memory name, uint256 userId, address wallet, uint256 repoId, string memory login)
        internal
        returns (Fixture memory f)
    {
        f = _fixture(name, userId, wallet, repoId, login);
        _addKey(f);
    }

    // --- metadata and configuration ---------------------------------------

    function test_NameAndSymbol() public view {
        assertEq(uik.name(), "User Identity Key");
        assertEq(uik.symbol(), "UIK");
    }

    function test_ExpectedEventName() public view {
        assertEq(uik.expectedEventName(), "issues");
    }

    function test_JwtVerifierIsImmutable() public view {
        assertEq(address(uik.jwt()), address(verifier));
    }

    function test_AttestationSourceReads() public view {
        assertEq(uik.attestationRepoId(), ATTESTATION_REPO_ID);
        assertEq(uik.jobWorkflowRef(), WORKFLOW_REF);
    }

    function test_TokenIdOfIsIdentity() public view {
        assertEq(uik.tokenIdOf(USER_ID), USER_ID);
    }

    function testFuzz_TokenIdOfIsIdentity(uint64 userId) public view {
        assertEq(uik.tokenIdOf(userId), uint256(userId));
    }

    function test_SetAttestationRepoIdEmits() public {
        vm.expectEmit(true, false, false, false);
        emit UIK.AttestationRepoSet(42);
        uik.setAttestationRepoId(42);

        assertEq(uik.attestationRepoId(), 42);
    }

    function test_SetJobWorkflowRefEmits() public {
        vm.expectEmit(false, false, false, true);
        emit UIK.JobWorkflowRefSet("owner/repo/.github/workflows/x.yml@refs/heads/main");
        uik.setJobWorkflowRef("owner/repo/.github/workflows/x.yml@refs/heads/main");

        assertEq(uik.jobWorkflowRef(), "owner/repo/.github/workflows/x.yml@refs/heads/main");
    }

    function test_SetAttestationRepoIdOnlyOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        uik.setAttestationRepoId(42);
    }

    function test_SetJobWorkflowRefOnlyOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        uik.setJobWorkflowRef("x");
    }

    function test_OwnershipTransferIsTwoStep() public {
        uik.transferOwnership(stranger);
        // Still the old owner until the pending owner accepts.
        assertEq(uik.owner(), owner);
        assertEq(uik.pendingOwner(), stranger);

        vm.prank(stranger);
        uik.acceptOwnership();
        assertEq(uik.owner(), stranger);
    }

    // --- registration happy path -------------------------------------------

    function test_RegisterMintsToAttestedWallet() public {
        Fixture memory f = _ready("sample-jwt.json");

        _register(f, USER_ID, alice);

        assertEq(uik.ownerOf(USER_ID), alice);
        assertEq(uik.balanceOf(alice), 1);
    }

    /// @dev The core T2 property: the proof names its beneficiary, so a relayer can pay the gas
    ///      without being able to redirect the identity.
    function test_RegisterIsPermissionless() public {
        Fixture memory f = _ready("sample-jwt.json");

        vm.prank(relayer);
        _register(f, USER_ID, alice);

        assertEq(uik.ownerOf(USER_ID), alice);
        assertEq(uik.balanceOf(relayer), 0);
    }

    function test_RegisterEmitsIdentityBound() public {
        Fixture memory f = _ready("sample-jwt.json");

        vm.warp(1_700_000_000);
        vm.expectEmit(true, true, true, true);
        emit UIK.IdentityBound(USER_ID, alice, address(0), 1_700_000_000);
        _register(f, USER_ID, alice);
    }

    function test_RegisterStoresIdentity() public {
        Fixture memory f = _ready("sample-jwt.json");

        vm.warp(1_700_000_000);
        _register(f, USER_ID, alice);

        UIK.Identity memory identity = uik.identityOf(USER_ID);
        assertEq(identity.githubUserId, USER_ID);
        assertEq(identity.boundAt, 1_700_000_000);
        assertEq(identity.login, "octocat");
    }

    function test_RegisterMarksProofUsed() public {
        Fixture memory f = _ready("sample-jwt.json");
        bytes32 proofId = keccak256(f.signature);

        assertFalse(uik.isProofUsed(proofId));
        _register(f, USER_ID, alice);
        assertTrue(uik.isProofUsed(proofId));
    }

    function test_ProofIdOfIsSignatureHash() public {
        Fixture memory f = _fixture("sample-jwt.json");
        assertEq(uik.proofIdOf(f.signature), keccak256(f.signature));
    }

    function test_TwoAccountsGetDistinctTokens() public {
        Fixture memory aliceF = _ready("sample-jwt.json", 111, alice, ATTESTATION_REPO_ID);
        Fixture memory bobF = _fixture("sample-jwt.json", 222, bob, ATTESTATION_REPO_ID);

        _register(aliceF, 111, alice);
        _register(bobF, 222, bob);

        assertEq(uik.ownerOf(111), alice);
        assertEq(uik.ownerOf(222), bob);
    }

    function test_OneWalletMayHoldSeveralIdentities() public {
        Fixture memory first = _ready("sample-jwt.json", 111, alice, ATTESTATION_REPO_ID);
        Fixture memory second = _fixture("sample-jwt.json", 222, alice, ATTESTATION_REPO_ID);

        _register(first, 111, alice);
        _register(second, 222, alice);

        assertEq(uik.balanceOf(alice), 2);
    }

    // --- claim binding ------------------------------------------------------

    function test_RejectsAudMismatch() public {
        Fixture memory f = _ready("sample-jwt.json");

        // The proof attests `alice`; nobody can redirect it to another wallet.
        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "aud"));
        _register(f, USER_ID, bob);
    }

    function test_RejectsActorIdMismatch() public {
        Fixture memory f = _ready("sample-jwt.json");

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "actor_id"));
        _register(f, USER_ID + 1, alice);
    }

    /// @dev The login is display-only, but it is still proven rather than trusted from the caller.
    function test_RejectsLoginMismatch() public {
        Fixture memory f = _ready("sample-jwt.json");

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "actor"));
        _registerAs(f, USER_ID, alice, "not-octocat");
    }

    function testFuzz_RejectsAnyLoginButTheAttestedOne(string calldata login) public {
        Fixture memory f = _ready("sample-jwt.json");
        vm.assume(keccak256(bytes(login)) != keccak256(bytes(f.login)));

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "actor"));
        _registerAs(f, USER_ID, alice, login);
    }

    /// @dev A login carrying a quote is escaped in the signed payload, so the claim matcher rejects
    ///      it before the charset check ever runs. {UIK-_requireRenderableLogin} is the second line.
    function test_RejectsLoginWithQuoteAtClaimCheck() public {
        Fixture memory f = _ready("quoted-login-jwt.json");

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "actor"));
        _register(f, USER_ID, alice);
    }

    /// @dev A slash survives JSON encoding, so it satisfies the claim check and must be caught by
    ///      the charset validation. Left unchecked it would corrupt the metadata profile URL.
    function test_RejectsUnrenderableLogin() public {
        Fixture memory f = _ready("bad-login-jwt.json");

        vm.expectRevert(UIK.InvalidLogin.selector);
        _register(f, USER_ID, alice);
    }

    function test_RejectsEmptyLogin() public {
        Fixture memory f = _ready("empty-login-jwt.json");

        vm.expectRevert(UIK.InvalidLogin.selector);
        _register(f, USER_ID, alice);
    }

    function test_RejectsOverlongLogin() public {
        Fixture memory f = _ready("long-login-jwt.json");

        vm.expectRevert(UIK.InvalidLogin.selector);
        _register(f, USER_ID, alice);
    }

    function test_AcceptsMaximumLengthLogin() public {
        string memory login = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddd";
        assertEq(bytes(login).length, 39);
        Fixture memory f = _ready("sample-jwt.json", USER_ID, alice, ATTESTATION_REPO_ID, login);

        _register(f, USER_ID, alice);
        assertEq(uik.identityOf(USER_ID).login, login);
    }

    function test_AcceptsHyphensAndDigits() public {
        Fixture memory f = _ready("sample-jwt.json", USER_ID, alice, ATTESTATION_REPO_ID, "oct-0-cat-9");

        _register(f, USER_ID, alice);
        assertEq(uik.identityOf(USER_ID).login, "oct-0-cat-9");
    }

    /// @dev Without the `repository_id` pin, anyone could call the attestation workflow as a
    ///      reusable workflow from their own repository and choose the audience.
    function test_RejectsForeignRepository() public {
        Fixture memory f = _ready("sample-jwt.json", USER_ID, alice, 999999);

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "repository_id"));
        _register(f, USER_ID, alice);
    }

    /// @dev Only the `issues` trigger carries an external actor in the attestation repository.
    function test_RejectsWrongEventName() public {
        Fixture memory f = _ready("wrong-event-jwt.json");

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "event_name"));
        _register(f, USER_ID, alice);
    }

    /// @dev Without the `job_workflow_ref` pin, rewriting the attestation workflow would be enough
    ///      to mint anyone's identity to any address.
    function test_RejectsForeignJobWorkflowRef() public {
        Fixture memory f = _ready("wrong-workflow-ref-jwt.json");

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "job_workflow_ref"));
        _register(f, USER_ID, alice);
    }

    function test_RejectsWhenAttestationSourceUnset() public {
        UIK fresh = new UIK(owner, verifier);
        Fixture memory f = _ready("sample-jwt.json");

        vm.expectRevert(UIK.AttestationSourceNotConfigured.selector);
        fresh.register(f.kid, f.headerB64, f.payloadB64, f.signature, USER_ID, alice, f.login);
    }

    function test_RejectsWhenWorkflowRefUnset() public {
        UIK fresh = new UIK(owner, verifier);
        fresh.setAttestationRepoId(ATTESTATION_REPO_ID);
        Fixture memory f = _ready("sample-jwt.json");

        vm.expectRevert(UIK.AttestationSourceNotConfigured.selector);
        fresh.register(f.kid, f.headerB64, f.payloadB64, f.signature, USER_ID, alice, f.login);
    }

    /// @dev The whole claim matcher rests on JSON escaping `"` inside values. A workflow name
    ///      crafted to look like a claim must not be able to forge one.
    function test_ClaimInjectionCannotForgeActorId() public {
        Fixture memory f = _ready("claim-injection-jwt.json");

        // The payload literally contains `pwn","actor_id":"999999"...` inside the `workflow` claim.
        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "actor_id"));
        _register(f, 999999, alice);
    }

    function test_ClaimInjectionStillBindsRealActor() public {
        Fixture memory f = _ready("claim-injection-jwt.json");

        // The genuine claim is unaffected by the injected text.
        _register(f, USER_ID, alice);
        assertEq(uik.ownerOf(USER_ID), alice);
    }

    // --- verifier delegation ------------------------------------------------

    function test_RejectsUnknownKid() public {
        Fixture memory f = _fixture("sample-jwt.json");

        vm.expectRevert(abi.encodeWithSelector(GithubOidcVerifier.UnknownKid.selector, f.kid));
        _register(f, USER_ID, alice);
    }

    function test_RejectsBadSignature() public {
        Fixture memory f = _ready("sample-jwt.json");
        f.signature[0] = bytes1(uint8(f.signature[0]) ^ 1);

        vm.expectRevert(GithubOidcVerifier.BadJwt.selector);
        _register(f, USER_ID, alice);
    }

    function test_RejectsWrongIssuer() public {
        Fixture memory f = _ready("wrong-issuer-jwt.json");

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "iss"));
        _register(f, USER_ID, alice);
    }

    function test_RejectsExpiredProof() public {
        Fixture memory f = _ready("sample-jwt.json");

        vm.warp(f.exp + 1);
        vm.expectRevert(GithubOidcVerifier.TokenExpired.selector);
        _register(f, USER_ID, alice);
    }

    // --- replay and identifier bounds --------------------------------------

    function test_RejectsReplayedProof() public {
        Fixture memory f = _ready("sample-jwt.json");
        _register(f, USER_ID, alice);

        vm.expectRevert(abi.encodeWithSelector(UIK.ProofAlreadyUsed.selector, keccak256(f.signature)));
        _register(f, USER_ID, alice);
    }

    function test_RejectsZeroUserId() public {
        Fixture memory f = _ready("sample-jwt.json", 0, alice, ATTESTATION_REPO_ID);

        vm.expectRevert(abi.encodeWithSelector(UIK.InvalidGithubUserId.selector, 0));
        _register(f, 0, alice);
    }

    function test_RejectsUserIdTooLarge() public {
        uint256 userId = uint256(type(uint64).max) + 1;
        Fixture memory f = _ready("sample-jwt.json", userId, alice, ATTESTATION_REPO_ID);

        vm.expectRevert(abi.encodeWithSelector(UIK.InvalidGithubUserId.selector, userId));
        _register(f, userId, alice);
    }

    function test_RejectsZeroWallet() public {
        Fixture memory f = _ready("sample-jwt.json", USER_ID, address(0), ATTESTATION_REPO_ID);

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidReceiver.selector, address(0)));
        _register(f, USER_ID, address(0));
    }

    function test_IdentityOfRevertsForUnregistered() public {
        vm.expectRevert(abi.encodeWithSelector(UIK.NotRegistered.selector, USER_ID));
        uik.identityOf(USER_ID);
    }

    // --- rebinding ----------------------------------------------------------

    function test_RebindMovesTokenToNewWallet() public {
        Fixture memory first = _ready("sample-jwt.json");
        _register(first, USER_ID, alice);

        Fixture memory second = _fixture("sample-jwt.json", USER_ID, bob, ATTESTATION_REPO_ID);
        _register(second, USER_ID, bob);

        assertEq(uik.ownerOf(USER_ID), bob);
        assertEq(uik.balanceOf(alice), 0);
        assertEq(uik.balanceOf(bob), 1);
    }

    function test_RebindEmitsPreviousWallet() public {
        Fixture memory first = _ready("sample-jwt.json");
        _register(first, USER_ID, alice);

        Fixture memory second = _fixture("sample-jwt.json", USER_ID, bob, ATTESTATION_REPO_ID);

        vm.warp(1_700_000_042);
        vm.expectEmit(true, true, true, true);
        emit UIK.IdentityBound(USER_ID, bob, alice, 1_700_000_042);
        _register(second, USER_ID, bob);
    }

    function test_RebindUpdatesBoundAt() public {
        Fixture memory first = _ready("sample-jwt.json");
        vm.warp(1_700_000_000);
        _register(first, USER_ID, alice);

        Fixture memory second = _fixture("sample-jwt.json", USER_ID, bob, ATTESTATION_REPO_ID);
        vm.warp(1_800_000_000);
        _register(second, USER_ID, bob);

        assertEq(uik.identityOf(USER_ID).boundAt, 1_800_000_000);
    }

    /// @dev Rebinding to the wallet that already holds the identity is a no-op and rejected, so a
    ///      stale proof cannot be used to churn state.
    function test_RebindToSameWalletReverts() public {
        Fixture memory first = _ready("sample-jwt.json");
        _register(first, USER_ID, alice);

        // Same claims, different signature.
        Fixture memory duplicate = _fixture("sample-jwt-alt.json");
        assertEq(duplicate.wallet, alice);

        vm.expectRevert(abi.encodeWithSelector(UIK.AlreadyBound.selector, USER_ID, alice));
        _register(duplicate, USER_ID, alice);
    }

    /// @dev Only the account itself can rebind, because only it can produce a proof carrying its
    ///      `actor_id`. A third party's proof moves their own identity, never someone else's.
    function test_RebindCannotBeDrivenByAnotherAccount() public {
        Fixture memory first = _ready("sample-jwt.json");
        _register(first, USER_ID, alice);

        Fixture memory attacker = _fixture("sample-jwt.json", USER_ID + 1, bob, ATTESTATION_REPO_ID);

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "actor_id"));
        _register(attacker, USER_ID, bob);
    }

    // --- soulbound ----------------------------------------------------------

    function test_TransferFromReverts() public {
        Fixture memory f = _ready("sample-jwt.json");
        _register(f, USER_ID, alice);

        vm.prank(alice);
        vm.expectRevert(UIK.NonTransferable.selector);
        uik.transferFrom(alice, bob, USER_ID);
    }

    function test_SafeTransferFromReverts() public {
        Fixture memory f = _ready("sample-jwt.json");
        _register(f, USER_ID, alice);

        vm.prank(alice);
        vm.expectRevert(UIK.NonTransferable.selector);
        uik.safeTransferFrom(alice, bob, USER_ID);
    }

    function test_SafeTransferFromWithDataReverts() public {
        Fixture memory f = _ready("sample-jwt.json");
        _register(f, USER_ID, alice);

        vm.prank(alice);
        vm.expectRevert(UIK.NonTransferable.selector);
        uik.safeTransferFrom(alice, bob, USER_ID, "");
    }

    function test_ApproveReverts() public {
        Fixture memory f = _ready("sample-jwt.json");
        _register(f, USER_ID, alice);

        vm.prank(alice);
        vm.expectRevert(UIK.NonTransferable.selector);
        uik.approve(bob, USER_ID);
    }

    function test_SetApprovalForAllReverts() public {
        Fixture memory f = _ready("sample-jwt.json");
        _register(f, USER_ID, alice);

        vm.prank(alice);
        vm.expectRevert(UIK.NonTransferable.selector);
        uik.setApprovalForAll(bob, true);
    }

    function test_NoApprovalSurvivesRebind() public {
        Fixture memory first = _ready("sample-jwt.json");
        _register(first, USER_ID, alice);

        Fixture memory second = _fixture("sample-jwt.json", USER_ID, bob, ATTESTATION_REPO_ID);
        _register(second, USER_ID, bob);

        assertEq(uik.getApproved(USER_ID), address(0));
    }

    // --- fuzz ---------------------------------------------------------------

    /// forge-config: default.fuzz.runs = 16
    function testFuzz_RegisterBindsAnyValidAccount(uint64 userId, address wallet) public {
        vm.assume(userId != 0);
        vm.assume(wallet != address(0));
        // Precompiles and the test contract itself are poor ERC-721 receivers under `_mint`.
        vm.assume(uint160(wallet) > 0x0a);

        Fixture memory f = _ready("sample-jwt.json", uint256(userId), wallet, ATTESTATION_REPO_ID);
        _register(f, uint256(userId), wallet);

        assertEq(uik.ownerOf(uint256(userId)), wallet);
        assertEq(uik.identityOf(uint256(userId)).githubUserId, userId);
    }

    /// forge-config: default.fuzz.runs = 16
    function testFuzz_RejectsAnyWalletButTheAttestedOne(address wallet) public {
        Fixture memory f = _ready("sample-jwt.json");
        vm.assume(wallet != alice);

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "aud"));
        _register(f, USER_ID, wallet);
    }

    /// forge-config: default.fuzz.runs = 16
    function testFuzz_RejectsAnyActorButTheAttestedOne(uint256 userId) public {
        Fixture memory f = _ready("sample-jwt.json");
        vm.assume(userId != USER_ID);

        vm.expectRevert(abi.encodeWithSelector(JsonClaim.ClaimMismatch.selector, "actor_id"));
        _register(f, userId, alice);
    }
}
