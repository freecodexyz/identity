// test/UIKMetadata.t.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IERC4906} from "@openzeppelin/contracts/interfaces/IERC4906.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {GithubOidcVerifier} from "../src/GithubOidcVerifier.sol";
import {IERC5192} from "../src/IERC5192.sol";
import {ITokenRenderer} from "../src/ITokenRenderer.sol";
import {UIK} from "../src/UIK.sol";
import {OidcFixture} from "./OidcFixture.sol";

/// @dev Echoes what {UIK} passed in, so the argument wiring can be asserted rather than assumed.
contract EchoRenderer is ITokenRenderer {
    function render(uint256 tokenId, address wallet, string calldata login, uint64 boundAt)
        external
        pure
        returns (string memory)
    {
        return string.concat(
            "echo://",
            Strings.toString(tokenId),
            "/",
            Strings.toHexString(uint160(wallet), 20),
            "/",
            login,
            "/",
            Strings.toString(boundAt)
        );
    }
}

/// @dev {UIK-tokenURI} is a view function, so it reaches a renderer through a staticcall. A renderer
///      that writes state therefore cannot work, and must degrade rather than brick metadata.
///      Deliberately does not implement {ITokenRenderer}, which would not compile; only the selector
///      has to match for {UIK} to call it.
contract StatefulRenderer {
    uint256 private _calls;

    function render(uint256, address, string calldata, uint64) external returns (string memory) {
        _calls += 1;
        return "custom://stateful";
    }
}

contract StaticRenderer is ITokenRenderer {
    function render(uint256, address, string calldata login, uint64) external pure returns (string memory) {
        return string.concat("custom://", login);
    }
}

contract RevertingRenderer is ITokenRenderer {
    error Broken();

    function render(uint256, address, string calldata, uint64) external pure returns (string memory) {
        revert Broken();
    }
}

/// @dev Burns all forwarded gas. A renderer must not be able to brick metadata this way either.
contract GasBurningRenderer is ITokenRenderer {
    function render(uint256, address, string calldata, uint64) external view returns (string memory) {
        while (true) {
            assert(gasleft() > 0);
        }
        return "";
    }
}

contract UIKMetadata_T is OidcFixture {
    uint64 constant ATTESTATION_REPO_ID = 1296269;
    string constant WORKFLOW_REF = "freecodexyz/identity/.github/workflows/register.yml@refs/heads/main";
    uint64 constant USER_ID = 583231;

    string constant DATA_URI_PREFIX = "data:application/json;base64,";

    bytes4 constant ERC165_ID = 0x01ffc9a7;
    bytes4 constant ERC721_ID = 0x80ac58cd;
    bytes4 constant ERC721_METADATA_ID = 0x5b5e139f;
    bytes4 constant ERC4906_ID = 0x49064906;
    bytes4 constant ERC5192_ID = 0xb45a3c0e;

    GithubOidcVerifier verifier;
    UIK uik;

    address owner = address(this);
    address stranger = address(0xBAD);
    address alice = address(0x1111111111111111111111111111111111111111);
    address bob = address(0x2222222222222222222222222222222222222222);

    function setUp() public {
        verifier = new GithubOidcVerifier(owner);
        uik = new UIK(owner, verifier);
        uik.setAttestationRepoId(ATTESTATION_REPO_ID);
        uik.setJobWorkflowRef(WORKFLOW_REF);
    }

    function _bindAlice() internal returns (Fixture memory f) {
        f = _fixture("sample-jwt.json");
        verifier.addKey(f.kid, f.modulus, f.exponent);
        uik.register(f.kid, f.headerB64, f.payloadB64, f.signature, USER_ID, alice, f.login);
    }

    function _rebindToBob() internal {
        Fixture memory f = _fixture("sample-jwt.json", USER_ID, bob, ATTESTATION_REPO_ID, "octocat-two");
        uik.register(f.kid, f.headerB64, f.payloadB64, f.signature, USER_ID, bob, f.login);
    }

    function _startsWithDataUri(string memory uri) internal pure returns (bool) {
        bytes memory raw = bytes(uri);
        bytes memory prefix = bytes(DATA_URI_PREFIX);
        if (raw.length < prefix.length) return false;
        for (uint256 i = 0; i < prefix.length; ++i) {
            if (raw[i] != prefix[i]) return false;
        }
        return true;
    }

    // --- interface advertisement -------------------------------------------

    function test_SupportsCoreInterfaces() public view {
        assertTrue(uik.supportsInterface(ERC165_ID));
        assertTrue(uik.supportsInterface(ERC721_ID));
        assertTrue(uik.supportsInterface(ERC721_METADATA_ID));
    }

    /// @dev ERC-4906 declares only events, so `type(IERC4906).interfaceId` is zero and the value has
    ///      to be the one fixed by the ERC. This pins that it is not accidentally derived.
    function test_SupportsErc4906WithFixedId() public view {
        assertTrue(uik.supportsInterface(ERC4906_ID));
        assertEq(type(IERC4906).interfaceId, bytes4(0));
    }

    function test_SupportsErc5192() public view {
        assertTrue(uik.supportsInterface(ERC5192_ID));
        assertEq(type(IERC5192).interfaceId, ERC5192_ID);
    }

    function testFuzz_RejectsUnknownInterface(bytes4 interfaceId) public view {
        vm.assume(interfaceId != ERC165_ID);
        vm.assume(interfaceId != ERC721_ID);
        vm.assume(interfaceId != ERC721_METADATA_ID);
        vm.assume(interfaceId != ERC4906_ID);
        vm.assume(interfaceId != ERC5192_ID);
        vm.assume(interfaceId != 0xffffffff);

        assertFalse(uik.supportsInterface(interfaceId));
    }

    // --- ERC-5192 -----------------------------------------------------------

    function test_LockedIsTrueForBoundIdentity() public {
        _bindAlice();
        assertTrue(uik.locked(USER_ID));
    }

    function test_LockedRevertsForUnknownToken() public {
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, USER_ID));
        uik.locked(USER_ID);
    }

    function test_MintEmitsLocked() public {
        Fixture memory f = _fixture("sample-jwt.json");
        verifier.addKey(f.kid, f.modulus, f.exponent);

        vm.expectEmit(false, false, false, true);
        emit IERC5192.Locked(USER_ID);
        uik.register(f.kid, f.headerB64, f.payloadB64, f.signature, USER_ID, alice, f.login);
    }

    // --- ERC-4906 -----------------------------------------------------------

    /// @dev The Transfer from the zero address already tells indexers to fetch metadata, so a mint
    ///      must not also emit the "it changed" signal.
    function test_MintDoesNotEmitMetadataUpdate() public {
        Fixture memory f = _fixture("sample-jwt.json");
        verifier.addKey(f.kid, f.modulus, f.exponent);

        vm.recordLogs();
        uik.register(f.kid, f.headerB64, f.payloadB64, f.signature, USER_ID, alice, f.login);

        bytes32 topic = keccak256("MetadataUpdate(uint256)");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != topic);
        }
    }

    function test_RebindEmitsMetadataUpdate() public {
        _bindAlice();

        vm.expectEmit(false, false, false, true);
        emit IERC4906.MetadataUpdate(USER_ID);
        _rebindToBob();
    }

    function test_SetRendererEmitsBatchMetadataUpdate() public {
        vm.expectEmit(false, false, false, true);
        emit IERC4906.BatchMetadataUpdate(0, type(uint256).max);
        uik.setRenderer(new StaticRenderer());
    }

    // --- built-in renderer --------------------------------------------------

    function test_TokenUriRevertsForUnknownToken() public {
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, USER_ID));
        uik.tokenURI(USER_ID);
    }

    function test_TokenUriIsBase64DataUri() public {
        _bindAlice();
        assertTrue(_startsWithDataUri(uik.tokenURI(USER_ID)));
    }

    /// @dev Decoded and `JSON.parse`d off-chain, so malformed output fails rather than passing a
    ///      substring check.
    function test_TokenUriDecodesToValidJson() public {
        _bindAlice();
        vm.warp(1_700_000_000);

        string memory json = _decodeTokenURI(uik.tokenURI(USER_ID));

        assertEq(vm.parseJsonString(json, ".name"), "@octocat");
        assertEq(vm.parseJsonString(json, ".image"), "https://avatars.githubusercontent.com/u/583231");
        assertEq(vm.parseJsonString(json, ".external_url"), "https://github.com/octocat");
        assertGt(bytes(vm.parseJsonString(json, ".description")).length, 0);
    }

    function test_TokenUriCarriesAttributes() public {
        vm.warp(1_700_000_000);
        _bindAlice();

        string memory json = _decodeTokenURI(uik.tokenURI(USER_ID));

        assertEq(vm.parseJsonString(json, ".trait_github_user_id"), "583231");
        assertEq(vm.parseJsonString(json, ".trait_login_at_binding"), "octocat");
        assertEq(vm.parseJsonString(json, ".trait_bound_wallet"), "0x1111111111111111111111111111111111111111");
        assertEq(vm.parseJsonString(json, ".trait_bound_at"), "1700000000");
    }

    function test_TokenUriTracksRebinding() public {
        vm.warp(1_700_000_000);
        _bindAlice();

        vm.warp(1_800_000_000);
        _rebindToBob();

        string memory json = _decodeTokenURI(uik.tokenURI(USER_ID));

        assertEq(vm.parseJsonString(json, ".name"), "@octocat-two");
        assertEq(vm.parseJsonString(json, ".external_url"), "https://github.com/octocat-two");
        assertEq(vm.parseJsonString(json, ".trait_bound_wallet"), "0x2222222222222222222222222222222222222222");
        assertEq(vm.parseJsonString(json, ".trait_bound_at"), "1800000000");
        // The image is keyed by account id, so it survives a rename.
        assertEq(vm.parseJsonString(json, ".image"), "https://avatars.githubusercontent.com/u/583231");
    }

    /// forge-config: default.fuzz.runs = 48
    function testFuzz_TokenUriIsAlwaysValidJson(uint64 userId, uint64 boundAt) public {
        vm.assume(userId != 0);

        Fixture memory f = _fixture("sample-jwt.json", uint256(userId), alice, ATTESTATION_REPO_ID);
        verifier.addKey(f.kid, f.modulus, f.exponent);

        // Bound against the fixture's own window rather than a fixed ceiling. Anything past `exp`
        // is just an expired proof, which says nothing about how metadata renders.
        uint256 timestamp = bound(uint256(boundAt), f.nbf + 1, f.exp);
        vm.warp(timestamp);

        uik.register(f.kid, f.headerB64, f.payloadB64, f.signature, uint256(userId), alice, f.login);

        string memory json = _decodeTokenURI(uik.tokenURI(uint256(userId)));
        assertEq(vm.parseJsonString(json, ".trait_github_user_id"), vm.toString(uint256(userId)));
        assertEq(vm.parseJsonString(json, ".trait_bound_at"), vm.toString(timestamp));
    }

    // --- swappable renderer -------------------------------------------------

    function test_RendererDefaultsToUnset() public view {
        assertEq(address(uik.renderer()), address(0));
        assertFalse(uik.rendererFrozen());
    }

    function test_SetRendererReplacesOutput() public {
        _bindAlice();
        uik.setRenderer(new StaticRenderer());

        assertEq(uik.tokenURI(USER_ID), "custom://octocat");
    }

    function test_SetRendererEmitsRendererSet() public {
        ITokenRenderer next = new StaticRenderer();

        vm.expectEmit(true, false, false, false);
        emit UIK.RendererSet(address(next));
        uik.setRenderer(next);

        assertEq(address(uik.renderer()), address(next));
    }

    function test_RendererReceivesBoundState() public {
        vm.warp(1_700_000_000);
        _bindAlice();

        uik.setRenderer(new EchoRenderer());

        assertEq(uik.tokenURI(USER_ID), "echo://583231/0x1111111111111111111111111111111111111111/octocat/1700000000");
    }

    /// @dev A renderer that writes state cannot be reached through a staticcall, so it must fall
    ///      back rather than make every token's metadata revert.
    function test_StateWritingRendererFallsBackToBuiltIn() public {
        _bindAlice();
        uik.setRenderer(ITokenRenderer(address(new StatefulRenderer())));

        assertTrue(_startsWithDataUri(uik.tokenURI(USER_ID)));
    }

    function test_ClearingRendererRestoresBuiltIn() public {
        _bindAlice();
        uik.setRenderer(new StaticRenderer());
        assertEq(uik.tokenURI(USER_ID), "custom://octocat");

        uik.setRenderer(ITokenRenderer(address(0)));
        assertTrue(_startsWithDataUri(uik.tokenURI(USER_ID)));
    }

    /// @dev A faulty renderer must degrade the display, never break metadata for every token.
    function test_RevertingRendererFallsBackToBuiltIn() public {
        _bindAlice();
        uik.setRenderer(new RevertingRenderer());

        assertTrue(_startsWithDataUri(uik.tokenURI(USER_ID)));
    }

    function test_GasBurningRendererFallsBackToBuiltIn() public {
        _bindAlice();
        uik.setRenderer(new GasBurningRenderer());

        assertTrue(_startsWithDataUri(uik.tokenURI{gas: 30_000_000}(USER_ID)));
    }

    /// @dev An address with no code returns empty data, which decodes as a zero-length string
    ///      rather than reverting. Pinned so the behaviour is deliberate.
    function test_RendererWithoutCodeFallsBackToBuiltIn() public {
        _bindAlice();
        uik.setRenderer(ITokenRenderer(address(0xDEAD)));

        assertTrue(_startsWithDataUri(uik.tokenURI(USER_ID)));
    }

    function test_SetRendererOnlyOwner() public {
        // Deployed before the expectation so the constructor call does not consume it.
        ITokenRenderer next = new StaticRenderer();

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        uik.setRenderer(next);
    }

    // --- freezing -----------------------------------------------------------

    function test_FreezeRendererEmits() public {
        vm.expectEmit(false, false, false, true);
        emit UIK.RendererFrozen();
        uik.freezeRenderer();

        assertTrue(uik.rendererFrozen());
    }

    function test_FreezeRendererBlocksFurtherChanges() public {
        uik.setRenderer(new StaticRenderer());
        uik.freezeRenderer();

        ITokenRenderer next = new StaticRenderer();

        vm.expectRevert(UIK.RendererIsFrozen.selector);
        uik.setRenderer(next);
    }

    function test_FreezeRendererKeepsCurrentRendererLive() public {
        _bindAlice();
        uik.setRenderer(new StaticRenderer());
        uik.freezeRenderer();

        assertEq(uik.tokenURI(USER_ID), "custom://octocat");
    }

    function test_FreezeRendererOnlyOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        uik.freezeRenderer();
    }

    function test_FreezeIsIdempotent() public {
        uik.freezeRenderer();
        uik.freezeRenderer();
        assertTrue(uik.rendererFrozen());
    }

    /// @dev The renderer freeze must not touch the attestation source, which still has to be
    ///      rotatable when GitHub changes the workflow ref.
    function test_FreezeRendererLeavesAttestationSourceMutable() public {
        uik.freezeRenderer();

        uik.setAttestationRepoId(42);
        uik.setJobWorkflowRef("owner/repo/.github/workflows/x.yml@refs/heads/main");

        assertEq(uik.attestationRepoId(), 42);
    }

    /// @dev The renderer owner can change what a token looks like and nothing else.
    function test_RendererAuthorityCannotMoveIdentity() public {
        _bindAlice();
        uik.setRenderer(new StaticRenderer());

        assertEq(uik.ownerOf(USER_ID), alice);
        assertEq(uik.identityOf(USER_ID).githubUserId, USER_ID);
    }
}
