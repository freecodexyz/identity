// src/UIK.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {IERC4906} from "@openzeppelin/contracts/interfaces/IERC4906.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {IERC5192} from "./IERC5192.sol";
import {IJwtVerifier} from "./IJwtVerifier.sol";
import {ITokenRenderer} from "./ITokenRenderer.sol";
import {JsonClaim} from "./JsonClaim.sol";

/**
 * @title UIK
 * @notice User Identity Key: a soulbound ERC-721 binding a GitHub account to a wallet address.
 *
 * @dev The token id is the GitHub account's numeric id, which is immutable and never recycled.
 *      The login is recorded for display only, because logins are renameable and recyclable.
 *
 *      # Proof model
 *
 *      A GitHub Actions OIDC token is signed by GitHub and cannot be forged. But GitHub will sign
 *      `actor_id: alice` next to any `aud` the requesting workflow asks for, so the security of the
 *      whole scheme reduces to a single question:
 *
 *          who controlled the workflow code that requested the token?
 *
 *      This contract implements the "attestation repository" answer. Registration proofs are only
 *      accepted from one specific workflow file, in one specific repository, triggered by one
 *      specific event:
 *
 *      - `repository_id` must equal {attestationRepoId}. Without this, anyone could invoke the
 *        attestation workflow as a reusable workflow from their own repository and choose `aud`.
 *      - `job_workflow_ref` must equal {jobWorkflowRef}. This pins the exact file and ref that
 *        requested the token, so the attestation repository's owner cannot silently rewrite it;
 *        rotating the workflow requires an owner transaction on this contract.
 *      - `event_name` must equal {expectedEventName} (`issues`). The `issues` event runs in the
 *        attestation repository's context while setting `actor_id` to the *external* account that
 *        opened the issue, which is what lets a user prove their identity without granting any
 *        permission or modifying any repository of their own.
 *      - `aud` must equal the wallet being bound. The attestation workflow reads that address from
 *        the issue title, so it is chosen by the account holder through GitHub and is publicly
 *        attributable, never supplied by a backend.
 *
 *      Dropping any one of those four checks reintroduces impersonation. In particular
 *      `actor_id` alone proves nothing: events such as `issues`, `issue_comment`, `watch` and
 *      `fork` let any account become the actor of a run in a repository it does not control.
 *
 *      # Rebinding
 *
 *      A later proof for the same account moves the token to the new wallet without the current
 *      holder's consent. That is intentional: the token means "the wallet currently controlled by
 *      GitHub account N", so it must survive key rotation, and it is the recovery path if a user is
 *      tricked into attesting an address they do not own. Only the account itself can rebind,
 *      because only it can produce a proof carrying its `actor_id`.
 *
 *      # Metadata
 *
 *      Metadata is served fully on-chain as a base64 data URI, so what a wallet displays rests on
 *      the same guarantees as the binding itself. It is dynamic, because rebinding changes the
 *      holder, the timestamp and possibly the login, so this contract implements ERC-4906 to tell
 *      indexers when to refresh. Rendering is delegated to a swappable {ITokenRenderer}; the built-in
 *      renderer is used whenever none is set or a renderer reverts. That authority is display-only
 *      and can be given up permanently through {freezeRenderer}.
 */
contract UIK is IERC4906, IERC5192, ERC721, Ownable2Step {
    string private constant _EXPECTED_EVENT = "issues";

    /// @dev Avatars are addressable by account id, so the image needs no stored value.
    string private constant _AVATAR_BASE_URI = "https://avatars.githubusercontent.com/u/";
    /// @dev GitHub has no id-addressable profile page, so the human link needs the login.
    string private constant _PROFILE_BASE_URI = "https://github.com/";

    /// @dev GitHub logins are at most 39 characters of `[A-Za-z0-9-]`.
    uint256 private constant _MAX_LOGIN_LENGTH = 39;

    /**
     * @dev ERC-4906 declares only events, so its identifier is not derivable with
     *      `type(IERC4906).interfaceId`, which would be zero. It is fixed by the ERC.
     */
    bytes4 private constant _ERC4906_INTERFACE_ID = bytes4(0x49064906);
    bytes4 private constant _ERC5192_INTERFACE_ID = bytes4(0xb45a3c0e);

    struct Identity {
        uint64 githubUserId; // == tokenId -> kept for clarity
        uint64 boundAt; // block.timestamp of the most recent binding -> truncated at uint64
        string login; // GitHub login at the most recent binding -> renameable, display only
    }

    event IdentityBound(
        uint256 indexed githubUserId, address indexed wallet, address indexed previousWallet, uint64 boundAt
    );
    event AttestationRepoSet(uint64 indexed githubRepoId);
    event JobWorkflowRefSet(string jobWorkflowRef);
    event RendererSet(address indexed renderer);
    event RendererFrozen();

    error AttestationSourceNotConfigured();
    error InvalidGithubUserId(uint256 githubUserId);
    error InvalidLogin();
    error AlreadyBound(uint256 githubUserId, address wallet);
    error ProofAlreadyUsed(bytes32 proofId);
    error NotRegistered(uint256 tokenId);
    error NonTransferable();
    error RendererIsFrozen();

    IJwtVerifier private immutable _jwt;

    uint64 private _attestationRepoId;
    string private _jobWorkflowRef;

    ITokenRenderer private _renderer;
    bool private _rendererFrozen;

    mapping(uint256 tokenId => Identity identity) private _identities;
    mapping(bytes32 proofId => bool used) private _usedProofs;

    /**
     * @dev Sets the initial owner and the JWT verifier. The attestation source must still be
     *      configured through {setAttestationRepoId} and {setJobWorkflowRef} before any
     *      registration can succeed.
     */
    constructor(address initialOwner, IJwtVerifier jwt_) ERC721("User Identity Key", "UIK") Ownable(initialOwner) {
        _jwt = jwt_;
    }

    /**
     * @dev Binds `wallet` to the GitHub account `githubUserId` and mints or moves its UIK.
     *
     * Anyone may submit this call. The proof itself names its beneficiary through the `aud` claim,
     * so a relayer can pay the gas without being able to redirect the identity.
     *
     * `login` is not trusted from the caller; it is checked against the signed `actor` claim, which
     * avoids having to extract values from the payload.
     *
     * Requirements:
     *
     * - The attestation source must be configured.
     * - `kid`, `signature`, the issuer and the active window must satisfy {IJwtVerifier}.
     * - The payload must carry `aud`, `actor`, `actor_id`, `repository_id`, `event_name` and
     *   `job_workflow_ref` matching `wallet`, `login`, `githubUserId` and the configured
     *   attestation source.
     * - `login` must be a renderable GitHub login.
     * - The proof must not have been used before.
     * - `wallet` must not already hold this identity.
     *
     * Emits an {IdentityBound} event, plus {IERC5192-Locked} on first binding or
     * {IERC4906-MetadataUpdate} on a rebinding.
     */
    function register(
        bytes32 kid,
        bytes calldata headerB64,
        bytes calldata payloadB64,
        bytes calldata signature,
        uint256 githubUserId,
        address wallet,
        string calldata login
    ) external virtual {
        bytes memory payload = _jwt.verifyGithubOidc(kid, headerB64, payloadB64, signature);
        _verifyClaims(payload, githubUserId, wallet, login);
        _bind(githubUserId, wallet, login, proofIdOf(signature));
    }

    /**
     * @dev Returns the verifier this contract trusts for GitHub OIDC signatures.
     */
    function jwt() public view virtual returns (IJwtVerifier) {
        return _jwt;
    }

    /**
     * @dev Returns the GitHub repository id proofs must originate from.
     */
    function attestationRepoId() public view virtual returns (uint64) {
        return _attestationRepoId;
    }

    /**
     * @dev Returns the exact `job_workflow_ref` proofs must carry.
     */
    function jobWorkflowRef() public view virtual returns (string memory) {
        return _jobWorkflowRef;
    }

    /**
     * @dev Returns the GitHub Actions event name proofs must carry.
     */
    function expectedEventName() public pure virtual returns (string memory) {
        return _EXPECTED_EVENT;
    }

    /**
     * @dev Returns the active metadata renderer, or the zero address when the built-in renderer is
     *      in use.
     */
    function renderer() public view virtual returns (ITokenRenderer) {
        return _renderer;
    }

    /**
     * @dev Returns whether the renderer can still be changed.
     */
    function rendererFrozen() public view virtual returns (bool) {
        return _rendererFrozen;
    }

    /**
     * @dev Returns the UIK token id for a GitHub account id.
     */
    function tokenIdOf(uint64 githubUserId) public pure virtual returns (uint256) {
        return uint256(githubUserId);
    }

    /**
     * @dev Returns the replay key derived from a JWT signature.
     *
     * PKCS#1 v1.5 signing is deterministic, so a given OIDC token always hashes to the same value
     * and two distinct tokens cannot collide without breaking the signature scheme.
     */
    function proofIdOf(bytes calldata signature) public pure virtual returns (bytes32) {
        return keccak256(signature);
    }

    /**
     * @dev Returns whether a proof has already been consumed.
     */
    function isProofUsed(bytes32 proofId) public view virtual returns (bool) {
        return _usedProofs[proofId];
    }

    /**
     * @dev Returns identity metadata for `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must be registered.
     */
    function identityOf(uint256 tokenId) public view virtual returns (Identity memory) {
        if (_ownerOf(tokenId) == address(0)) revert NotRegistered(tokenId);
        return _identities[tokenId];
    }

    /**
     * @dev Returns the metadata URI for `tokenId`, rendered by {renderer} or by the built-in
     *      renderer when none is set.
     *
     * A renderer that reverts is treated as absent so a faulty deployment degrades the display
     * rather than breaking metadata for every token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        address wallet = _requireOwned(tokenId);

        ITokenRenderer renderer_ = _renderer;
        // A renderer set to an address with no code would make the high-level call revert before it
        // is attempted, which `try` does not catch. Check it here so a mistyped address degrades
        // like any other faulty renderer.
        if (address(renderer_) == address(0) || address(renderer_).code.length == 0) {
            return _defaultTokenURI(tokenId, wallet);
        }

        Identity memory identity = _identities[tokenId];
        try renderer_.render(tokenId, wallet, identity.login, identity.boundAt) returns (string memory uri) {
            return uri;
        } catch {
            return _defaultTokenURI(tokenId, wallet);
        }
    }

    /**
     * @inheritdoc IERC5192
     *
     * @dev Always true. An identity only ever moves through a fresh OIDC proof, never through a
     *      call a holder or operator can make.
     */
    function locked(uint256 tokenId) public view virtual returns (bool) {
        _requireOwned(tokenId);
        return true;
    }

    /**
     * @dev Advertises ERC-721, ERC-721 Metadata, ERC-4906 and ERC-5192.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, IERC165) returns (bool) {
        return interfaceId == _ERC4906_INTERFACE_ID || interfaceId == _ERC5192_INTERFACE_ID
            || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Sets the GitHub repository id proofs must originate from.
     *
     * Requirements:
     *
     * - The caller must be the contract owner.
     *
     * Emits an {AttestationRepoSet} event.
     */
    function setAttestationRepoId(uint64 githubRepoId) external virtual onlyOwner {
        _setAttestationRepoId(githubRepoId);
    }

    /**
     * @dev Sets the exact `job_workflow_ref` proofs must carry.
     *
     * Requirements:
     *
     * - The caller must be the contract owner.
     *
     * Emits a {JobWorkflowRefSet} event.
     */
    function setJobWorkflowRef(string calldata ref) external virtual onlyOwner {
        _setJobWorkflowRef(ref);
    }

    /**
     * @dev Sets the metadata renderer, or the zero address to return to the built-in renderer.
     *
     * This authority is display-only. It cannot mint, move, or unbind an identity.
     *
     * Requirements:
     *
     * - The caller must be the contract owner.
     * - The renderer must not be frozen.
     *
     * Emits a {RendererSet} and an {IERC4906-BatchMetadataUpdate} event.
     */
    function setRenderer(ITokenRenderer renderer_) external virtual onlyOwner {
        _setRenderer(renderer_);
    }

    /**
     * @dev Permanently gives up the ability to change the renderer.
     *
     * Preferred over renouncing ownership, which would also freeze the attestation source and so
     * prevent rotating the pinned workflow.
     *
     * Requirements:
     *
     * - The caller must be the contract owner.
     *
     * Emits a {RendererFrozen} event.
     */
    function freezeRenderer() external virtual onlyOwner {
        _freezeRenderer();
    }

    /**
     * @dev Single mutation choke point for the attestation repository id.
     *
     * Emits an {AttestationRepoSet} event.
     */
    function _setAttestationRepoId(uint64 githubRepoId) internal virtual {
        _attestationRepoId = githubRepoId;
        emit AttestationRepoSet(githubRepoId);
    }

    /**
     * @dev Single mutation choke point for the pinned workflow ref.
     *
     * Emits a {JobWorkflowRefSet} event.
     */
    function _setJobWorkflowRef(string memory ref) internal virtual {
        _jobWorkflowRef = ref;
        emit JobWorkflowRefSet(ref);
    }

    /**
     * @dev Single mutation choke point for the metadata renderer.
     *
     * Emits a {RendererSet} and an {IERC4906-BatchMetadataUpdate} event.
     */
    function _setRenderer(ITokenRenderer renderer_) internal virtual {
        if (_rendererFrozen) revert RendererIsFrozen();

        _renderer = renderer_;

        emit RendererSet(address(renderer_));
        // Swapping the renderer changes the metadata of every token that exists.
        emit BatchMetadataUpdate(0, type(uint256).max);
    }

    /**
     * @dev Single mutation choke point for the renderer freeze.
     *
     * Emits a {RendererFrozen} event.
     */
    function _freezeRenderer() internal virtual {
        _rendererFrozen = true;
        emit RendererFrozen();
    }

    /**
     * @dev Single mutation choke point for identity bindings. Mints on first binding and moves the
     *      existing token on any later one.
     *
     * Requirements:
     *
     * - `githubUserId` must be a non-zero GitHub account id that fits in `uint64`.
     * - `login` must be a renderable GitHub login.
     * - `proofId` must not have been consumed.
     * - `wallet` must differ from the current holder.
     *
     * Emits an {IdentityBound} event, plus {IERC5192-Locked} on first binding or
     * {IERC4906-MetadataUpdate} on a rebinding.
     */
    function _bind(uint256 githubUserId, address wallet, string memory login, bytes32 proofId) internal virtual {
        if (githubUserId == 0 || githubUserId > type(uint64).max) revert InvalidGithubUserId(githubUserId);
        if (wallet == address(0)) revert ERC721InvalidReceiver(address(0));
        if (_usedProofs[proofId]) revert ProofAlreadyUsed(proofId);

        address previousWallet = _ownerOf(githubUserId);
        if (previousWallet == wallet) revert AlreadyBound(githubUserId, wallet);

        _requireRenderableLogin(login);
        _usedProofs[proofId] = true;

        // A uint64 Unix timestamp remains valid far beyond any practical lifetime of this contract.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 boundAt = uint64(block.timestamp);
        _identities[githubUserId] = Identity({
            // casting is safe because githubUserId is bounded above.
            // forge-lint: disable-next-line(unsafe-typecast)
            githubUserId: uint64(githubUserId),
            boundAt: boundAt,
            login: login
        });

        emit IdentityBound(githubUserId, wallet, previousWallet, boundAt);

        if (previousWallet == address(0)) {
            _mint(wallet, githubUserId);
            // The Transfer from the zero address already prompts indexers to fetch metadata, so
            // only the soulbound signal is needed here.
            emit Locked(githubUserId);
        } else {
            // Proof-driven rebinding. `auth` is zero because the current holder's approval is
            // deliberately not consulted; the GitHub account, not the wallet, owns this identity.
            _update(wallet, githubUserId, address(0));
            // Holder, timestamp and login all just changed.
            emit MetadataUpdate(githubUserId);
        }
    }

    /**
     * @dev Reverts unless the payload proves that `wallet` was attested by `githubUserId`, using
     *      `login`, through the configured attestation workflow.
     */
    function _verifyClaims(bytes memory payload, uint256 githubUserId, address wallet, string memory login)
        internal
        view
        virtual
    {
        uint64 repoId = _attestationRepoId;
        string memory workflowRef = _jobWorkflowRef;
        if (repoId == 0 || bytes(workflowRef).length == 0) revert AttestationSourceNotConfigured();

        // The address the identity binds to. Chosen by the account holder through the issue title.
        JsonClaim.requireStringClaim(payload, "aud", Strings.toHexString(uint160(wallet), 20));
        // The GitHub account that opened the issue.
        JsonClaim.requireStringClaim(payload, "actor_id", Strings.toString(githubUserId));
        // Display only, but still proven rather than trusted from the caller.
        JsonClaim.requireStringClaim(payload, "actor", login);
        // Together these three pin the code that chose `aud` to the reviewed attestation workflow.
        JsonClaim.requireStringClaim(payload, "repository_id", Strings.toString(uint256(repoId)));
        JsonClaim.requireStringClaim(payload, "event_name", _EXPECTED_EVENT);
        JsonClaim.requireStringClaim(payload, "job_workflow_ref", workflowRef);
    }

    /**
     * @dev Reverts unless `login` is safe to interpolate into the metadata JSON.
     *
     * GitHub already restricts logins to at most 39 characters of `[A-Za-z0-9-]`, so this can only
     * fail if GitHub's own rules change. Checking it here turns that assumption into an invariant:
     * a login carrying a quote could otherwise inject attacker-chosen traits into the rendered
     * metadata. It can never affect a binding.
     */
    function _requireRenderableLogin(string memory login) internal pure virtual {
        bytes memory raw = bytes(login);
        if (raw.length == 0 || raw.length > _MAX_LOGIN_LENGTH) revert InvalidLogin();

        for (uint256 i = 0; i < raw.length; ++i) {
            uint8 c = uint8(raw[i]);
            bool allowed = (c >= 0x30 && c <= 0x39) // 0-9
                || (c >= 0x41 && c <= 0x5a) // A-Z
                || (c >= 0x61 && c <= 0x7a) // a-z
                || c == 0x2d; // -
            if (!allowed) revert InvalidLogin();
        }
    }

    /**
     * @dev Renders on-chain metadata as a base64 JSON data URI.
     *
     * The image is derived from the token id because GitHub serves avatars by account id. The
     * profile link needs the login because GitHub has no id-addressable profile page, and is
     * therefore only as current as the most recent binding.
     */
    function _defaultTokenURI(uint256 tokenId, address wallet) internal view virtual returns (string memory) {
        Identity memory identity = _identities[tokenId];
        string memory id = Strings.toString(tokenId);
        string memory login = identity.login;

        // Built in two halves. One long concatenation exhausts the stack once the optimizer is
        // enabled without via-ir, which would make the build configuration a trap for later.
        string memory head = string.concat(
            '{"name":"@',
            login,
            '","description":"User Identity Key. Proves that GitHub account ',
            id,
            ' controls this wallet, through a GitHub Actions OIDC attestation.","image":"',
            _AVATAR_BASE_URI,
            id,
            '","external_url":"',
            _PROFILE_BASE_URI,
            login,
            '"'
        );

        string memory attributes = string.concat(
            ',"attributes":[{"trait_type":"GitHub User ID","value":"',
            id,
            '"},{"trait_type":"Login At Binding","value":"',
            login,
            '"},{"trait_type":"Bound Wallet","value":"',
            Strings.toHexString(uint160(wallet), 20),
            '"},{"display_type":"date","trait_type":"Bound At","value":',
            Strings.toString(identity.boundAt),
            "}]}"
        );

        return string.concat("data:application/json;base64,", Base64.encode(bytes(string.concat(head, attributes))));
    }

    /**
     * @dev Blocks holder-initiated transfers.
     *
     * {ERC721} passes a non-zero `auth` for every transfer that originates from a token holder or
     * operator, and zero for mints and for the internal rebinding in {_bind}. Gating on `auth`
     * keeps a single choke point rather than overriding each public transfer alias.
     */
    function _update(address to, uint256 tokenId, address auth) internal virtual override returns (address) {
        if (auth != address(0)) revert NonTransferable();
        return super._update(to, tokenId, auth);
    }

    /**
     * @dev Blocks holder-initiated approvals.
     *
     * {ERC721-_update} clears approvals internally with a zero `auth`; every approval a holder or
     * operator can trigger passes a non-zero one.
     */
    function _approve(address to, uint256 tokenId, address auth, bool emitEvent) internal virtual override {
        if (auth != address(0)) revert NonTransferable();
        super._approve(to, tokenId, auth, emitEvent);
    }

    /**
     * @dev Blocks operator approvals. A soulbound token has nothing an operator could act on.
     */
    function _setApprovalForAll(address, address, bool) internal virtual override {
        revert NonTransferable();
    }
}
