// src/UIK.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {IJwtVerifier} from "./IJwtVerifier.sol";
import {JsonClaim} from "./JsonClaim.sol";

/**
 * @title UIK
 * @notice User Identity Key: a soulbound ERC-721 binding a GitHub account to a wallet address.
 *
 * @dev The token id is the GitHub account's numeric id, which is immutable and never recycled.
 *      Logins are renameable and are deliberately not stored.
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
 */
contract UIK is ERC721, Ownable2Step {
    string private constant _EXPECTED_EVENT = "issues";

    struct Identity {
        uint64 githubUserId; // == tokenId -> kept for clarity
        uint64 boundAt; // block.timestamp of the most recent binding -> truncated at uint64
    }

    event IdentityBound(
        uint256 indexed githubUserId, address indexed wallet, address indexed previousWallet, uint64 boundAt
    );
    event AttestationRepoSet(uint64 indexed githubRepoId);
    event JobWorkflowRefSet(string jobWorkflowRef);

    error AttestationSourceNotConfigured();
    error InvalidGithubUserId(uint256 githubUserId);
    error AlreadyBound(uint256 githubUserId, address wallet);
    error ProofAlreadyUsed(bytes32 proofId);
    error NotRegistered(uint256 tokenId);
    error NonTransferable();

    IJwtVerifier private immutable _jwt;

    uint64 private _attestationRepoId;
    string private _jobWorkflowRef;

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
     * Requirements:
     *
     * - The attestation source must be configured.
     * - `kid`, `signature`, the issuer and the active window must satisfy {IJwtVerifier}.
     * - The payload must carry `aud`, `actor_id`, `repository_id`, `event_name` and
     *   `job_workflow_ref` matching `wallet`, `githubUserId` and the configured attestation source.
     * - The proof must not have been used before.
     * - `wallet` must not already hold this identity.
     *
     * Emits an {IdentityBound} event.
     */
    function register(
        bytes32 kid,
        bytes calldata headerB64,
        bytes calldata payloadB64,
        bytes calldata signature,
        uint256 githubUserId,
        address wallet
    ) external virtual {
        bytes memory payload = _jwt.verifyGithubOidc(kid, headerB64, payloadB64, signature);
        _verifyClaims(payload, githubUserId, wallet);
        _bind(githubUserId, wallet, proofIdOf(signature));
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
     * @dev Single mutation choke point for identity bindings. Mints on first binding and moves the
     *      existing token on any later one.
     *
     * Requirements:
     *
     * - `githubUserId` must be a non-zero GitHub account id that fits in `uint64`.
     * - `proofId` must not have been consumed.
     * - `wallet` must differ from the current holder.
     *
     * Emits an {IdentityBound} event.
     */
    function _bind(uint256 githubUserId, address wallet, bytes32 proofId) internal virtual {
        if (githubUserId == 0 || githubUserId > type(uint64).max) revert InvalidGithubUserId(githubUserId);
        if (wallet == address(0)) revert ERC721InvalidReceiver(address(0));
        if (_usedProofs[proofId]) revert ProofAlreadyUsed(proofId);

        address previousWallet = _ownerOf(githubUserId);
        if (previousWallet == wallet) revert AlreadyBound(githubUserId, wallet);

        _usedProofs[proofId] = true;

        // A uint64 Unix timestamp remains valid far beyond any practical lifetime of this contract.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 boundAt = uint64(block.timestamp);
        _identities[githubUserId] = Identity({
            // casting is safe because githubUserId is bounded above.
            // forge-lint: disable-next-line(unsafe-typecast)
            githubUserId: uint64(githubUserId),
            boundAt: boundAt
        });

        emit IdentityBound(githubUserId, wallet, previousWallet, boundAt);

        if (previousWallet == address(0)) {
            _mint(wallet, githubUserId);
        } else {
            // Proof-driven rebinding. `auth` is zero because the current holder's approval is
            // deliberately not consulted; the GitHub account, not the wallet, owns this identity.
            _update(wallet, githubUserId, address(0));
        }
    }

    /**
     * @dev Reverts unless the payload proves that `wallet` was attested by `githubUserId` through
     *      the configured attestation workflow.
     */
    function _verifyClaims(bytes memory payload, uint256 githubUserId, address wallet) internal view virtual {
        uint64 repoId = _attestationRepoId;
        string memory workflowRef = _jobWorkflowRef;
        if (repoId == 0 || bytes(workflowRef).length == 0) revert AttestationSourceNotConfigured();

        // The address the identity binds to. Chosen by the account holder through the issue title.
        JsonClaim.requireStringClaim(payload, "aud", Strings.toHexString(uint160(wallet), 20));
        // The GitHub account that opened the issue.
        JsonClaim.requireStringClaim(payload, "actor_id", Strings.toString(githubUserId));
        // Together these three pin the code that chose `aud` to the reviewed attestation workflow.
        JsonClaim.requireStringClaim(payload, "repository_id", Strings.toString(uint256(repoId)));
        JsonClaim.requireStringClaim(payload, "event_name", _EXPECTED_EVENT);
        JsonClaim.requireStringClaim(payload, "job_workflow_ref", workflowRef);
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
