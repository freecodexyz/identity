// src/ITokenRenderer.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title ITokenRenderer
 * @notice Pluggable metadata renderer for {UIK}.
 *
 * @dev Renderers are stateless with respect to the token: everything they need is passed in, so a
 *      renderer never calls back into {UIK}. Implementations must not revert on well-formed input;
 *      {UIK} falls back to its built-in renderer when one does, which degrades the display rather
 *      than bricking metadata for every token.
 */
interface ITokenRenderer {
    /**
     * @notice Returns the `tokenURI` for a bound identity.
     *
     * @param tokenId The GitHub account id, which is also the token id.
     * @param wallet The wallet the identity is currently bound to.
     * @param login The GitHub login recorded at the most recent binding. Renameable, display only.
     * @param boundAt The block timestamp of the most recent binding.
     */
    function render(uint256 tokenId, address wallet, string calldata login, uint64 boundAt)
        external
        view
        returns (string memory);
}
