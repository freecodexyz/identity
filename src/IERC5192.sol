// src/IERC5192.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title IERC5192
 * @notice Minimal soulbound token interface, as defined in ERC-5192.
 *
 * @dev Interface id `0xb45a3c0e`. OpenZeppelin does not ship this interface, so it is declared here.
 *      Clients use it to hide transfer controls instead of offering an action that always reverts.
 */
interface IERC5192 {
    /// @notice Emitted when a token becomes locked, that is, non-transferable.
    event Locked(uint256 tokenId);

    /// @notice Emitted when a token becomes unlocked, that is, transferable.
    event Unlocked(uint256 tokenId);

    /**
     * @notice Returns whether `tokenId` is non-transferable.
     *
     * @dev Reverts when `tokenId` does not exist.
     */
    function locked(uint256 tokenId) external view returns (bool);
}
