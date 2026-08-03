// src/JsonClaim.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title JsonClaim
 * @notice Byte-oriented assertions over a compact JWT JSON payload.
 *
 * @dev This library never parses JSON. It searches for the exact byte sequence `"<key>":"<value>"`.
 *      That is sound only because a JSON encoder escapes `"` inside string values as `\"`, so an
 *      attacker-controlled claim value (a repository name, a branch, a workflow name) cannot contain
 *      the unescaped quote needed to forge another claim. Any change to the matching strategy must
 *      preserve that property; see the injection regression tests.
 */
library JsonClaim {
    error ClaimMissing(string claim);
    error ClaimMismatch(string claim);

    /**
     * @dev Returns the index of the first occurrence of `needle` in `hay`, or `-1` when absent.
     */
    function indexOf(bytes memory hay, bytes memory needle) internal pure returns (int256) {
        if (needle.length == 0 || hay.length < needle.length) return -1;

        // this is O(n*m) decent enough
        for (uint256 i = 0; i <= hay.length - needle.length; i++) {
            bool match_ = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    match_ = false;
                    break;
                }
            }
            // safe to cast uint256 -> int256
            // forge-lint: disable-next-line(unsafe-typecast)
            if (match_) return int256(i);
        }
        return -1;
    }

    /**
     * @dev Asserts the bytes for `"<key>":"<expectedValue>"` are present in `payload`.
     *
     * Requirements:
     *
     * - `payload` must contain `key`.
     * - The value of `key` must equal `expectedValue`.
     */
    function requireStringClaim(bytes memory payload, string memory key, string memory expectedValue) internal pure {
        bytes memory needle = abi.encodePacked('"', bytes(key), '":"', bytes(expectedValue), '"');
        if (indexOf(payload, needle) >= 0) return;

        bytes memory claim = abi.encodePacked('"', bytes(key), '":');
        if (indexOf(payload, claim) < 0) revert ClaimMissing(key);

        revert ClaimMismatch(key);
    }
}
