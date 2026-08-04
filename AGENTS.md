# AGENTS.md

## Role

You are editing a Solidity smart-contract repository. Optimize for auditability, semantic consistency, and small override surfaces. Write code in the OpenZeppelin v5 style: private state, explicit invariants, custom errors, narrow interfaces, and tests that prove behavior.

## Scope

These rules apply to Solidity contracts, libraries, interfaces, scripts, and tests. When a deeper directory has its own `AGENTS.md`, follow the closest file for that subtree.

## Project Overview

- Project name: write it as `identity` in prose and commands.
- Purpose: EVM contracts that bind a GitHub account to a wallet address using a GitHub Actions OIDC proof.
- Repository shape: a single Foundry project at the repository root.
- Stack: Foundry, Solidity `^0.8.24`, OpenZeppelin Contracts and `forge-std` as git submodules under `lib/`.
- Core contract: `UIK`, a soulbound ERC-721 "User Identity Key" whose token id is the GitHub account's numeric id.
- `foundry.toml` sets `ffi = true` because the tests sign JWT fixtures through a Node generator.
- `foundry.toml` enables the optimizer with `via_ir = true`. Both are load-bearing: the legacy pipeline runs out of stack while building the metadata JSON, so turning via-ir off breaks the build rather than merely changing output.

## Commands

| Purpose | Command |
| --- | --- |
| Initialize submodules | `git submodule update --init --recursive` |
| Format check | `forge fmt --check` |
| Build with sizes | `forge build --sizes` |
| Tests | `forge test -vvv` |
| Gas report | `forge test --gas-report` |
| Regenerate one fixture by hand | `node test/fixtures/load-fixture.mjs test/fixtures/sample-jwt.json` |
| Preview a key sync without sending | `VERIFIER_ADDRESS=0x… RPC_URL=… DRY_RUN=true ./sync-github-keys.sh` |
| Check tooling and deployment | `./bin/identity doctor` |
| Deploy both contracts | `./bin/identity deploy --rpc-url …` |
| Inspect a deployment | `./bin/identity status` |

## Repository Structure

- `src/UIK.sol`: soulbound identity ERC-721, the T2 claim checks, and on-chain metadata.
- `src/GithubOidcVerifier.sol`: GitHub JWKS mirror, RSA signature, issuer, and active-window checks.
- `src/IJwtVerifier.sol`: verifier boundary consumed by `UIK`.
- `src/ITokenRenderer.sol`: swappable metadata renderer boundary.
- `src/IERC5192.sol`: minimal soulbound interface; OpenZeppelin does not ship one.
- `src/JsonClaim.sol`: byte-oriented JSON claim matcher.
- `test/OidcFixture.sol`: shared loader for generated OIDC fixtures and token URI decoding.
- `test/fixtures/load-fixture.mjs`: deterministic JWT generator invoked through `vm.ffi`.
- `test/fixtures/decode-token-uri.mjs`: decodes and `JSON.parse`s a token URI for assertions.
- `test/fixtures/*.json`: one file per scenario; negative cases are data, not code.
- `.github/workflows/register.yml`: the attestation workflow pinned on-chain by `UIK`.
- `.github/workflows/sync-github-keys.yml`: scheduled mirror of GitHub's JWKS into the verifier.
- `.github/workflows/test-contracts.yml`: `forge fmt --check`, `forge build --sizes`, `forge test -vvv`.
- `sync-github-keys.sh`: the key sync itself, driven by `cast`. Runnable locally against anvil.
- `bin/identity`: deployment helper CLI. Ruby 3.2, standard library only, no bundler.
- `tools/identity/`: its implementation. Deliberately not under `lib/`, which Foundry owns.
- `script/`: Foundry deploy scripts.
- `lib/`: git submodules. Do not edit directly.

## Architecture Boundaries

- `UIK.tokenIdOf(githubUserId)` is intentionally identity mapping; the token id is the GitHub account id. GitHub account ids and repository ids share a numeric range, so never mix the two id spaces in one ERC-721.
- Registration must verify all five claims together: `aud`, `actor_id`, `repository_id`, `event_name`, and `job_workflow_ref`. Dropping any one of them reintroduces impersonation. `actor_id` alone proves nothing, because events such as `issues`, `issue_comment`, `watch`, and `fork` let any account become the actor of a run in a repository it does not control.
- Preserve the issuer string exactly: `https://token.actions.githubusercontent.com`.
- `aud` is compared against `Strings.toHexString` of the wallet, so the attestation workflow must request a lowercase hex address as the audience.
- `register` is intentionally permissionless. The proof names its own beneficiary, so whoever submits it pays the gas without being able to redirect the identity. Never add an access check that ties the mint to `msg.sender`.
- Two keys live in this repository's secrets and they are not interchangeable. `FCF_KEY_SYNC_PRIVATE_KEY` owns the verifier and can mint trust in a forged JWT; `FCF_REGISTRAR_PRIVATE_KEY` only pays gas and holds no authority at all. Never collapse them into one.
- `register.yml` simulates with `cast call` before `cast send`. That is what keeps an already-registered account, an unsynced key or an expired token from costing gas, and it is why the registrar key is hard to grief.
- The kid derivation in `register.yml` and in `sync-github-keys.sh` must stay identical, `cast keccak` over the raw kid string. Nothing in the Foundry suite covers that seam: the fixtures use a padded-ASCII kid, so the two shell scripts only agree by construction.
- `JsonClaim` is sound only because a JSON encoder escapes `"` inside string values. Any change to the matching strategy must preserve that, and must keep the injection regression tests passing.
- `JsonClaim.indexOf` is inline assembly comparing a masked 32-byte word per position. It deliberately reads up to 31 bytes past the end of both arrays and masks them off, and it never writes; do not add the `memory-safe` annotation on the strength of that. It dominates `register` gas, so verify any edit differentially against the naive byte-at-a-time search before trusting it.
- GitHub JWKS `kid` values are stored on-chain as `keccak256(bytes(kid))` of the UTF-8 bytes; keep `sync-github-keys.sh` aligned with that.
- The verifier owner key used by the key sync is the highest-value secret in the system. It can add an arbitrary signing key, and therefore mint trust in a forged JWT for any account. Keep it dedicated to that job, and prefer a keeper role over the full owner if the contract ever gains one.
- The key sync must only ever follow `jwks_uri` back to the issuer's own origin. A tampered discovery document could otherwise redirect it to attacker-controlled keys.
- `MIN_KEYS` exists so a truncated or partial JWKS response cannot revoke the whole registry. Do not remove that floor to make a run succeed.
- Revoking a key GitHub has just dropped can reject an OIDC token that is still inside its validity window. That is acceptable because tokens are short-lived and a user can simply open another issue, but it is why revocation is switchable.
- The registry is not enumerable, so reconciliation reconstructs the set of known kids from `KeyAdded` logs. Adding a getter for that set would be a contract change; do not assume one exists.
- Any workflow in this repository that opens an issue also triggers `register.yml`. The parse step classifies a non-address title as `skip`, so it is harmless, but keep that in mind before adding issue-opening automation.
- `bin/identity` depends on nothing but Ruby's standard library, forge, cast and gh. Do not add a Gemfile; a contracts repository should not require a second package manager to deploy.
- The helper never writes a private key to `.identity.yml`. Keys come from the environment or a no-echo prompt on each run, which is what keeps that file safe to leave in a working tree.
- `Shell` always passes an argv array, never a command string, so a configured value can never become shell syntax. Keep it that way.
- The attestation repository id and `job_workflow_ref` are derived from the checkout rather than typed, because a hand-assembled ref is the easiest way to deploy a UIK that rejects every proof. `gh repo view` does not expose the numeric id, so it comes from `gh api repos/{owner}/{repo}`.
- `UIK` is soulbound. The only way a token moves is a fresh OIDC proof through `_bind`. Do not add a holder-initiated transfer path.
- `.github/workflows/register.yml` is pinned on-chain through `job_workflow_ref`. Renaming the file, moving it, or changing its ref requires an owner transaction on the deployed `UIK`. Treat edits to it as a protocol change.
- The issue title is untrusted input. Never interpolate `${{ github.event.issue.title }}` into a `run:` block; pass it through `env:` and validate it.
- The stored `login` is display-only and never an identifier. It is proven with `requireStringClaim` against the signed `actor` claim rather than parsed out of the payload, which keeps `JsonClaim` assert-only. Do not add a value-extracting parser to get it.
- `login` is interpolated into metadata JSON and into a profile URL, so `_requireRenderableLogin` must keep rejecting anything outside `[A-Za-z0-9-]`. Loosening it allows trait injection and URL manipulation.
- Metadata is served on-chain so that what a client displays rests on the same guarantees as the binding. Do not introduce an HTTP `_baseURI()`.
- The ERC-4906 interface id must stay hardcoded as `0x49064906`. `type(IERC4906).interfaceId` is zero, because the ERC declares only events.
- `tokenURI` is a view function and reaches a renderer through a staticcall. A renderer must be treated as untrusted: no code, a revert, gas exhaustion, and state writes all have to fall back to the built-in renderer rather than propagate.
- Renderer authority is display-only. It must never be able to mint, move, or unbind an identity. `freezeRenderer` gives it up permanently and deliberately leaves the attestation source mutable, because the pinned workflow still has to be rotatable.
- `_defaultTokenURI` builds its JSON in two halves on purpose, and the build depends on `via_ir`. Long `string.concat` chains are the stack pressure here; adding to one is what will break the build first.

## Solidity code rules

Use named imports only. Do not use wildcard imports. Prefix interfaces with `I`. Mark contracts `abstract` when they are not deployable as-is.

```solidity
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IVault {
    function totalAssets() external view returns (uint256);
}

abstract contract BaseVault is IVault {
    // Not deployable without a concrete asset/accounting implementation.
}
```

Keep every state variable `private` and underscore-prefixed. Expose reads through `public view virtual` getters. Do not make storage public just to get an auto-generated getter. Changes to state must go through functions that enforce events and invariants.

```solidity
mapping(address account => uint256 balance) private _balances;
uint256 private _totalSupply;

function balanceOf(address account) public view virtual returns (uint256) {
    return _balances[account];
}

function totalSupply() public view virtual returns (uint256) {
    return _totalSupply;
}
```

Use one mutation choke point per state concept. Public/external functions and convenience internals validate inputs, resolve `_msgSender()`, then delegate to one `internal virtual` function that performs the actual state change. Thin aliases are not virtual; override the underlying choke point instead.

```solidity
function transfer(address to, uint256 value) public virtual returns (bool) {
    address owner = _msgSender();
    _transfer(owner, to, value);
    return true;
}

function _transfer(address from, address to, uint256 value) internal {
    if (from == address(0)) revert ERC20InvalidSender(address(0));
    if (to == address(0)) revert ERC20InvalidReceiver(address(0));
    _update(from, to, value);
}

function _update(address from, address to, uint256 value) internal virtual {
    // All balance and supply mutation for this concept happens here.
}
```

In reusable contracts, do not read `msg.sender` or `msg.data` directly. Inherit/use `Context` and call `_msgSender()` and `_msgData()` so meta-transaction variants can override semantics.

```solidity
function deposit(uint256 assets) external virtual {
    address caller = _msgSender();
    _deposit(caller, caller, assets);
}
```

Use custom errors, not revert strings, for domain failures. Prefer ERC-6093 names for token errors such as `ERC20InvalidSender`, `ERC20InsufficientBalance`, and `ERC20InvalidSpender`. Revert on failure; do not return `false` unless an external standard forces the signature.

```solidity
error VaultZeroAssets();
error VaultUnauthorizedAccount(address account);

function _deposit(address caller, address receiver, uint256 assets) internal virtual {
    if (assets == 0) revert VaultZeroAssets();
    if (receiver == address(0)) revert ERC721InvalidReceiver(address(0));

    // Do not write: require(assets != 0, "zero assets");
}
```

Use `address(0)` deliberately. In token update choke points it is the sentinel for mint and burn, and standard `Transfer` events must encode mint/burn through zero-address endpoints. Boundary wrappers such as `_mint` and `_burn` still validate invalid zero-address usage.

```solidity
function _mint(address to, uint256 value) internal {
    if (to == address(0)) revert ERC20InvalidReceiver(address(0));
    _update(address(0), to, value);
}

function _burn(address from, uint256 value) internal {
    if (from == address(0)) revert ERC20InvalidSender(address(0));
    _update(from, address(0), value);
}
```

Emit events immediately after the state mutation they describe. New events should be past-tense, e.g. `OwnershipTransferred`, `TokensBurned`, `RoleGranted`. Index address, account, and role fields that off-chain systems filter on; leave amounts unindexed unless there is a clear indexing reason.

```solidity
event DepositCompleted(address indexed caller, address indexed receiver, uint256 assets);

function _deposit(address caller, address receiver, uint256 assets) internal virtual {
    _totalAssets += assets;
    emit DepositCompleted(caller, receiver, assets);
}
```

Cache storage reads when the value is used more than once. Every `unchecked` block must be locally justified by a preceding check or an adjacent comment proving overflow or underflow impossible.

```solidity
uint256 fromBalance = _balances[from];
if (fromBalance < value) {
    revert ERC20InsufficientBalance(from, fromBalance, value);
}
unchecked {
    // Safe because value <= fromBalance was checked above.
    _balances[from] = fromBalance - value;
}
```

Treat `type(uint256).max` allowance as infinite and do not decrement it. Use the overloaded-internal pattern for event escape hatches: the simple overload is non-virtual and delegates to the full virtual overload with explicit behavior flags such as `emitEvent`.

```solidity
function _approve(address owner, address spender, uint256 value) internal {
    _approve(owner, spender, value, true);
}

function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual {
    _allowances[owner][spender] = value;
    if (emitEvent) emit Approval(owner, spender, value);
}

function _spendAllowance(address owner, address spender, uint256 value) internal virtual {
    uint256 currentAllowance = allowance(owner, spender);
    if (currentAllowance < type(uint256).max) {
        if (currentAllowance < value) {
            revert ERC20InsufficientAllowance(spender, currentAllowance, value);
        }
        unchecked {
            // Safe because currentAllowance >= value was checked above.
            _approve(owner, spender, currentAllowance - value, false);
        }
    }
}
```

Use `SafeERC20` for every external ERC20 interaction. Do not call `transfer`, `transferFrom`, or `approve` raw on token contracts. Use `safeTransfer`, `safeTransferFrom`, `forceApprove`, `safeIncreaseAllowance`, and `safeDecreaseAllowance` as appropriate. Use `Address` helpers for low-level value transfers and function calls.

```solidity
using SafeERC20 for IERC20;

function pull(IERC20 token, address from, uint256 amount) external {
    token.safeTransferFrom(from, address(this), amount);
}

function sweepNative(address payable to, uint256 amount) external onlyOwner {
    Address.sendValue(to, amount);
}
```

For contracts with authority over funds, ownership, upgrades, or roles, prefer two-step ownership transfer or explicit `AccessControl` roles. Do not introduce single-step owner handoff for production authority paths.

```solidity
contract ManagedVault is Ownable2Step, AccessControl {
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    function harvest() external onlyRole(KEEPER_ROLE) {
        _harvest();
    }
}
```

For upgradeable contracts, use ERC-7201-style namespaced storage structs. Do not add top-level state variables to proxy implementations. Use `initializer`/`reinitializer`, `__Module_init` and `__Module_init_unchained`, and disable initializers on the implementation contract.

```solidity
/// @custom:storage-location erc7201:myapp.storage.Vault
struct VaultStorage {
    uint256 _totalAssets;
    mapping(address account => uint256 shares) _shares;
}

bytes32 private constant VaultStorageLocation =
    0x0f4c8d1c0d5bb98f9f2f2a5c6d97d65b1b18143a6b7397d2f5f7b6f0e6f9b500;

function _getVaultStorage() private pure returns (VaultStorage storage $) {
    assembly {
        $.slot := VaultStorageLocation
    }
}
```

## NatSpec

Every public, external, and `internal virtual` function must explain behavior. Use `@inheritdoc` when implementing an interface without semantic changes. Add `Requirements:` and `Emits:` blocks when a function has preconditions or events. If an alias should not be overridden, say which function should be overridden instead.

```solidity
/**
 * @dev Moves `assets` from `caller` into the vault and credits `receiver`.
 *
 * Requirements:
 *
 * - `assets` must be non-zero.
 * - `receiver` must not be the zero address.
 *
 * Emits a {DepositCompleted} event.
 */
function _deposit(address caller, address receiver, uint256 assets) internal virtual;

/// @inheritdoc IERC20
function balanceOf(address account) public view virtual returns (uint256);
```

## Tests

Add or update tests with every behavior change. Cover normal paths, reverts, event emission, and edge cases. Use fuzz tests for math-heavy code and invariant tests for state machines. Every bug fix must include a regression test that fails without the fix. Do not weaken tests to make a patch pass.

```solidity
function testFuzz_DepositCreditsReceiver(uint256 assets) public {
    assets = bound(assets, 1, type(uint128).max);
    vault.deposit(assets, receiver);
    assertEq(vault.balanceOf(receiver), assets);
}

function invariant_TotalSupplyEqualsAccountedBalances() public view {
    assertEq(vault.totalSupply(), handler.accountedBalances());
}
```

Keep tests deterministic and local. Do not reach GitHub, an RPC endpoint, or any other network from a test. The only external process a test may use is `test/fixtures/load-fixture.mjs` through `vm.ffi`.

Every claim check in `UIK` must have a negative test proving that removing it would allow impersonation, and the `JsonClaim` injection regressions must stay green.

## Boundaries

- Never edit, print, copy, infer, or commit real secrets: `.env`, `.env.*`, `PRIVATE_KEY`, GitHub tokens, RPC credentials, or wallet data. The RSA key in `test/fixtures/load-fixture.mjs` is a committed test-only key and is not a secret.
- Do not deploy, broadcast transactions, or call live RPCs unless the user explicitly asks.
- Do not change the GitHub OIDC issuer, workflow permissions, deployed contract addresses, or the pinned `job_workflow_ref` without explicit approval.
- Do not edit generated or dependency directories: `cache/`, `out/`, `broadcast/`, or `lib/`.
- Never replace Foundry with another contract toolchain without explicit user approval.

## Do not

Do not use wildcard imports, public state variables, raw `msg.sender` in reusable code, `require(..., "string")` for domain errors, raw ERC20 calls, unexplained `unchecked`, pre-mutation events, single-step ownership transfer for production authority, top-level storage in upgradeable implementations, or multiple override points for the same state transition.
