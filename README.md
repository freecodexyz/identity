<div>
    <img src="assets/fcf-canvas-landscape.png" />
</div>

# identity

Smart contracts that bind a GitHub account to a wallet address, with no repository of your own to modify.

[Website](https://freecodefund.xyz) · [Docs](https://docs.freecodefund.xyz) · [X](https://x.com/freecodexyz)

At the foundation is the **User Identity Key** (**UIK**), a soulbound ERC-721 whose token id is the GitHub account's numeric id. A UIK can only be minted from a GitHub Actions OIDC proof, creating a public, cryptographically verifiable link between a GitHub account and a wallet.

Where a repository identity proves _who owns this code_, a user identity proves _who this developer is_. It is the primitive underneath contributor reputation, payouts to people rather than projects, and any protocol action that should be attributable to a human.

## Registering

One click. No repository to fork, no file to commit, no app to install, no scope to grant, no gas to pay.

1. Open an issue on this repository whose **title is your wallet address and nothing else**.
2. The attestation workflow proves your GitHub identity and submits the proof.
3. The workflow comments the transaction hash and closes the issue.

Opening another issue with a different address rebinds the identity to the new wallet. That is the recovery path for a rotated or lost key, and the reason a mistaken registration is never permanent.

## How it works

A GitHub Actions OIDC token is signed by GitHub and cannot be forged. But GitHub will sign `actor_id: alice` next to whatever `aud` the requesting workflow asks for, so the entire security of the scheme reduces to one question:

> who controlled the workflow code that requested the token?

The `issues` event is the key. It runs in **this** repository's context while setting `actor_id` to the **external** account that opened the issue. That is what removes every requirement from the person registering. It is also, in the wrong hands, an impersonation primitive — so `UIK` pins the answer to the question above on-chain:

| Claim | Pinned to | Without it |
| --- | --- | --- |
| `repository_id` | this repository | anyone could invoke the workflow as a reusable workflow from their own repo and choose the audience |
| `job_workflow_ref` | `.github/workflows/register.yml` at its ref | rewriting the workflow would be enough to mint anyone's identity to any address |
| `event_name` | `issues` | widens the trigger surface beyond what was analysed |
| `actor_id` | the account being registered | no identity is proven at all |
| `aud` | the wallet being bound | the proof could be redirected to another address |

The address comes from the **issue title**, which is publicly and permanently attributable to the account that opened it. No backend chooses it, and none can substitute it. Changing the pinned workflow requires an owner transaction against the deployed contract, so the code that mints identities cannot be swapped silently.

Because the proof names its own beneficiary through `aud`, `register` is permissionless: a relayer can pay the gas without being able to redirect the identity, and anyone can broadcast a proof they hold.

## Metadata

Metadata is served fully on-chain as a base64 `data:` URI, so what a wallet displays rests on the same guarantees as the binding itself rather than on a server that could say anything.

```json
{
  "name": "@octocat",
  "description": "User Identity Key. Proves that GitHub account 583231 controls this wallet, through a GitHub Actions OIDC attestation.",
  "image": "https://avatars.githubusercontent.com/u/583231",
  "external_url": "https://github.com/octocat",
  "attributes": [
    { "trait_type": "GitHub User ID", "value": "583231" },
    { "trait_type": "Login At Binding", "value": "octocat" },
    { "trait_type": "Bound Wallet", "value": "0x1111111111111111111111111111111111111111" },
    { "display_type": "date", "trait_type": "Bound At", "value": 1754000000 }
  ]
}
```

The image needs no stored value: GitHub serves avatars by account id, which is the token id. The login is recorded only for the name and the profile link, because GitHub has no id-addressable profile page — it is proven against the signed `actor` claim, refreshed on every rebinding, and never used as an identifier.

Two extensions matter here:

- **ERC-4906.** Rebinding changes the holder, the timestamp and possibly the login, so the contract emits `MetadataUpdate` to stop marketplaces serving a stale render forever.
- **ERC-5192.** The token reports `locked() == true`, so clients hide transfer controls instead of offering an action that always reverts.

Rendering is delegated to a swappable `ITokenRenderer`, falling back to the built-in renderer whenever none is set or a renderer misbehaves. That authority is display-only — it can never mint, move, or unbind an identity — and it can be given up permanently with `freezeRenderer()`, which deliberately leaves the attestation source rotatable.

## Contracts

- `src/UIK.sol`: soulbound identity ERC-721. Token id is the GitHub account id.
- `src/GithubOidcVerifier.sol`: mirrors GitHub's JWKS and verifies the RSA signature, issuer, and active window.
- `src/IJwtVerifier.sol`: the verifier boundary `UIK` consumes.
- `src/ITokenRenderer.sol`: the swappable metadata renderer boundary.
- `src/IERC5192.sol`: minimal soulbound interface.
- `src/JsonClaim.sol`: byte-oriented JSON claim matcher.

## Development

```shell
git submodule update --init --recursive
forge fmt --check
forge build --sizes
forge test -vvv
```

Tests sign real RSA JWTs through `test/fixtures/load-fixture.mjs` under `vm.ffi`, so Node is required. Every negative case is a JSON fixture rather than a hand-crafted token.

## Deploying

```shell
PRIVATE_KEY=... forge script script/DeployGithubOidcVerifier.s.sol --rpc-url "$RPC_URL" --broadcast

PRIVATE_KEY=... \
JWT_VERIFIER_ADDRESS=0x... \
ATTESTATION_REPO_ID=... \
JOB_WORKFLOW_REF="freecodexyz/identity/.github/workflows/register.yml@refs/heads/main" \
  forge script script/DeployUIK.s.sol --rpc-url "$RPC_URL" --broadcast
```

The verifier owner then mirrors GitHub's active signing keys with `addKey`, and rotates them with `revokeKey` as GitHub rotates its JWKS.
