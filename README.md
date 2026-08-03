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

## Contracts

- `src/UIK.sol`: soulbound identity ERC-721. Token id is the GitHub account id.
- `src/GithubOidcVerifier.sol`: mirrors GitHub's JWKS and verifies the RSA signature, issuer, and active window.
- `src/IJwtVerifier.sol`: the verifier boundary `UIK` consumes.
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
