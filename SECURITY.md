# Security Policy

## Reporting a vulnerability

**Email <paoloanzn@gmail.com>. Do not open an issue, a pull request, or a discussion.**

Never disclose a vulnerability publicly before it has been fixed. That includes this repository's issue tracker, pull requests, forks, commit messages, and anywhere else public — social media, chat groups, write-ups, and conference talks included.

A public report on this codebase is not a disclosure of a theoretical weakness. `UIK` binds real GitHub accounts to real wallets, and anything that lets one account's identity be minted to an address that account does not control is directly exploitable the moment it is known.

You will get a reply confirming receipt. Please allow time for a fix before considering any further disclosure, and coordinate the timing in that thread.

## What to include

Whatever you have. The more of this the better:

- the contract and file, and the commit or deployed address it applies to
- what an attacker gains, and what they need in order to do it
- the smallest reproduction you can manage, ideally a failing Foundry test
- the chain and transaction hash, if you observed it against a live deployment

## Scope

Covered by this policy:

- `src/` — the contracts, including anything that lets a proof bind an identity to the wrong wallet, lets the claim matcher be bypassed, lets the verifier accept a JWT it should reject, or lets renderer authority reach beyond display
- `.github/workflows/register.yml` — the attestation workflow pinned on-chain, including anything that changes which account or which address a proof ends up carrying
- `.github/workflows/sync-github-keys.yml` and `sync-github-keys.sh` — anything that could get a signing key GitHub does not publish into the verifier, or remove one it does
- `bin/identity` and `tools/` — anything that leaks the deployer key or misdirects a deployment

Not covered, and deliberate rather than accidental:

- **The RSA private key in `test/fixtures/load-fixture.mjs`.** It is committed on purpose so the JWT fixtures are reproducible. It signs nothing outside this repository's test suite and is not a secret.
- **The issue tracker being public.** Registration is a public issue whose title is the wallet address, and that public attributability is the mechanism, not a leak. See the README.
- **Anyone being able to trigger the attestation workflow.** That is the point: proving an identity must not require permission. A proof still binds only to the address the opener chose.
- **GitHub itself** — the OIDC issuer, the JWKS endpoint, the Actions platform. Report those to [GitHub's program](https://bounty.github.com).

## Supported versions

The `main` branch and whatever is currently deployed. There are no maintained release branches.
