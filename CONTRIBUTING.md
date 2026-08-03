# Contributing

This repository accepts **bug reports and security reports only**.

It is not open to feature requests, refactors, documentation rewrites, or unsolicited pull requests. Changes to the contracts alter what a deployed identity proof means, so they go through the maintainer rather than through an open contribution process. A pull request that was not asked for will be closed without review.

## Reporting a security vulnerability

**Email [paoloanzn@gmail.com](mailto:paoloanzn@gmail.com). Do not open an issue, a pull request, or a discussion.**

Never disclose a vulnerability publicly before it has been fixed. That includes this repository's issue tracker, pull requests, forks, commit messages, and anywhere else public — social media, chat groups, write-ups, and conference talks included. A public report on this codebase is not a disclosure of a theoretical weakness: `UIK` binds real GitHub accounts to real wallets, and anything that lets one account's identity be minted to another party's address is directly exploitable the moment it is known.

Please include whatever you have:

- the contract and file, and the commit or deployed address it applies to
- what an attacker gains, and what they need in order to do it
- the smallest reproduction you can manage, ideally a failing Foundry test
- the chain and transaction hash, if you observed it against a live deployment

You will get a reply confirming receipt. Please allow time for a fix before considering any further disclosure, and coordinate the timing in that thread.

Reports about GitHub itself — the OIDC issuer, the JWKS endpoint, the Actions platform — belong to [GitHub's own program](https://bounty.github.com), not here.

## Reporting a bug

Non-security bugs can go in a public issue. Before opening one, read the note below about how this tracker works.

Useful reports say what you ran, what happened, and what you expected instead. For anything touching registration, the workflow run URL and the transaction hash are usually enough to diagnose it.

## Before you open an issue

**This repository's issue tracker is also its registration mechanism.** Opening an issue here triggers `.github/workflows/register.yml`, which reads the issue title. Two things follow from that:

- **Do not start a bug report's title with `0x`.** A title beginning with `0x` is treated as an attempted wallet registration. If it is not a valid 20-byte address, the workflow comments on your issue and closes it automatically. A title like `0x0 returned from tokenURI` will be closed as malformed rather than read as a bug. Rephrase it — `tokenURI returns 0x0 for an unregistered token` is fine.
- **Most open and closed issues here are registrations, not reports.** An issue whose title is a bare address is somebody claiming their identity. That is what the tracker is for; it is not noise, and it does not need triage.

Any title that does not begin with `0x` is ignored by the workflow entirely, so an ordinary bug report is left alone.

## Working on the code

If you have been asked to prepare a change, follow [AGENTS.md](./AGENTS.md). It carries the invariants that are not obvious from reading the contracts, several of which are load-bearing for the security of a proof.

Every change must keep the checks green:

```shell
forge fmt --check
forge build --sizes
forge test -vvv
```
