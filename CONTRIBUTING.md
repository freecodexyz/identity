# Contributing

This repository accepts **bug reports and security reports only**.

It is not open to feature requests, refactors, documentation rewrites, or unsolicited pull requests. Changes to the contracts alter what a deployed identity proof means, so they go through the maintainer rather than through an open contribution process. A pull request that was not asked for will be closed without review.

## Reporting a security vulnerability

**Report it privately. Never through an issue, a pull request, or a discussion.**

[SECURITY.md](./SECURITY.md) is the policy: where to send it, what to include, and what is in and out of scope.

Do not disclose anywhere public before a fix exists — that includes forks, commit messages, social media, write-ups, and talks. A public report on this codebase is not a theoretical weakness: `UIK` binds real GitHub accounts to real wallets, and anything that lets one account's identity be minted to an address that account does not control is directly exploitable the moment it is known.

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
