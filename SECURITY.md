# Reporting a vulnerability

Please do not open a public issue for a security problem in this project. It stores secrets; a public
report is a disclosure.

Use [GitHub's private vulnerability reporting](https://github.com/MarStack-Labs/marstack-secrets/security/advisories/new)
instead. That opens a private thread visible only to the maintainer.

Useful things to include, in rough order of usefulness:

- The version or commit you tested, from `marsec version`.
- The smallest sequence of requests or commands that shows the problem.
- What you expected instead, and why.
- Whether the store was sealed, unsealed, or uninitialized at the time.
- Anything from the server log or the audit log that shows it, with values redacted.

You do not need a working exploit. A clear description of a weakness is worth reporting on its own.

## What to expect

This is a single-maintainer project, not a vendor with an on-call rota. Expect an acknowledgement
within a week. If a report is valid, the fix and the advisory go out together.

## Scope

In scope: anything in this repository. The server, the client, the agent, the operator commands, the
`systemd` unit, and the deployment guidance.

Out of scope, because they are already stated as accepted risks in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) rather than being oversights:

- Reading key material from a process you already have root on the host for.
- A hypervisor snapshotting guest memory on rented infrastructure.
- Rewriting the whole audit log when you already have write access to the file. The chain detects
  partial tampering, not a full rewrite, and there is a test that says so.
- Local root using `marsec operator` to provision itself a credential. That is how the first
  credential exists at all.

If you think one of those framings is wrong, that itself is worth reporting.

## Things known to be missing

The end of [docs/ROADMAP.md](docs/ROADMAP.md) lists what v1 does not have, including key encryption
key rotation and enforced token binding. Reporting one of those as a vulnerability is not necessary;
arguing that one of them should have blocked the v1 claim is welcome.
