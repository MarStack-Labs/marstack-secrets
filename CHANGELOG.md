# Changelog

Notable changes, newest first. This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
and the format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

For a v1 release of a store that holds secrets, the entries worth reading are the ones under
*Deliberately absent*. Everything a version does not do is a thing an operator would otherwise find
out during an incident.

## [Unreleased]

### Changed

- The repository now matches `marstack-cloud` and `marstack-access`: a tracked `.githooks/pre-commit`
  rather than an untracked one, `make tools`, `make dist` and `make site`, and a landing page at
  `site/` built on the same theme the console serves.
- `staticcheck` and `gosec` join the security gate. CI and the hook call the same `Makefile` targets,
  so neither can drift from the other.
- The console uses the shared `meridian.css`, so the three MarStack products look like one platform.

### Fixed

- `crypto.Label` bounded the parts it length-prefixes. Every caller was bounded elsewhere, but the
  function relying on that bound did not enforce it, and an over-long part would have wrapped the
  four byte prefix and let two different tenant and version pairs derive the same key encryption key.
- Two dead symbols and a struct literal that should have been a conversion, all found by
  `staticcheck`.
- The README and threat model no longer claim GitHub Actions is disabled.

### Notes

- The audit chain uses the same four byte length prefix and is deliberately left alone. Widening it
  would change every digest and make every existing record fail verification, which is the failure
  the log exists to prevent. That, and the four other rules `gosec` is not asked about, are recorded
  in [CONTRIBUTING.md](CONTRIBUTING.md).

## [1.2.0] — 2026-09-06

### Added

- **A browser interface at `/ui/`**, off unless `MARSEC_UI_ENABLED` is set, and warning on every boot
  when it is on. It reads and writes secrets and parameters, unseals, lists leases, explains a policy
  decision, and rotates. Three embedded files, no framework, no build step, so the binary stays one
  file.

### Changed

- `marsec status` and the client's `SealStatus` report the key encryption key version. The rotation
  work added it to the API and left the client behind, so the one command the runbook tells an
  operator to run before rotating did not show the number it asks for.

### Known limits

- The interface renders decrypted values onto a screen, which no control in this process can protect.
  Cross site scripting is now a threat where it was not; a strict content security policy is the
  mitigation, held shut by tests rather than assumed. See
  [docs/adr/0007](docs/adr/0007-a-browser-interface-that-is-off-by-default.md).
- The session token lives in a JavaScript variable, so reloading the page signs you out. That is the
  intended cost of keeping it out of browser storage.

## [1.1.0] — 2026-09-06

### Added

- **Key encryption key rotation.** `POST /v1/sys/rotate` raises the version and rewraps every stored
  secret version and parameter onto it. Only the wrapped data key is replaced; payloads are never
  re-encrypted, so the cost is one key unwrap per value. The version now lives in the database rather
  than in a compiled in constant, and `GET /v1/sys/seal-status` reports it.

### Changed

- The walk pages with a cursor instead of holding one transaction, because the database is opened with
  a single connection and a long transaction would stop every other request until it finished.
- Rotating a parameter's key leaves `updated_at` and `updated_by` alone. A rotation is not an edit.

### Fixed

- The `security` gate had been failing since the runbooks were added, unnoticed because that commit
  was verified with the other targets run individually. The finding was the example host
  `secrets.internal:8200` matching `generic-api-key`; the exemption is now recorded in
  `.gitleaks.toml` and scoped to lines containing that host, so everything else in those files is
  still scanned.

### Known limits

- A rotation is store wide while every authorization in this store is per tenant. An identity granted
  `write` on `sys/rotate` rewraps other tenants' values without being able to read them. See
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- The root key is not rotated. Every key encryption key version derives from it, so rotation limits a
  leaked derived key and not a compromised root.
- A rotation that fails partway leaves the store working and readable, but incompletely rotated. Run
  it again; the next pass finishes the rest.

## [1.0.0] — 2026-08-25

First release. The store is usable end to end: it boots sealed, authenticates workloads, serves
secrets and parameters behind policy, and records every access in a log it refuses to run without.

### Added

- **Storage and encryption.** SQLite with write-ahead logging, `synchronous=FULL` so a commit is
  acknowledged only after `fsync`, and `secure_delete` so destroying a version erases the bytes rather
  than freeing the page. Envelope encryption throughout: a fresh data key per value, wrapped by a key
  encryption key, with authenticated data binding every ciphertext to its tenant, path and version.
- **Seal and unseal.** The root key exists only in memory, split with Shamir secret sharing. A restart
  leaves the store sealed. The persisted configuration holds the parameters and a key check value and
  nothing else, so the database alone is useless.
- **Process protections.** Memory locked, core dumps disabled, and the process made undumpable, all
  applied before any key exists. Any failure stops the process unless explicitly overridden.
- **Authentication.** Single-use bootstrap tokens, and instance identity verified against a control
  plane: strict EdDSA verification, single-use assertion identifiers, bounded clock skew. Tokens are
  stored as a fingerprint, and every rejection returns the same error.
- **Authorisation.** Path patterns and capabilities, default deny, an explicit denial winning outright,
  and otherwise the most specific matching rule deciding alone. Tenant isolation is checked before any
  policy loads. `POST /v1/sys/policies/check` explains a decision to the caller it concerns.
- **Secrets over HTTP.** Versioned reads and writes with check-and-set, reversible delete, and
  metadata. Authorization runs before storage is touched, so a refusal is identical whether the path
  exists or not.
- **Parameters.** Typed values validated on write, inheritance towards the tenant root, and references
  to secrets that are authorized separately and never resolved recursively.
- **Leases.** Every read records who holds which version until when, which is what makes revocation by
  prefix or by identity possible. Revoking takes the holders' tokens with it.
- **Audit.** Append-only, hash chained, `fsync`ed before the response returns, and carrying no value.
  A record that cannot be written refuses the request, and a failing sink seals the store.
- **Metrics.** Prometheus exposition, written by hand rather than adding a dependency, unauthenticated
  and answering while sealed because that is when the numbers matter.
- **Client tooling.** `marsec login`, `status`, `secret`, `param`, and an agent that renders secrets
  into files an unmodified application already reads and reloads it when they change.
- **Operations.** Snapshot, verify and restore, with `make drill` exercising the whole cycle on every
  commit. Runbooks for a leaked secret, a compromised identity, a self-sealed store and a restore.

### Deliberately absent

Each of these is a decision with a reason, not an oversight. The reasoning is in
[docs/ROADMAP.md](docs/ROADMAP.md).

- **Token binding enforcement.** Recorded but not enforced. A binding only means something if the
  server observes it rather than being told, so it waits for mTLS.
- **A liveness check against the control plane.** A destroyed instance can still spend an assertion
  inside its expiry window.
- **An audit anchor outside the host.** The chain detects partial tampering, not a rewrite by whoever
  can write the whole file. There is a test that proves this rather than a claim that implies
  otherwise.
- **Parameter versioning**, and therefore parameter rollback.
- **Response wrapping.** Dropped rather than deferred: every channel it would protect is already
  closed.
- **High availability, disaster recovery replication, dynamic secrets, a PKI engine, transit
  encryption, and a web UI.** Deferred beyond v1 from the start. Auto-unseal is a prerequisite for the
  first of these, not an optional extra.

### Notes for operators

- Linux only. macOS is a development platform; the process protections have no equivalent there.
- Requires Go 1.26.6 or newer to build. Earlier 1.26 patch releases carry standard library
  vulnerabilities reachable from the TLS listener.
- The store boots sealed. A restart is an outage until a quorum of share holders is available.
- Auditing cannot be turned off. A full audit disk stops the store; see
  [docs/RUNBOOKS.md](docs/RUNBOOKS.md).

[1.2.0]: https://github.com/MarStack-Labs/marstack-secrets/releases/tag/v1.2.0
[1.1.0]: https://github.com/MarStack-Labs/marstack-secrets/releases/tag/v1.1.0
[1.0.0]: https://github.com/MarStack-Labs/marstack-secrets/releases/tag/v1.0.0
