# ADR 0006 — Rotation is a module, not a method on the seal manager

- Status: accepted
- Date: 2026-09-06

## Context

Rotating the key encryption key means two things happening in order: raising the stored version, then
moving every already stored value onto it. The first belongs to `internal/modules/seal`, which owns
the root key. The second belongs to `internal/modules/secret` and `internal/modules/param`, which own
their tables and, more importantly, own the shape of the additional authenticated data their values
were sealed with. A secret binds tenant, path and its real version; a parameter binds tenant, its
policy path, and a fixed version. Only the owning module can reconstruct either.

The obvious implementation is a method on the seal manager that walks the other modules' tables. Rule
1 in `docs/ARCHITECTURE.md` forbids it: a module must not import another module. The rule is not
bureaucratic here. A seal manager that knew the column names of `secret_versions` would break the next
time the secret module changed them, and the compiler would not say so until runtime.

Putting the orchestration in `internal/app` instead would work, but the composition root would grow a
handler and a route, and `docs/ARCHITECTURE.md` says routing tables are never central.

## Decision

Rotation is its own module, `internal/modules/rotate`, holding no storage of its own.

It declares what it needs in its own vocabulary:

- `Keys`, with `KEKVersion` and `Rotate`, returning plain integers.
- `Subject`, with `Name` and `Rewrap`, returning `rotate.Progress`.

Neither names a type from another module. `internal/app` writes the adapters — `keyRotator`,
`secretRewrapper`, `paramRewrapper`, `rotationAuthorizer` — exactly as it already does for
`secretReader` and `leaseIssuer`.

Each store walks its own rows and never learns which version is current. It asks the cipher to rewrap
an envelope and writes back only when the cipher reports the envelope moved.

The walk pages with a keyset cursor rather than holding a transaction. The database is opened with one
connection, so a transaction spanning the whole walk would stop every other request for its duration.

The request must name the version the caller believes is current. A mismatch is a conflict and nothing
moves.

## Consequences

Positive:

- A new store becomes rotatable by implementing `Subject` and adding one line to `app.assemble`. No
  existing module changes.
- Because each store decides for itself whether an envelope moved, the walk is idempotent, and a
  rotation interrupted partway is finished by running it again.
- The architecture check keeps enforcing this. A future attempt to reach across modules fails
  `make arch-check` rather than passing review.

Negative:

- Every rotation scans every row, since no store filters on a version it is not allowed to know. For a
  store whose row count is small by nature this is the right trade; it would not be for a table that
  grows with time.
- The composition root gained four adapters. That is the cost of structural typing across a boundary
  the compiler is not allowed to cross directly.
- A rotation that fails partway still raises the version, so a retry raises it again. Version numbers
  are integers and older ones stay derivable, so this costs nothing but a number.

## Related

The authorization reach, and what rotation does and does not protect against, are in
`docs/THREAT-MODEL.md`. The operator procedure is in `docs/RUNBOOKS.md`.
