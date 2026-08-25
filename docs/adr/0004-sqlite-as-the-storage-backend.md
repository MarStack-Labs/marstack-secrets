# ADR 0004 — SQLite as the storage backend

- Status: accepted
- Date: 2026-08-25
- Supersedes the zero-dependency position in ADR 0002

## Context

The store needs durable, transactional persistence. The audit record and the access it describes must
commit together, which rules out anything without real transactions. ADR 0001 already settled that
this is a single consistency domain running in one process.

ADR 0002 committed to the standard library until it genuinely could not do the job. Persistence is
that point: `database/sql` is an interface, not an implementation.

## Decision

SQLite through `modernc.org/sqlite`, a pure Go translation of the SQLite C source. This is the first
direct dependency in the module.

`modernc.org/sqlite` rather than `mattn/go-sqlite3` because it needs no cgo. A cgo-free build keeps
cross-compilation trivial, produces a static binary for the agent that will later run on bare metal,
and avoids a C toolchain in the supply chain of a process that holds encryption keys.

Connections are opened with four pragmas, verified by reading them back during `Open` so a pragma
that silently fails to apply is a startup error rather than a wrong assumption:

| Pragma | Value | Reason |
|---|---|---|
| `journal_mode` | `WAL` | Readers do not block the writer |
| `synchronous` | `FULL` | `fsync` before a commit is acknowledged |
| `foreign_keys` | `ON` | Off by default in SQLite, which surprises everyone once |
| `secure_delete` | `ON` | Freed content is zeroed rather than left in the file |
| `busy_timeout` | `5000` | A short wait instead of an immediate `SQLITE_BUSY` |

`synchronous=FULL` is the durability requirement from the roadmap. `NORMAL`, the usual choice under
WAL, can lose recently committed transactions on power loss. For a secret store, acknowledging a
write that later disappears is worse than being slower.

`secure_delete=ON` is the difference between deleting a row and erasing it. Without it, overwriting a
ciphertext at the SQL level leaves the previous bytes in the database file as free space until a
`VACUUM` happens to reuse the page — so a destroyed secret would still be recoverable from the file.
It costs write throughput on every write, not only on deletes, and that cost is accepted: a store
whose destroy operation does not destroy is worse than a slower one.

The behaviour is asserted by reading the raw database and write-ahead log files after a destroy and
failing if the material is still present. That test fails when the pragma is removed, which is the
only reason to trust it.

`SetMaxOpenConns(1)` serialises writes so write ordering is predictable and `SQLITE_BUSY` never has
to be handled by hand. This matches the convention already used in `marstack-cloud`.

The database file is `0600` and its directory `0700`, applied by `Open` rather than left to the
deployment.

## Migrations

Each module owns its own schema and passes its migrations to `sqlite.Migrate` under its own module
name. There is no central schema file, for the same reason there is no central routing table.

Applied migrations are recorded with a SHA-256 checksum of their statements. Re-running a migration
whose text has changed is an error rather than a silent no-op, which catches the common and
expensive mistake of editing a migration that has already run somewhere else.

## Consequences

Positive:

- Real transactions, real durability, no server to operate.
- One direct dependency, no cgo, no C toolchain.
- Pragmas are asserted rather than assumed.

Negative:

- The dependency tree grew from zero to ten modules, all transitive to `modernc.org/sqlite`. This is
  the cost of the decision and it is the reason `govulncheck` runs on every commit.
- `SetMaxOpenConns(1)` caps write throughput at one writer. For the expected read-heavy load this is
  not a constraint, and it will be revisited only with a measurement, not a hunch.
- SQLite is single-node by construction. High availability will therefore need a different storage
  decision, recorded when it is made rather than designed for now.

## Related

The first commit under this decision also raised the minimum toolchain to Go 1.26.6, because
`govulncheck` reported three standard library vulnerabilities in 1.26.5 reachable from the TLS
listener. Pinning the minimum in `go.mod` makes the fix a property of the repository rather than of
whichever machine happens to build it.
