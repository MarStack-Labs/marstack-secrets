# Roadmap

Milestones are ordered by dependency, not by appeal. Each one ends with something that can be run
and tested.

## M0 — Skeleton (done)

Modular monolith layout, dependency rules enforced by `make arch-check`, configuration with secure
defaults, structured logging, middleware chain, `GET /v1/sys/health`, CI with security gates.

## M1 — Storage and envelope encryption (done)

Envelope encryption is done, in `internal/platform/crypto`. A fresh data encryption key per sealed
value, wrapped by a key encryption key, with AES-256-GCM throughout. Additional authenticated data
binds every ciphertext to a length-prefixed encoding of `tenant`, `path`, and `version`, so a
ciphertext moved to another location fails to decrypt rather than decrypting somewhere it does not
belong. `Rewrap` rotates a key encryption key by rewrapping data keys only, leaving payloads
untouched.

The SQLite foundation is done, in `internal/platform/sqlite`. Write-ahead logging, `synchronous=FULL`
so a commit is acknowledged only after `fsync`, foreign keys enforced, and a single writer connection.
Pragmas are read back during `Open`, so one that fails to apply is a startup error rather than a
silent assumption. Migrations are owned per module and checksummed, so editing a migration that has
already run is an error rather than a no-op.

The versioned repository is done, in `internal/modules/secret`. Every write creates a new version,
check-and-set rejects a write whose expectation no longer matches, delete is reversible, destroy
erases the stored material, and versions beyond the configured limit are destroyed automatically.
The repository stores sealed envelopes and never sees a plaintext.

`secret.Service` composes the two. It seals inside the write transaction, using the version the
transaction is about to assign, so the authenticated data and the stored version can never disagree.
Key material reaches it through a `Cipher` interface it declares itself, so the service holds
plaintexts but never a key. M2 supplies the sealed implementation of that interface.

Nothing in M1 is exposed over HTTP. A secret endpoint that predates M3 would be an unauthenticated
secret endpoint, so the engine stays reachable from Go code and tests until authentication exists.

## M2 — Seal and unseal (in progress)

Shamir secret sharing is done, in `internal/platform/crypto`. Splitting and combining happen over
GF(256) using loop based multiplication rather than lookup tables, so no memory access depends on
secret data. Every subset of the threshold size reconstructs the secret and no smaller subset does,
which is asserted across all ten three-of-five combinations rather than a single sampled one.

The process boots sealed and serves only `sys/health`, `sys/seal-status`, and `sys/unseal`. Root key
split with Shamir 3-of-5, verified against a key check value, held in `mlock`ed memory and zeroed on
shutdown. Auto-seal when the audit sink fails. `systemd` unit and host hardening.

## M3 — Authentication

Bootstrap tokens, then instance identity verified against the control plane: signature over JWKS,
expiry with a bounded clock skew, single-use `jti`, audience check, and a liveness check against the
control plane. Tokens are bound to the instance that obtained them. Rate limiting per identity.

No new secret types or engines are added before M3 is finished. If authentication is wrong, the rest
is decoration.

## M4 — Authorisation

Policies as path patterns plus capabilities, default deny, `deny` always winning. Tenant isolation
checked before policy evaluation. A `policy check` endpoint that explains which rule decided and
why — the first question during an incident.

## M5 — Leases

Every secret read issues a lease. Renew, revoke, revoke by prefix, revoke by identity. Expiry sweeper
with jitter and batch limits. A webhook from the control plane revokes by identity when an instance
is destroyed.

## M6 — Parameter store

Typed values, hierarchical inheritance, and references to secrets. A resolved reference is treated as
a secret: not cached, always audited, and requiring read capability on the referenced path.

## M7 — Audit and metrics

Hash-chained append-only log, `fsync` before the response is returned, fail closed when the sink is
unavailable, and a verification command. Prometheus metrics.

## M8 — Client tooling

Full CLI, and an agent that logs in, renders templates, renews leases before expiry, reloads the
application on change, and serves a last-known-good cache when the server is unreachable. The agent
is what lets an unmodified application use the store.

## M9 — Operations

Snapshot and restore, a restore drill in CI, response wrapping, and runbooks for break-glass, key
rotation, and prefix revocation.

## Deferred beyond v1

High availability and Raft, disaster recovery replication, dynamic secrets, a PKI engine, transit
encryption, and a web UI.

Auto-unseal is a prerequisite for high availability, not an optional extra: every new node boots
sealed, so failover without auto-unseal still waits for a human to type Shamir shares.
