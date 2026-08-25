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

## M2 — Seal and unseal (done)

Shamir secret sharing is done, in `internal/platform/crypto`. Splitting and combining happen over
GF(256) using loop based multiplication rather than lookup tables, so no memory access depends on
secret data. Every subset of the threshold size reconstructs the secret and no smaller subset does,
which is asserted across all ten three-of-five combinations rather than a single sampled one.

The seal manager is done, in `internal/modules/seal`. The root key exists only in memory: a restart
leaves the store sealed, and the persisted configuration holds nothing but the Shamir parameters and
a key check value. Key encryption keys are derived per tenant rather than stored, so no key material
is written anywhere.

`seal.Cipher` is the implementation of the interface `secret` declares. Neither module imports the
other; the composition root puts them together, which is exactly the arrangement ADR 0001 exists to
allow.

The sealed boot is done. The process starts sealed and a middleware refuses every path that no module
declared safe while sealed. The allowlist is not a central list: a module states its own tolerant
paths through an optional interface, the same way it owns its routes and its schema. The gate exists
before there is anything to gate, so a route added in M3 is refused by default rather than by
remembering to add it.

Process protections are applied before any key exists: memory locked, core dumps disabled, and the
process made undumpable. Any failure stops the process unless the operator explicitly opted out. The
`systemd` unit supplies the capability and the resource limit that make locking possible, and
`lima/marsec-dev.yaml` provides the Linux VM the whole thing is verified in.

Auto-seal when the audit sink fails belongs with M7, since there is no audit sink to fail yet.

## M3 — Authentication (done)

Identities and tokens are done, in `internal/modules/auth`. A token is 256 random bits behind a
`mss_` prefix and only its SHA-256 fingerprint is stored, so the database cannot hand anyone a
working credential. Tokens carry an expiry and an optional binding, and can be revoked one at a time
or all at once per identity.

Every rejection returns the same error. Expired, revoked, never issued, wrong binding, disabled
identity and malformed all look identical from outside, so the endpoint cannot be used to learn
which tokens exist.

Bootstrap login works end to end. An operator registers an identity and mints a single-use token on
the host with `marsec operator`, which writes to the database directly and needs neither the network
nor an unsealed store. The workload trades that token once at `POST /v1/auth/bootstrap/login` for a
session token and carries it as a bearer credential.

Identities live in `internal/platform/authn`, not in the auth module. A handler in another module
needs to read the caller, and modules cannot import each other, so the identity type and its context
plumbing belong to the platform while the auth module keeps the storage and the endpoints.

Auth endpoints are refused while sealed. A session for a store that can decrypt nothing is not worth
issuing, so they are not on the sealed allowlist.

Instance identity is done. A workload presents the assertion its control plane signed at
`POST /v1/auth/instance/login` and receives a session token. The assertion is verified strictly
(see `internal/platform/jwt`), its `jti` is spent inside the same transaction that issues the
session, and the instance is enrolled on first login. An instance cannot change tenant, cannot take
over an identity registered with another kind, and cannot log in once disabled. The endpoint is only
routed when a control plane is configured, so an unconfigured store answers `404` rather than
advertising a login it cannot perform.

Token binding is recorded but not enforced, and that is worth stating plainly. A binding only means
something if the server observes it rather than being told; a stolen token used elsewhere would
present the same instance name, which is public. Enforcement therefore waits for mTLS, where the
client certificate is the observed value. Until then instance sessions are issued unbound, and a test
asserts that rather than leaving a control in place that cannot be enforced.

Rate limiting is done, in `internal/platform/ratelimit`. Login attempts are counted per source
address and authenticated requests per identity, the second only after authentication succeeds so
unauthenticated traffic cannot exhaust a real identity's budget. The key table is bounded and sweeps
idle buckets, because a limiter keyed by attacker-chosen values is otherwise a memory exhaustion of
its own.

Not built, and honest about it: a liveness check against the control plane, so a destroyed instance
cannot spend an assertion still inside its expiry window. The window is bounded by the assertion's
own expiry, and the check needs an endpoint the control plane does not expose yet.

No new secret types or engines are added before M3 is finished. If authentication is wrong, the rest
is decoration.

## M4 — Authorisation (done)

Policies are path patterns plus capabilities, in `internal/modules/policy`. Default deny, an explicit
denial anywhere wins outright, and otherwise the most specific matching rule decides alone. The
outcome does not depend on the order rules or policies are listed in, which is what makes a policy
set reviewable.

Tenant isolation is checked before any policy is loaded, so no rule can grant its way across the
boundary. A stored policy is revalidated when it is read rather than trusted because it was valid
when written.

Secret endpoints are open behind authentication and policy. Authorization happens before storage is
touched, so a refusal is identical whether the path exists or not. The client is told nothing about
why; `POST /v1/sys/policies/check` returns the reason, but only about the caller's own access.

The authentication middleware reaches the secret and policy modules as an injected middleware rather
than an import, since modules cannot import each other. The composition root owns both and hands the
guard over.

Undelete and destroy remain reachable only from Go and the operator CLI. Nothing needs them over HTTP
yet, and the capability set they would use is already in the engine.

## M5 — Leases (in progress)

What a lease is here, stated plainly: a lease on a static secret cannot claw the value back. The
client already holds the plaintext, and no amount of bookkeeping changes that. Pretending otherwise
would be the worst kind of security theatre.

What a lease does is record who holds which version of which path until when, and that record is what
makes scoped revocation possible. Without it there is no way to answer "which identities hold copies
of anything under secret/prod/payment/", and therefore no way to revoke exactly those.

So revocation acts on access rather than on copies. Revoking by prefix or by identity revokes the
holders' tokens, which forces re-authentication: a live instance re-authenticates by itself, while a
stolen token cannot. The result reports how many leases and tokens went, because during an incident
the next question is always how much.

The manager is done, in `internal/modules/lease`. A repeated read reuses one lease rather than
creating a row per request, which a schema level partial unique index enforces rather than trusting
the code. Reissuing extends an expiry and never shortens it. Sweeping is batched and keeps a
retention window, so recent history survives while the table stays bounded.

Still to come in M5: issuing a lease on every secret read, the lease endpoints, the sweeper loop with
jitter, and the control plane webhook that revokes by identity when an instance is destroyed.

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
