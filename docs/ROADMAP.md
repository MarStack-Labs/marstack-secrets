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

## M5 — Leases (done)

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

Reads issue a lease, and a lease that cannot be recorded fails the read. Serving a secret without
recording who received it would be an unrecorded read, which is the thing the record exists to
prevent.

Renew and revoke act on the caller's own leases only; another identity's lease answers 404 rather
than 403, since the caller has no business knowing it exists. Prefix revocation needs the `delete`
capability on the prefix: an identity that may delete secrets under a path may also revoke the
holdings under it. Everything else stays with the operator CLI, because there is no administrator
role yet and exposing a store-wide revocation to any authenticated caller would be worse than
inconvenient.

The sweeper runs with jitter around the configured interval, so a fleet of instances does not
converge on the same instant.

Not built: the control plane webhook that revokes by identity when an instance is destroyed. It needs
marstack-cloud to emit the event, and `RevokeIdentity` is already there to receive it.

## M6 — Parameter store (done)

Typing and inheritance are done, in `internal/modules/param`. A value declares one of `string`,
`int`, `bool` or `stringlist` and is validated on write, so a wrong type is caught where it is typed
rather than when an application crashes reading it.

Resolution walks up towards the tenant root: `apps/payment/log_level` falls back to `apps/log_level`
and then `log_level`. The nearest definition wins, and the result reports which path supplied it, so
an operator debugging inheritance can see the answer rather than deduce it.

Three deliberate departures from the specification, each because the specification was written before
the code existed:

- Inheritance never leaves the tenant. The original example fell back to `param/log_level` with no
  tenant at all, which would let one tenant's default reach another. Isolation wins.
- Parameters are not versioned in v1. Versioning is a second copy of the machinery the secret store
  already has, and the audit log already records who changed what and when. Rollback is the thing
  that is missing, and it is the trigger for adding versions.
- Values reuse the same envelope encryption as secrets rather than a lighter scheme. One encryption
  path is easier to keep correct than two, and encrypting a parameter more strongly than it needs
  costs nothing.

References are done. A value may contain `${secret/<tenant>/<path>}`, resolved when the parameter is
read, and three rules make that safe rather than convenient:

- The referenced secret is authorized separately. An identity with parameter access but no secret
  access is refused, which is asserted, because otherwise a parameter would be a way around policy.
- A reference cannot name another tenant. The check is explicit rather than left to the authorizer.
- Resolution does not recurse. A secret whose contents happen to look like a reference is returned
  literally, so there are no loops and no depth to bound.

A resolved value is reported as sensitive, with the references it consumed, so a caller and an
operator can both tell that a parameter is carrying secret material.

Every parameter operation is audited, including refusals, and the value never reaches the log.

## M7 — Audit and metrics (done)

The log is done, in `internal/platform/audit`, and wired through every module that touches a secret.
Append only, hash chained, `fsync`ed before the response is returned, and carrying no value: the
Event type has no field for one. Version is recorded, because the incident question is who read which
value, not who read the secret.

Auditing cannot be turned off. There is no configuration for it, only a path, defaulting inside the
data directory so it is always writable. A record that cannot be written refuses the request, and a
failing sink seals the store, which is the auto-seal deferred from M2.

Refusals are recorded too, with the policy and rule that decided. "Who tried and was turned away" is
the other half of an incident.

What the chain does not do is written down in `docs/THREAT-MODEL.md` and pinned by a test: anyone who can
rewrite the whole file can recompute every hash and pass verification. Closing that needs an anchor
off the host, which is not built.

Metrics are done, in `internal/platform/metrics`, exposed by `internal/modules/observe`. Written by
hand rather than pulling in the Prometheus client, with the reasoning and the triggers for changing
course in ADR 0005.

`GET /v1/sys/metrics` is unauthenticated and answers while sealed, matching `sys/seal-status`.
Scraping a sealed store is when the numbers matter most, and an authenticated endpoint would be
unreachable then. No metric carries a tenant, path, or identity label.

## M8 — Client tooling (done)

The HTTP client is done, in `internal/client`, and it is a new peer of `app`, `modules` and
`platform` rather than a package inside any of them. Two architecture rules came with it: the client
must not import modules or the composition root, and the server must not import the client. Sharing
types across that line would let a server change quietly become a client change, and a module that
needed to call the API it serves would be a design problem rather than an import problem.

Plaintext HTTP needs an explicit opt-in, TLS 1.3 is the floor, responses are size bounded, and every
status the store can answer with becomes a named error, including a sealed store distinguished from
any other outage — an agent needs to tell "wait and retry" from "this will not work".

The client commands are done: `login`, `status`, `secret get|put|delete`, `param get|put`.

Values are read from stdin by default. Passing `--value` works but prints a warning, because process
arguments are readable by other users on the host and a secret on a command line is a secret in
everyone's `ps` output.

The session token is kept in a `0600` file, `MARSEC_TOKEN` overrides it for a single call, and a
missing session says to run `marsec login` rather than reporting a bare 401.

The agent is done, in `internal/agent`, documented in `docs/AGENT.md`.

There is no separate cache, and that is the design rather than an omission. Keeping a second copy of
the secrets on disk to survive an outage would double the exposure to halve an inconvenience. The
rendered destination file already is that copy, so the agent declines to overwrite it with anything
worse: a destination is written only after every lookup in its template succeeded, and a failed cycle
leaves it exactly as it was.

Writes are atomic through a temporary file in the same directory followed by a rename, so an
application never reads a half written configuration. The reload command runs only when the content
actually changed, because reloading on every poll is a restart loop with extra steps. It is an
argument list rather than a shell string, so there is nothing to quote and nothing to inject.

Configuration is JSON rather than YAML: YAML needs a dependency and the file is short. Unknown fields
are rejected so a typo fails at startup instead of silently doing nothing.

## M9 — Operations (done, with one item deliberately dropped)

Snapshot and restore are done, in `internal/platform/sqlite`. A snapshot is a `VACUUM INTO`, so it is
consistent without a long lock, and it is verified after writing rather than assumed good: integrity
check plus a count of applied migrations. Restore refuses to write over an existing database, because
the file it would overwrite is the only other copy until the restored one is proven.

A snapshot holds encrypted data and no root key. A leaked snapshot is not leaked secrets, and it is
equally useless to whoever holds it without a quorum of shares.

`make drill` is the restore drill, and it runs as part of `make check`. It provisions a scratch store,
snapshots it, verifies, restores into a second directory, compares what the two report, and then
requires a second restore over the same target to fail. A backup that has never been restored is not a
backup, so the drill runs on every commit rather than on a schedule someone forgets.

`docs/RUNBOOKS.md` covers restarting, a leaked secret, a compromised identity, a store that sealed
itself, break-glass with no session token, and restoring from a snapshot.

Response wrapping is dropped rather than deferred, and the reasoning belongs here. Its purpose is
handing a secret through a channel you do not fully trust, and every such channel in this design is
already closed: values never appear in command arguments, the audit log has no field for them, and a
consumer that can authenticate can read directly. It would add an endpoint, a table and a single-use
protocol to solve a problem this store does not currently have. If a third party ever needs a one-time
handoff, that is when to build it.

## What v1 does not have

Written down so none of it is discovered during an incident. Key encryption key rotation was on this
list and is no longer; see `docs/RUNBOOKS.md`.

- Token binding enforcement. Recorded but not enforced; it needs mTLS, where the value is observed
  rather than claimed.
- A liveness check against the control plane, so a destroyed instance cannot spend an assertion still
  inside its expiry window.
- An audit anchor outside the host. The chain detects partial tampering, not a rewrite by whoever can
  write the whole file.
- Root key rotation. The key encryption key can now be rotated, but every version of it is derived
  from the same root. Replacing the root means re-splitting the Shamir shares.
- Parameter versioning, and therefore parameter rollback.
- High availability, disaster recovery replication, dynamic secrets, a PKI engine, and transit
  encryption, all deferred beyond v1 from the start. The web interface was on this list and is no
  longer; it is off by default and its trade is recorded in `docs/adr/0007`.

## Deferred beyond v1

High availability and Raft, disaster recovery replication, dynamic secrets, a PKI engine, and transit
encryption.

Auto-unseal is a prerequisite for high availability, not an optional extra: every new node boots
sealed, so failover without auto-unseal still waits for a human to type Shamir shares.
