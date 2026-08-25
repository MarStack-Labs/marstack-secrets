# marstack-secrets

Secret and parameter store for the MarStack platform. One Go binary, `marsec`, which is the server,
the operator tool, the client and the agent.

Two kinds of data, handled differently:

- **Secrets** — values that must never appear in a log, a cache, or a UI. Database passwords, API keys.
  Versioned, envelope encrypted, every access recorded.
- **Parameters** — configuration that is safe to display. Log levels, replica counts, feature flags.
  Typed, inherited down a path, and able to reference a secret.

Workloads authenticate with an identity their control plane vouched for, receive access with a bounded
lifetime, and cannot read anything the store failed to write a record for.

## Status

v1 is complete: 385 tests, one direct dependency, no CI required to verify it.

The server starts sealed, is initialized and unsealed with Shamir shares, authenticates workloads
against bootstrap tokens or control plane assertions, serves secrets and parameters behind policy,
issues leases that make scoped revocation possible, and records every access in a hash chained log it
refuses to run without.

[docs/ROADMAP.md](docs/ROADMAP.md) ends with a list of what v1 does **not** have — key rotation, token
binding enforcement, an audit anchor off the host, and more. Read it before relying on this for
anything that matters.

## How it fits together

```
                    ┌──────────────┐
   application ────▶│ rendered file│◀──── marsec agent ──┐
   (unmodified)     └──────────────┘                     │
                                                         │ HTTPS
   operator ──▶ marsec operator ──▶ database  ◀──────────┤
                (no network needed)                      │
                                                    ┌────▼─────┐
   control plane ──── signs assertion ─────────────▶│  marsec  │
                                                    │  server  │
                                                    └────┬─────┘
                                                         │
                                       ┌─────────────────┴──────────────────┐
                                       │ sealed until a quorum of shares    │
                                       │ root key in mlocked memory only    │
                                       │ SQLite, WAL, synchronous=FULL      │
                                       │ append-only hash chained audit log │
                                       └────────────────────────────────────┘
```

Inside the server, six modules with enforced boundaries: `seal`, `auth`, `policy`, `secret`, `param`,
`lease`, plus `health` and `observe`. No module imports another; the composition root wires them.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Endpoints

Reachable while sealed, because these are how a sealed store is diagnosed and opened:

| Endpoint | Description |
|---|---|
| `GET /v1/sys/health` | Liveness probe. Returns `{"status":"ok"}` and nothing else |
| `GET /v1/sys/seal-status` | Whether the store is uninitialized, sealed, or unsealed |
| `POST /v1/sys/init` | Generates the root key and returns the unseal shares, once |
| `POST /v1/sys/unseal` | Submits one share; the store opens on a quorum |
| `GET /v1/sys/metrics` | Prometheus exposition. Unauthenticated, and carries no tenant or path label |

Everything below answers `503 sealed` until the store is open:

| Endpoint | Needs | Description |
|---|---|---|
| `POST /v1/auth/bootstrap/login` | — | Trades a single-use bootstrap token for a session token |
| `POST /v1/auth/instance/login` | — | Trades a control plane assertion for a session token |
| `GET /v1/auth/self` | token | The identity behind the presented token |
| `POST /v1/auth/logout` | token | Revokes the presented token |
| `GET /v1/secret/data/{tenant}/{path...}` | `read` | Reads a secret, optionally `?version=N`; issues a lease |
| `PUT /v1/secret/data/{tenant}/{path...}` | `write` | Writes a new version, optionally with `cas` |
| `DELETE /v1/secret/data/{tenant}/{path...}` | `delete` | Reversibly deletes the current version |
| `GET /v1/secret/metadata/{tenant}/{path...}` | `read` | Version and lifecycle information |
| `GET /v1/param/data/{tenant}/{path...}` | `read` | Reads a parameter, following inheritance and references |
| `PUT /v1/param/data/{tenant}/{path...}` | `write` | Writes a typed parameter |
| `DELETE /v1/param/data/{tenant}/{path...}` | `delete` | Removes a parameter |
| `GET /v1/param/list/{tenant}?prefix=` | `list` | Lists parameters without decrypting them |
| `POST /v1/sys/policies/check` | token | Explains what the caller may do, and which rule decided |
| `GET /v1/sys/leases` | token | The caller's own active leases |
| `PUT /v1/sys/leases/renew` | token | Extends one of the caller's leases |
| `PUT /v1/sys/leases/revoke` | token | Drops one of the caller's leases |
| `PUT /v1/sys/leases/revoke-prefix` | `delete` on the prefix | Revokes every holding under a prefix, and the holders' tokens |

A path no module registered answers `404 not_found` whether or not it exists, so the route table stays
private. A refusal never says why; ask `policies/check` about your own access instead.

## Quick start

```sh
make check
make run
```

`make run` serves plaintext HTTP on `127.0.0.1:8200` for local development only. Anywhere else the
server refuses to start without a TLS certificate and key, and on Linux it also refuses to start if it
cannot lock its memory.

Initialize it. The shares are returned once and never again:

```sh
curl -s -X POST http://127.0.0.1:8200/v1/sys/init -d '{"shares":5,"threshold":3}'
{"shares":["mFMPJqpx…","XiAYC3k1…","be7n+iYk…","IBQP4D4N…","E9rwEWEc…"],"threshold":3}
```

Restart the process and the store is sealed, because the root key existed only in memory. Three
distinct shares in any order reopen it; a wrong quorum discards what it collected and starts over:

```sh
curl -s -X POST http://127.0.0.1:8200/v1/sys/unseal -d '{"share":"mFMPJqpx…"}'
{"state":"sealed","shares":5,"threshold":3,"progress":1}
```

### Provisioning, on the host

`marsec operator` writes to the database directly. It needs neither the network nor an unsealed store,
which is how the first credential comes into existence at all.

```sh
cat > writer.json <<'RULES'
[{"Path":"secret/prod/*","Capabilities":["read","write","delete"]},
 {"Path":"secret/prod/locked/*","Capabilities":["deny"]},
 {"Path":"param/prod/*","Capabilities":["read","write","list"]}]
RULES

marsec operator identity add service/ci --tenant prod --kind bootstrap
marsec operator policy put writer --tenant prod --rules writer.json
marsec operator policy bind service/ci --tenant prod --policy writer
marsec operator bootstrap service/ci
mss_WxZBPHbN-KSshKFKSoTJ0QLmAos76gO2MSBFUkQXdy4
```

### Using it, as a client

```sh
export MARSEC_ADDRESS=https://secrets.internal:8200
export MARSEC_CACERT=/etc/marstack-secrets/tls/ca.pem

marsec login --bootstrap-file /run/bootstrap-token
logged in; token kept in /root/.marsec/token, expires 2026-08-25T14:21:41Z

printf 'db_password=s3cr3t' | marsec secret put prod/apps/payment/db
wrote version 1

marsec secret get prod/apps/payment/db
db_password=s3cr3t

printf 'rotated' | marsec secret put prod/apps/payment/db --cas 1
wrote version 2

printf 'warn' | marsec param put prod/log_level --kind string
marsec param get prod/apps/billing/log_level --verbose
kind      string
from      log_level
inherited true
sensitive false
warn
```

Values come from stdin. `--value` works but warns, because a secret on a command line is a secret in
everyone's `ps` output.

A parameter may reference a secret, and the reference is authorized on its own:

```sh
printf 'postgres://app:${secret/prod/apps/payment/db}@db:5432/app' \
  | marsec param put prod/apps/db_url --kind string
```

### Understanding a refusal

```sh
marsec secret get prod/locked/root-key
error: client: the store refused the request

curl -s -X POST "$MARSEC_ADDRESS/v1/sys/policies/check" -H "Authorization: Bearer $(cat ~/.marsec/token)" \
  -d '{"tenant":"prod","path":"secret/prod/locked/root-key","capability":"read"}'
{"allowed":false,"policy":"writer","rule":"secret/prod/locked/*",
 "reason":"an explicitly denying rule matched, and denial always wins","policies":["writer"]}
```

### Letting an unmodified application use it

The agent renders secrets into files the application already reads, and reloads it when they change.
See [docs/AGENT.md](docs/AGENT.md).

```
password = {{ secret "apps/payment/db" }}
level    = {{ param "apps/billing/log_level" }}
```

```sh
marsec agent --config /etc/marstack-secrets/agent.json
```

### Checking the trail

```sh
marsec operator audit verify
/var/lib/marstack-secrets/audit.log verifies: 5 record(s), tip 1e567ff1922d…

marsec operator audit verify --file /tmp/tampered.log
error: audit: the chain does not verify: expected record 4 but found 5
```

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modular monolith layout and the six rules that keep it modular |
| [docs/ENGINEERING-PRINCIPLES.md](docs/ENGINEERING-PRINCIPLES.md) | How KISS, DRY, YAGNI, SoC and SOLID are applied here |
| [docs/SECURITY.md](docs/SECURITY.md) | Every control, where it is enforced, and what the audit chain cannot do |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every `MARSEC_*` variable, server and client |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | `systemd` unit, host hardening, and how to verify a running instance |
| [docs/AGENT.md](docs/AGENT.md) | The agent, and why it keeps no cache of its own |
| [docs/RUNBOOKS.md](docs/RUNBOOKS.md) | A leaked secret, a compromised identity, a self-sealed store, a restore |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Milestones in dependency order, ending with what v1 lacks |
| [docs/adr/](docs/adr/) | Five decision records: the monolith, the standard library, transport, SQLite, metrics |

## Development

| Command | Purpose |
|---|---|
| `make check` | Every gate: formatting, vet, boundaries, race tests, restore drill, security scans |
| `make test` | Unit tests |
| `make cover` | Unit tests with a coverage summary |
| `make arch-check` | Fails if a module imports another module, or the server imports its own client |
| `make drill` | Saves, verifies and restores a snapshot, and fails if the copy differs |
| `make security` | `govulncheck` and `gitleaks` |
| `make hooks` | Installs a pre-commit hook that runs `make check` |
| `make vm-up` | Starts the Linux VM the process protections can be tested in |
| `make vm-test` | Runs the suite inside that VM |

Run `make hooks` once after cloning. GitHub Actions is disabled on this repository to keep runner
usage at zero, so the pre-commit hook is where these gates actually run. Everything CI would do is a
`Makefile` target, which is why turning CI off cost no coverage.

## Requirements

- **Linux to run the server.** macOS is for development only: `mlockall`, `RLIMIT_CORE` and
  `PR_SET_DUMPABLE` have no macOS equivalent, so the server refuses to start there unless
  `MARSEC_ALLOW_UNPROTECTED_MEMORY=true`.
- **Go 1.26.6 or newer.** Earlier 1.26 patch releases carry standard library vulnerabilities reachable
  from the TLS listener, so `go.mod` requires the fixed toolchain.
- Lima, if you want `make vm-up` to give you that Linux VM.
- `gitleaks` on `PATH` for `make security`.

One direct dependency: `modernc.org/sqlite`, chosen over `mattn/go-sqlite3` because it needs no cgo.
See [ADR 0004](docs/adr/0004-sqlite-as-the-storage-backend.md).
