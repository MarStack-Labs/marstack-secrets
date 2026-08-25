# marstack-secrets

Secret and parameter store for the MarStack platform.

Two kinds of data, handled differently:

- **Secrets** — values that must never appear in logs, caches, or a UI. Database passwords, API keys.
- **Parameters** — configuration that is safe to display. Log levels, replica counts, feature flags.

Workloads authenticate with a machine identity issued by the MarStack control plane, receive access
with a bounded lifetime, and every read is recorded in a tamper-evident audit log.

## Status

Early development, but usable end to end: the server starts sealed, is initialized and unsealed with
Shamir shares, authenticates workloads, and serves versioned encrypted secrets behind policy. See
[docs/ROADMAP.md](docs/ROADMAP.md) for what is still missing, most notably leases, the parameter
store, and audit logging.

| Endpoint | Description |
|---|---|
| `GET /v1/sys/health` | Liveness probe. Returns `{"status":"ok"}` and nothing else |
| `GET /v1/sys/seal-status` | Whether the store is uninitialized, sealed, or unsealed |
| `POST /v1/sys/init` | Generates the root key and returns the unseal shares, once |
| `POST /v1/sys/unseal` | Submits one share; the store opens when a quorum is reached |
| `POST /v1/auth/bootstrap/login` | Trades a single-use bootstrap token for a session token |
| `POST /v1/auth/instance/login` | Trades a control plane assertion for a session token, when configured |
| `GET /v1/auth/self` | The identity behind the presented token |
| `POST /v1/auth/logout` | Revokes the presented token |
| `GET /v1/secret/data/{tenant}/{path...}` | Reads a secret, optionally `?version=N` |
| `PUT /v1/secret/data/{tenant}/{path...}` | Writes a new version, optionally with `cas` |
| `DELETE /v1/secret/data/{tenant}/{path...}` | Reversibly deletes the current version |
| `GET /v1/secret/metadata/{tenant}/{path...}` | Version and lifecycle information |
| `POST /v1/sys/policies/check` | Explains what the caller may do and why |
| `GET /v1/sys/leases` | The caller's own active leases |
| `PUT /v1/sys/leases/renew` | Extends one of the caller's leases |
| `PUT /v1/sys/leases/revoke` | Drops one of the caller's leases |
| `PUT /v1/sys/leases/revoke-prefix` | Revokes every holding under a prefix, and the holders' tokens |

Every other path answers `503 sealed` until the store is unsealed. A path that no module registered
answers `404 not_found` whether or not it exists, so the route table stays private.

## Quick start

```sh
make check
make run
```

`make run` serves plaintext HTTP on `127.0.0.1:8200` for local development only. In every other
context the server refuses to start without a TLS certificate and key.

```sh
curl -s http://127.0.0.1:8200/v1/sys/seal-status
{"state":"uninitialized","shares":0,"threshold":0,"progress":0}

curl -s -X POST http://127.0.0.1:8200/v1/sys/init -d '{"shares":5,"threshold":3}'
{"shares":["mFMPJqpx...","XiAYC3k1...","be7n+iYk...","IBQP4D4N...","E9rwEWEc..."],"threshold":3}
```

The shares are returned once and never again. Restart the process and the store is sealed, because
the root key existed only in memory:

```sh
curl -s -X POST http://127.0.0.1:8200/v1/sys/unseal -d '{"share":"mFMPJqpx..."}'
{"state":"sealed","shares":5,"threshold":3,"progress":1}
```

Three distinct shares in any order open it. A wrong quorum discards the collected shares and starts
over.

Provisioning happens on the host, against the database directly, and needs neither the network nor an
unsealed store:

```sh
sudo -u marstack-secrets marsec operator identity add instance/web-01 --tenant prod --kind instance
sudo -u marstack-secrets marsec operator bootstrap instance/web-01
mss_WxZBPHbN-KSshKFKSoTJ0QLmAos76gO2MSBFUkQXdy4
```

The workload trades that token once for a session token:

```sh
curl -s -X POST http://127.0.0.1:8200/v1/auth/bootstrap/login -d '{"token":"mss_WxZ..."}'
{"token":"mss_zUg_...","expires_at":"2026-08-25T12:51:48Z"}

curl -s http://127.0.0.1:8200/v1/auth/self -H 'Authorization: Bearer mss_zUg_...'
{"identity":"instance/web-01","kind":"instance","tenant":"prod"}
```

Grant it something to do, then use it:

```sh
cat > writer.json <<'RULES'
[{"Path":"secret/prod/*","Capabilities":["read","write","delete"]},
 {"Path":"secret/prod/locked/*","Capabilities":["deny"]}]
RULES

marsec operator policy put writer --tenant prod --rules writer.json
marsec operator policy bind service/ci --tenant prod --policy writer
```

```sh
curl -s -X PUT http://127.0.0.1:8200/v1/secret/data/prod/payment-api \
  -H 'Authorization: Bearer mss_zUg_...' -d '{"value":"db_password=s3cr3t"}'
{"version":1}

curl -s http://127.0.0.1:8200/v1/secret/data/prod/payment-api \
  -H 'Authorization: Bearer mss_zUg_...'
{"value":"db_password=s3cr3t","version":1,"created_at":"2026-08-25T12:28:27Z"}
```

A refusal says nothing about why, or about whether the path exists. Ask the store instead:

```sh
curl -s -X POST http://127.0.0.1:8200/v1/sys/policies/check \
  -H 'Authorization: Bearer mss_zUg_...' \
  -d '{"tenant":"prod","path":"secret/prod/locked/x","capability":"read"}'
{"allowed":false,"policy":"writer","rule":"secret/prod/locked/*",
 "reason":"an explicitly denying rule matched, and denial always wins","policies":["writer"]}
```

Once a store is running, the same binary is the client:

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

marsec param get prod/apps/billing/log_level --verbose
kind      string
from      log_level
inherited true
sensitive false
warn
```

Values come from stdin. `--value` works but warns, because a secret in a command line is a secret in
everyone's `ps` output.

Every access leaves a record, and the chain can be checked at any time:

```sh
marsec operator audit verify
/var/lib/marstack-secrets/audit.log verifies: 5 record(s), tip 1e567ff1922d…

marsec operator audit verify --file /tmp/tampered.log
error: audit: the chain does not verify: expected record 4 but found 5
```

Positional arguments come before flags in `marsec operator`, because Go's flag parsing stops at the
first non-flag token.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modular monolith layout and the rules that keep it modular |
| [docs/ENGINEERING-PRINCIPLES.md](docs/ENGINEERING-PRINCIPLES.md) | How KISS, DRY, YAGNI, SoC and SOLID are applied here |
| [docs/SECURITY.md](docs/SECURITY.md) | Shift-left security practices and the threat boundary |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every `MARSEC_*` environment variable |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | `systemd` unit, host hardening, and how to verify a running instance |
| [docs/AGENT.md](docs/AGENT.md) | The agent that lets an unmodified application use the store |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Milestones, in order, with the reasoning behind the order |
| [docs/adr/](docs/adr/) | Architecture decision records |

## Development

| Command | Purpose |
|---|---|
| `make check` | Every gate: formatting, vet, architecture boundaries, race tests, security scans |
| `make test` | Unit tests |
| `make cover` | Unit tests with a coverage summary |
| `make arch-check` | Fails if a module imports another module |
| `make security` | `govulncheck` and `gitleaks` |
| `make hooks` | Installs a pre-commit hook that runs `make check` |
| `make vm-up` | Starts the Linux VM the process protections can be tested in |
| `make vm-test` | Runs the suite inside that VM |

Run `make hooks` once after cloning. GitHub Actions is disabled on this repository, so the
pre-commit hook is where the security and architecture gates actually run.

## Requirements

- Linux to run the server. macOS is for development only: the process protections have no macOS
  equivalent, so the server refuses to start unless `MARSEC_ALLOW_UNPROTECTED_MEMORY=true`
- Lima, if you want `make vm-up` to give you a Linux VM for testing
- Go 1.26.6 or newer. Earlier 1.26 patch releases carry standard library vulnerabilities reachable
  from the TLS listener, so `go.mod` requires the fixed toolchain
- `gitleaks` on `PATH` for `make security`
