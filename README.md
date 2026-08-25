# marstack-secrets

Secret and parameter store for the MarStack platform.

Two kinds of data, handled differently:

- **Secrets** — values that must never appear in logs, caches, or a UI. Database passwords, API keys.
- **Parameters** — configuration that is safe to display. Log levels, replica counts, feature flags.

Workloads authenticate with a machine identity issued by the MarStack control plane, receive access
with a bounded lifetime, and every read is recorded in a tamper-evident audit log.

## Status

Early development. The server starts sealed, can be initialized and unsealed, and stores versioned
encrypted secrets through its Go API. Secrets are not reachable over HTTP yet: an endpoint before
authentication exists would be an unauthenticated secret endpoint. See
[docs/ROADMAP.md](docs/ROADMAP.md).

| Endpoint | Description |
|---|---|
| `GET /v1/sys/health` | Liveness probe. Returns `{"status":"ok"}` and nothing else |
| `GET /v1/sys/seal-status` | Whether the store is uninitialized, sealed, or unsealed |
| `POST /v1/sys/init` | Generates the root key and returns the unseal shares, once |
| `POST /v1/sys/unseal` | Submits one share; the store opens when a quorum is reached |

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

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modular monolith layout and the rules that keep it modular |
| [docs/ENGINEERING-PRINCIPLES.md](docs/ENGINEERING-PRINCIPLES.md) | How KISS, DRY, YAGNI, SoC and SOLID are applied here |
| [docs/SECURITY.md](docs/SECURITY.md) | Shift-left security practices and the threat boundary |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every `MARSEC_*` environment variable |
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

Run `make hooks` once after cloning. GitHub Actions is disabled on this repository, so the
pre-commit hook is where the security and architecture gates actually run.

## Requirements

- Go 1.26.6 or newer. Earlier 1.26 patch releases carry standard library vulnerabilities reachable
  from the TLS listener, so `go.mod` requires the fixed toolchain
- `gitleaks` on `PATH` for `make security`
