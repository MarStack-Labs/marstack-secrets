# marstack-secrets

Secret and parameter store for the MarStack platform.

Two kinds of data, handled differently:

- **Secrets** — values that must never appear in logs, caches, or a UI. Database passwords, API keys.
- **Parameters** — configuration that is safe to display. Log levels, replica counts, feature flags.

Workloads authenticate with a machine identity issued by the MarStack control plane, receive access
with a bounded lifetime, and every read is recorded in a tamper-evident audit log.

## Status

Early development. The HTTP surface currently exposes a single endpoint; everything else in
[docs/ROADMAP.md](docs/ROADMAP.md) is not built yet.

| Endpoint | Description |
|---|---|
| `GET /v1/sys/health` | Liveness probe. Returns `{"status":"ok"}` and nothing else. |

## Quick start

```sh
make check
make run
```

`make run` serves plaintext HTTP on `127.0.0.1:8200` for local development only. In every other
context the server refuses to start without a TLS certificate and key.

```sh
curl -i http://127.0.0.1:8200/v1/sys/health
```

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
