# Security

A secret store has no useful "add security later" phase. The controls below are part of the build
from the first commit, and each one is either enforced by a test or by a CI gate.

## Shift left: where each control is enforced

| Stage | Gate | What it catches |
|---|---|---|
| Editing | No comments, no secrets in source; `.gitignore` excludes `*.pem`, `*.key`, `*.crt`, `.env` | Key material staged by accident |
| Pre-commit | `make hooks` installs a hook running `make check` | Everything below, before the commit exists |
| Commit | `make arch-check` | A module reaching past its boundary |
| Commit | `make test-race` | Data races, and the security assertions listed below |
| Commit | `gitleaks dir .` | Committed credentials, including in history |
| Commit | `govulncheck ./...` | Known vulnerabilities in dependencies and the toolchain |
| Repository | Workflow `permissions: contents: read` | An action with more token scope than it needs |

Every gate above is a target in the `Makefile`, and `make check` runs all of them. The workflow in
`.github/workflows/ci.yml` calls the same targets, so the two can never drift.

GitHub Actions is currently disabled on this repository to keep runner usage at zero, which makes
`make check` the only place these gates run. Install the pre-commit hook after cloning:

```sh
make hooks
```

Without the hook there is no enforcement at all, only intention. Dependency updates are applied by
hand alongside the milestone that needs them rather than on a schedule, since scheduled pull
requests cannot be verified while Actions are off.

## Secure defaults

| Default | Reason |
|---|---|
| TLS required; the server refuses to start without a certificate and key | Plaintext transport makes every other control decorative |
| TLS 1.3 minimum | Removes downgrade and legacy cipher negotiation |
| Plaintext HTTP only via `MARSEC_ALLOW_INSECURE_HTTP`, and it logs a warning on every start | Insecure operation must be explicit and visible |
| Plaintext HTTP and TLS material are mutually exclusive | Removes the ambiguity of "which one is actually in use" |
| Listen address defaults to `127.0.0.1` | An accidental deployment is not reachable from the network |
| `Cache-Control: no-store` on every response | Responses carrying secrets must not be stored by intermediaries |
| Request identifiers are generated, never taken from the client | A client-supplied identifier is attacker-controlled log content |
| Errors returned to clients are opaque codes | Internal detail belongs in the server log, not the response body |
| `GET /v1/sys/health` returns only `{"status":"ok"}` | Version and build detail are reconnaissance |

## Data at rest

| Control | Effect |
|---|---|
| Envelope encryption | A stored value is never in plaintext, and the persistence layer never receives one |
| Additional authenticated data | A ciphertext moved to another tenant, path, or version fails to decrypt |
| `secure_delete=ON` | Destroying a version erases the bytes rather than marking the space free |
| Database file `0600`, directory `0700` | Applied by `Open`, not left to the deployment |

## Assertions kept by tests

- A panicking handler returns `500` with an opaque body, and the panic value never reaches the client.
- The default configuration is rejected unless TLS material is supplied.
- Plaintext HTTP is off unless explicitly enabled.
- Request identifiers are unique per request and are not read from the request headers.
- The health response contains exactly one field.
- Key material is redacted through `String`, `GoString`, every `fmt` verb, `slog`, and `json.Marshal`.
- Decryption returns one opaque error for a wrong key, a moved ciphertext, and a tampered blob alike.
- A plaintext never reaches the database.
- Destroyed material is absent from the raw database and write-ahead log files.

## Threat boundary

The process holds key material in memory once unsealed. Anything able to read that memory is
inside the boundary:

- The kernel and anything with `CAP_SYS_PTRACE` or access to `/proc/<pid>/mem`.
- The hypervisor. On a third-party VPS the provider can snapshot guest RAM, and no in-guest control
  prevents it. Running on rented infrastructure is an accepted risk, not a mitigated one.
- Swap and core dumps. Both are disabled at deployment time; see the deployment section of the
  specification.

Explicitly outside the current scope, because the corresponding features do not exist yet:
authentication, authorisation, sealing, audit logging.

## Reporting

This is a personal project under active development. Open an issue for anything found; there is no
private disclosure process yet.
