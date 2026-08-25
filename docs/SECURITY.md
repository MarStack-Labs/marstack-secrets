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
| Every path is refused while sealed unless a module opted it in | A route added later is protected by default rather than by remembering |
| Unregistered paths answer `404` rather than `405` | A method mismatch does not confirm that a path exists |
| Request bodies are capped and reject unknown fields | Removes a trivial denial of service and catches misspelled fields |
| Tokens are stored as a SHA-256 fingerprint | The database cannot hand anyone a working credential |
| Every authentication failure returns one error | The endpoint cannot be used to learn which tokens exist |
| Bootstrap tokens are single use, consumed inside the issuing transaction | Concurrent exchanges cannot both succeed |
| Auth endpoints are refused while sealed | A session for a store that decrypts nothing is not worth issuing |
| Login attempts are limited per source address, taken from the connection | A client cannot pick its own rate limit bucket by setting a header |
| Authenticated requests are limited per identity, after authentication | Unauthenticated traffic cannot exhaust a real identity's budget |
| The rate limiter tracks a bounded number of keys | An attacker cannot grow the table into a memory exhaustion |
| Authorization runs before storage is touched | A refusal is identical whether the path exists or not |
| Refusals carry no reason; the reason goes to the log | A client cannot map policy structure by probing |
| Tenant isolation is checked before policies load | No rule, however broad, can reach another tenant |
| Stored policies are revalidated on read | A policy edited in the database is refused, not honoured |

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

## Process protections

Applied at startup, before any key exists. Failure to apply any of them stops the process unless
`MARSEC_ALLOW_UNPROTECTED_MEMORY` is set.

| Control | Effect |
|---|---|
| `mlockall(MCL_CURRENT\|MCL_FUTURE)` | Key material cannot be paged to swap |
| `RLIMIT_CORE = 0` | A crash cannot write the root key to disk |
| `PR_SET_DUMPABLE = 0` | `/proc/<pid>/mem` and `maps` belong to root, not the service user |

The third is the one that is easy to miss. Without it those entries belong to the service account, so
a second process running as `marstack-secrets` could read the root key straight out of memory.

Verification commands and expected values are in [DEPLOYMENT.md](DEPLOYMENT.md).

## Threat boundary

The process holds key material in memory once unsealed. Anything able to read that memory is
inside the boundary:

- The kernel and anything with `CAP_SYS_PTRACE`. `PR_SET_DUMPABLE=0` keeps `/proc/<pid>/mem` away
  from the service account, but root is still root.
- The hypervisor. On a third-party VPS the provider can snapshot guest RAM, and no in-guest control
  prevents it. Running on rented infrastructure is an accepted risk, not a mitigated one.
- Swap. Disabled at deployment time as a second line behind `mlock`; see
  [DEPLOYMENT.md](DEPLOYMENT.md).

Explicitly outside the current scope, because the corresponding features do not exist yet: audit
logging, and leases that would bound how long a granted read stays valid.

Local root on the host is inside the boundary by design: `marsec operator` writes to the database
directly, which is how the first credential comes into existence at all.

## Reporting

This is a personal project under active development. Open an issue for anything found; there is no
private disclosure process yet.
