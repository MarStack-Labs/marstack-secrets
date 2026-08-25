# Configuration

The server reads its configuration from the environment. Every variable is prefixed `MARSEC_`. An
empty or unset variable falls back to its default. Invalid values are reported together at startup
rather than one at a time.

| Variable | Default | Description |
|---|---|---|
| `MARSEC_LISTEN_ADDR` | `127.0.0.1:8200` | Address the HTTP server binds to |
| `MARSEC_DATA_DIR` | `/var/lib/marstack-secrets` | Absolute path for data, write-ahead log, and snapshots |
| `MARSEC_TLS_CERT_FILE` | none | PEM certificate chain. Required unless plaintext HTTP is enabled |
| `MARSEC_TLS_KEY_FILE` | none | PEM private key. Required unless plaintext HTTP is enabled |
| `MARSEC_LOG_LEVEL` | `info` | One of `debug`, `info`, `warn`, `error` |
| `MARSEC_SHUTDOWN_TIMEOUT` | `15s` | Grace period for in-flight requests on shutdown |
| `MARSEC_ALLOW_INSECURE_HTTP` | `false` | Serve plaintext HTTP. Local development only |
| `MARSEC_ALLOW_UNPROTECTED_MEMORY` | `false` | Start even when memory cannot be locked. Local development only |
| `MARSEC_CONTROL_PLANE_ISSUER` | none | Issuer expected in instance assertions. Enables instance login |
| `MARSEC_CONTROL_PLANE_JWKS_FILE` | none | Path to the control plane Ed25519 key set. Enables instance login |
| `MARSEC_CONTROL_PLANE_AUDIENCE` | `marstack-secrets` | Audience this store accepts in assertions |
| `MARSEC_CONTROL_PLANE_SKEW` | `30s` | Tolerated clock skew, capped at one minute regardless |
| `MARSEC_LOGIN_RATE_PER_MINUTE` | `10` | Login attempts allowed per source address |
| `MARSEC_LOGIN_BURST` | `5` | Login attempts allowed back to back |
| `MARSEC_REQUEST_RATE_PER_MINUTE` | `600` | Authenticated requests allowed per identity |
| `MARSEC_REQUEST_BURST` | `60` | Authenticated requests allowed back to back |
| `MARSEC_LEASE_TTL` | `30m` | How long a lease issued by a read stays valid |
| `MARSEC_SWEEP_INTERVAL` | `5m` | Roughly how often expired leases are swept, with jitter |
| `MARSEC_SWEEP_BATCH` | `500` | Rows removed per sweep, so one pass cannot stall writes |

## Validation rules

- `MARSEC_DATA_DIR` must be an absolute path.
- `MARSEC_SHUTDOWN_TIMEOUT` must be greater than zero.
- Either TLS material is supplied, or `MARSEC_ALLOW_INSECURE_HTTP` is true. Supplying both is an
  error, so there is never a question about which transport is actually in use.
- `MARSEC_ALLOW_UNPROTECTED_MEMORY` is separate from the transport switch on purpose. Running without
  TLS and running with key material that can reach swap are different risks, and accepting one should
  never silently accept the other. On macOS the protections do not exist at all, so local development
  there needs this variable.

- Instance login needs both `MARSEC_CONTROL_PLANE_ISSUER` and `MARSEC_CONTROL_PLANE_JWKS_FILE`.
  Setting one without the other is an error rather than a partly enabled login. Setting neither leaves
  `POST /v1/auth/instance/login` unrouted, so an unconfigured store answers `404` instead of
  advertising a login it cannot perform.
- Values are trimmed, and a value that is only whitespace counts as unset.
- Login attempts are counted per source address, taken from the connection rather than from any
  forwarded header, so a client cannot choose its own bucket. Behind a proxy every request shares the
  proxy's address; put the limit in front of the proxy in that case.

## Production example

```sh
MARSEC_LISTEN_ADDR=0.0.0.0:8200
MARSEC_DATA_DIR=/var/lib/marstack-secrets
MARSEC_TLS_CERT_FILE=/etc/marstack-secrets/tls/server.pem
MARSEC_TLS_KEY_FILE=/etc/marstack-secrets/tls/server-key.pem
MARSEC_LOG_LEVEL=info
```

## Local development

```sh
make run
```

Equivalent to:

```sh
MARSEC_ALLOW_INSECURE_HTTP=true \
MARSEC_ALLOW_UNPROTECTED_MEMORY=true \
MARSEC_DATA_DIR="$PWD/.data" \
MARSEC_LOG_LEVEL=debug \
./bin/marsec server
```

The server logs a warning on every start in this mode. That warning is intentional and must not be
silenced.
