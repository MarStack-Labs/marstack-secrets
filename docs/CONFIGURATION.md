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

## Validation rules

- `MARSEC_DATA_DIR` must be an absolute path.
- `MARSEC_SHUTDOWN_TIMEOUT` must be greater than zero.
- Either TLS material is supplied, or `MARSEC_ALLOW_INSECURE_HTTP` is true. Supplying both is an
  error, so there is never a question about which transport is actually in use.

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
MARSEC_DATA_DIR="$PWD/.data" \
MARSEC_LOG_LEVEL=debug \
./bin/marsec server
```

The server logs a warning on every start in this mode. That warning is intentional and must not be
silenced.
