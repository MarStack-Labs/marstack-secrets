# The agent

An application should not have to know this store exists. The agent reads secrets and parameters,
renders them into files the application already reads, and reloads it when they change.

## Configuration

JSON rather than YAML, because YAML needs a dependency and this file is short. Unknown fields are
rejected, so a typo is an error at startup rather than a setting that silently does nothing.

```json
{
  "address": "https://secrets.internal:8200",
  "ca_cert_file": "/etc/marstack-secrets/tls/ca.pem",
  "tenant": "prod",
  "auth": {
    "method": "bootstrap",
    "credential_file": "/run/marstack-secrets/bootstrap-token"
  },
  "poll_interval": "1m",
  "renew_before": "5m",
  "templates": [
    {
      "source": "/etc/app/config.tmpl",
      "destination": "/run/secrets/app.ini",
      "mode": "0400",
      "command": ["systemctl", "reload", "app"]
    }
  ]
}
```

`auth.method` is `bootstrap` or `instance`. The credential file holds a bootstrap token or a control
plane assertion.

`command` is an argument list, not a shell string. There is no shell, so there is nothing to quote and
nothing to inject.

## Templates

Go's `text/template` with two functions:

```
password = {{ secret "apps/payment/db" }}
level    = {{ param "apps/billing/log_level" }}
```

Paths are relative to the configured tenant. A parameter follows inheritance and resolves any secret
references, so a template can name one parameter and receive a fully assembled connection string.

## What it guarantees

| Behaviour | Why |
|---|---|
| A destination is written only after every lookup in its template succeeded | A half rendered configuration file is worse than a stale one |
| Writes are atomic: a temporary file in the same directory, then a rename | The application never reads a partially written file |
| The command runs only when the content actually changed | A reload on every poll is a restart loop with extra steps |
| A failed cycle leaves the destination untouched | The rendered file *is* the last-known-good cache |
| Leases are renewed before they expire | A lease that lapses is a holding the store can no longer account for |
| A lease the store has forgotten is dropped, not retried forever | It will be reissued by the next read |

There is no separate cache. Keeping a second copy of the secrets on disk to survive an outage would
double the exposure to halve an inconvenience. The rendered file already is that copy, so the agent
simply declines to overwrite it with anything worse.

## Running it

```sh
marsec agent --config /etc/marstack-secrets/agent.json
marsec agent --config /etc/marstack-secrets/agent.json --once
```

`--once` renders and exits, which is what a deployment step or a smoke test wants. Without it the
agent stays resident and polls with jitter around `poll_interval`, so a fleet does not converge on one
instant.
