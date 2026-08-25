# ADR 0003 — Transport is secure by default and insecurely explicit

- Status: accepted
- Date: 2026-08-25

## Context

Local development needs an easy way to reach the server. The usual accommodation is to serve
plaintext HTTP by default and enable TLS through configuration. For a service that returns secrets
in response bodies, that default is backwards: forgetting to set a flag would put credentials on the
wire in plaintext.

The opposite extreme, TLS with no exception, makes `make run` and integration tests require a
certificate before anything can be tried.

## Decision

TLS is the default and its absence is an error. The server refuses to start unless
`MARSEC_TLS_CERT_FILE` and `MARSEC_TLS_KEY_FILE` are both set, with `tls.VersionTLS13` as the
minimum.

Plaintext HTTP requires `MARSEC_ALLOW_INSECURE_HTTP=true`. In that mode:

- Startup logs a warning on every boot, not only the first.
- Supplying TLS material as well is a configuration error, so the transport in use is never
  ambiguous.

The listen address defaults to `127.0.0.1:8200` rather than all interfaces, so a deployment that
forgets to set it is unreachable from the network instead of quietly exposed.

## Consequences

Positive:

- The insecure path cannot be reached by omission, only by an explicit statement in the environment.
- The warning makes an insecure production deployment visible in logs and in any dashboard built on
  them.
- The mutual exclusion removes a class of incident where TLS is configured but not actually serving.

Negative:

- Any deployment tooling must supply certificates before the process will start. That is the intent.
- Tests that need a live listener use insecure mode. `TestServeRequiresTLSMaterialWhenNotInsecure`
  covers the secure path by asserting that startup fails without usable certificates.

## Related

The full transport and hardening requirements, including `mlock`, disabled core dumps, and disabled
swap, are in the specification and in `docs/THREAT-MODEL.md`.
