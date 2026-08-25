# ADR 0002 — Standard library first, dependencies by exception

- Status: accepted
- Date: 2026-08-25

## Context

The obvious starting kit for a Go service is a CLI framework, a router, a configuration library, and
a logging library. Each is defensible on its own. Together they are four supply chains attached to a
process that holds the encryption keys for every tenant's secrets, before a single line of domain
logic exists.

Go 1.22 added method and wildcard patterns to `http.ServeMux`, and Go 1.21 added `log/slog`. Two of
the four are now standard library features.

## Decision

Start with the standard library and add a dependency only when it cannot do the job. Each addition
gets an ADR recording what it replaced and why.

Current state:

| Concern | Choice |
|---|---|
| Routing | `http.ServeMux` with `"GET /v1/sys/health"` patterns |
| Logging | `log/slog` with the JSON handler |
| Configuration | Environment variables parsed into one struct |
| CLI | Subcommand dispatch in `main`, roughly thirty lines |
| Random identifiers | `crypto/rand.Text` |

The direct dependency count is currently zero.

## Consequences

Positive:

- Nothing to review in `go.mod`, and `govulncheck` has almost no surface to report on.
- No framework conventions to learn before reading the code.
- Reproducible builds without a vendor directory.

Negative:

- Hand-rolled subcommand dispatch will become worse than a dependency as the CLI grows. It is
  expected to be replaced; `main` is deliberately thin so the replacement is contained.
- Environment variables will eventually stop expressing what an operator needs, particularly for
  seal configuration. A file format arrives then, with its own ADR.
- Some plumbing is written by hand — the middleware chain, the status recorder. Roughly a hundred
  lines, all of it tested.

## Triggers for revisiting

- The CLI exceeds a handful of commands with flags and subcommand trees.
- Seal configuration needs nested structure.
- The middleware chain grows beyond what a reader can follow in one screen.
