# Engineering principles

These are the rules this repository is held to. Each one is stated as something a reviewer can
check, not as an aspiration.

## KISS

Prefer the boring option that a new reader can follow without a diagram.

| Applied here | Instead of |
|---|---|
| `http.ServeMux` with `"GET /v1/sys/health"` patterns | A third-party router |
| Environment variables parsed into one struct | A configuration file format and its parser |
| Standard library subcommand dispatch in `main` | A CLI framework, until the command count justifies one |
| SQLite as the storage backend | An embedded consensus log |

A dependency is added when the standard library genuinely cannot do the job, and the reason is
recorded in an ADR.

## DRY

Duplication of *knowledge* is the target, not duplication of characters.

- The list of valid log levels exists once, in `internal/platform/logging`. Configuration validation
  calls into it rather than restating the list.
- Response encoding lives in `httpx.JSON` and `httpx.Problem`. No handler writes JSON by hand.
- `make check` is the single definition of "does this pass". CI calls the same target a developer
  calls, so the two can never drift.

Two pieces of code that look alike but change for different reasons stay separate.

## YAGNI

Build what the current milestone needs. Nothing in this repository exists for a requirement that has
not arrived.

Deliberately absent, with the trigger that will bring it in:

| Not built | Built when |
|---|---|
| CLI framework | The command count makes hand-rolled dispatch worse than a dependency |
| Configuration file format | Environment variables stop expressing what an operator needs |
| Module registry or plugin system | Modules need to be enabled at runtime, not at compile time |
| High availability and consensus | Auto-unseal exists, because failover without it still needs a human |
| Dynamic secrets, PKI, transit | The core store is complete and audited |

Absence is a decision. When a reviewer asks "where is X", the answer is in this table or it is a
genuine gap.

## Separation of concerns

Each package answers one question.

| Package | Question |
|---|---|
| `platform/config` | What did the operator ask for, and is it valid? |
| `platform/logging` | How is a log record shaped? |
| `platform/httpx` | How does an HTTP request enter and leave the process? |
| `modules/<name>` | What does this capability do? |
| `app` | Which modules exist, and how are they wired? |
| `cmd/marsec` | What did the user type, and which signal ended the process? |

`platform/httpx` takes its own `ServerConfig` rather than `config.Config`. The extra struct keeps
transport code independent of the application's configuration schema, so the schema can change
without touching the server.

## SOLID

**Single responsibility.** A module handles one capability. When a module needs a second reason to
change, it splits.

**Open/closed.** Adding a capability means adding a module and one line in `app.New`. No existing
module is edited, and the middleware chain is untouched.

**Liskov substitution.** Anything satisfying `Module` can be mounted. `Register` must only add
routes; a module that mutates global state during registration breaks the substitution and is a bug.

**Interface segregation.** `Module` has two methods. Interfaces are declared by the consumer, sized
to what the consumer uses, and never grown to cover a possible future caller.

**Dependency inversion.** `config.Load` takes a `func(string) string` rather than calling
`os.Getenv`, so configuration is tested without touching process state. Handlers take a `*slog.Logger`
rather than reaching for the default logger. The composition root is the only place that knows about
concrete implementations.

## Testing

- Tests exercise packages through their public surface, using `httptest` and `t.TempDir()`.
- No test spawns a process or binds a fixed port.
- A bug fix arrives with the test that would have caught it.
- Security behaviour is asserted, not assumed: that panics do not leak internals, that health does
  not leak build details, that plaintext HTTP is off unless explicitly requested.

## Comments

Code carries no comments. Names, types, and tests carry the meaning. Anything that genuinely needs
explaining — a trade-off, a non-obvious constraint, a rejected alternative — goes into `docs/` or an
ADR, where it can be found and kept current.
