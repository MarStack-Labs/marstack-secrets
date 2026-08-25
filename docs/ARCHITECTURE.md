# Architecture

## Shape: modular monolith

One binary, one process, one deployment unit. Inside it, the code is split into modules with
explicit boundaries so that a module can be understood, tested, and later extracted without
untangling it from the rest.

This is deliberately not a set of microservices. A secret store is a single consistency domain: a
read must see the version that was just written, and a revocation must take effect immediately.
Splitting that across a network buys distribution problems and pays for nothing.

## Layout

```
cmd/marsec/               process entry point, flag and signal handling only
internal/
  app/                    composition root: owns the module list and the middleware chain
  modules/                one directory per bounded capability
    health/
  platform/               shared infrastructure with no domain knowledge
    config/
    httpx/
    logging/
scripts/
docs/
```

## Dependency rules

```
cmd  ──▶  app     ──▶  modules  ──▶  platform
      │           └──────────────▶  platform
      └──▶  client ──────────────▶  platform
```

Six rules, enforced by `make arch-check`:

1. A module must not import another module.
2. A module must not import `internal/app`.
3. `internal/platform` must not import `internal/modules` or `internal/app`.
4. Everything may import `internal/platform`.
5. `internal/client` must not import modules or the composition root. It speaks to the store over
   HTTP like any other caller, so sharing types with the server would let a server change quietly
   become a client change.
6. The server must not import `internal/client`. If a module ever needs to call the API it serves,
   something is wrong with the design rather than with the import.

Rule 1 is the one that keeps the monolith modular. When two modules need each other, the dependency
goes through an interface that the consumer declares and the composition root satisfies — never
through a direct import.

## The module contract

```go
type Module interface {
	Name() string
	Register(mux *http.ServeMux)
}
```

The interface is declared in `internal/app`, and Go's structural typing means modules satisfy it
without importing it. A module therefore has no compile-time knowledge that a composition root
exists. Adding a module is one line in `app.New`.

A module owns its own routes. There is no central routing table listing every path in the system,
because that file becomes a merge-conflict magnet and a place where a route can be registered
without the owning module noticing.

A module also owns its own schema. It declares its migrations and passes them to `sqlite.Migrate`
under its own name, for the same reason there is no central routing table.

Modules share a database but not each other's tables. A foreign key from one module's table into
another's would make the two schemas one, and a migration in either could then break the other. So
`policy_bindings` records an identity by its identifier with no foreign key to `auth_identities`: a
binding left behind by a deleted identity is inert, because an identity that cannot authenticate is
never evaluated.

A module satisfies the contract only once it has an HTTP surface to expose. `internal/modules/secret`
is a module with a Go API and no routes, and it stays that way until authentication exists in M3.

## Adding a module

1. Create `internal/modules/<name>/`.
2. Expose a type with `Name() string` and `Register(mux *http.ServeMux)`.
3. Keep HTTP handling, business rules, and storage in separate files inside the module.
4. Add it to the slice in `app.New`.
5. Test it through `httptest` against its own `http.ServeMux`, not through the full application.

Step 5 matters: a module test that boots the whole application is an integration test wearing a unit
test's clothes, and it stops telling you which boundary broke.

## Cross-cutting concerns

Request identifiers, security headers, access logging, and panic recovery live in the middleware
chain in `internal/app`, not in individual handlers. A module cannot forget to apply them, and a
module cannot opt out of them.

## What is not in the architecture yet

Storage, sealing, authentication, authorisation, leases, and auditing. Each arrives as its own module
or platform package as the roadmap progresses. The boundaries above exist now so that those modules
land in a structure rather than creating one.

`internal/platform/crypto` exists and has no HTTP surface. It is reachable only from Go code, which
is deliberate: a secret endpoint that predates authentication would be an unauthenticated secret
endpoint, however briefly.
