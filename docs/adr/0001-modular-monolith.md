# ADR 0001 — Modular monolith over microservices

- Status: accepted
- Date: 2026-08-25

## Context

The store must hold secrets and parameters, authenticate machine identities, evaluate policies, track
leases, and write an audit record for every access. These responsibilities are separable in code, and
the obvious cloud-native instinct is to separate them in deployment too.

Two facts argue against that. First, a secret store is one consistency domain: a read must observe
the version just written, and a revocation must take effect immediately. Second, the audit record and
the access it describes must commit together — a distributed transaction is the wrong tool for the
most security-critical write in the system.

## Decision

One binary, one process, one deployment unit. Internally the code is divided into modules under
`internal/modules`, shared infrastructure under `internal/platform`, and a composition root in
`internal/app`.

Four dependency rules, enforced in CI by `scripts/check-architecture.sh`:

1. A module must not import another module.
2. A module must not import the composition root.
3. Platform packages must not import modules or the composition root.
4. Everything may import platform packages.

The module contract is two methods, `Name()` and `Register(*http.ServeMux)`, declared in
`internal/app`. Go's structural typing means modules satisfy it without importing it, so a module has
no compile-time knowledge that a composition root exists.

## Consequences

Positive:

- Strong consistency is free rather than engineered.
- The audit write and the access it describes share a transaction.
- Boundaries are checked mechanically, so "modular" does not decay into "one package that imports
  everything".
- A module can later be extracted into a service, because the boundary it would need already exists.

Negative:

- Nothing scales independently. Accepted: the expected load is read-heavy and small, and a single
  node with a client-side cache covers it.
- The boundaries need enforcement, because nothing in the compiler prevents a module importing its
  neighbour. Hence rule 1 and the CI gate.
- All modules share a failure domain. This is also true of the alternative for the write path, and
  the client-side cache in the agent is the real availability answer.

## Alternatives rejected

**Microservices per capability.** Buys independent scaling that is not needed, pays with distributed
transactions on the audit path and eventual consistency on the read path.

**Single flat package.** Simpler on day one. By M5 the lease manager, policy engine, and storage layer
would be mutually entangled, and every test would need the whole system.
