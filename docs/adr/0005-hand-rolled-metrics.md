# ADR 0005 — Hand-rolled metrics rather than the Prometheus client

- Status: accepted
- Date: 2026-08-25

## Context

The store needs to expose counters and gauges for scraping. The obvious answer is
`github.com/prometheus/client_golang`, which is the reference implementation and what every operator
expects behind a `/metrics` endpoint.

It also brings a dependency tree of roughly ten modules into a process that holds the encryption keys
for every tenant's secrets, in service of eight metrics of which none is a histogram or a summary.

## Decision

Implement the exposition format directly, in `internal/platform/metrics`. Counters, gauges, and
gauges backed by a function read at scrape time. Roughly two hundred lines, plus tests.

The text format is stable and simple: a `# HELP` line, a `# TYPE` line, then one sample per line with
label pairs. The parts that are easy to get wrong are the parts the tests pin: label values are
escaped for backslash, quote and newline; output is sorted so two scrapes of an unchanged registry are
byte identical; a counter refuses a negative addition.

Invalid metric names and duplicate registrations panic rather than returning an error. Registration
happens once at startup from constants in this repository, so an invalid name cannot appear at runtime
without appearing in a test run first, and a panic at boot is the correct outcome for a programming
mistake.

## Consequences

Positive:

- No new dependency, and nothing new for `govulncheck` to report on.
- The output is deterministic, which makes it testable by comparison rather than by parsing.
- Reading the code is enough to know exactly what is exposed.

Negative:

- No histograms or summaries. The only latency-shaped metric in the specification is unseal duration,
  which happens rarely enough that a gauge of the last value would do.
- No exemplars, no OpenMetrics, no native histogram support. Each of these is a reason to switch, not
  a reason to have started differently.
- The exposition format is implemented twice in the world, and one of those copies is ours. If the
  format gains a version this repository has to follow it.

## Triggers for revisiting

- A latency distribution genuinely needs percentiles rather than an average.
- OpenMetrics or exemplars become a requirement from the collector side.
- The metric count grows past what a reader can hold in their head.

## Note on scope

`GET /v1/sys/metrics` is unauthenticated and answers while sealed, matching `GET /v1/sys/seal-status`
which already is. Scraping a sealed store is exactly when the numbers matter most, and an
authenticated endpoint would be unreachable then, since auth itself is refused while sealed. No metric
carries a tenant, path, or identity label, so the exposure is aggregate. Restrict the listener at the
network level.
