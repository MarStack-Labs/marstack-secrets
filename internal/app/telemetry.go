package app

import (
	"context"
	"net/http"

	"github.com/marstack-labs/marstack-secrets/internal/modules/lease"
	"github.com/marstack-labs/marstack-secrets/internal/modules/seal"
	"github.com/marstack-labs/marstack-secrets/internal/platform/audit"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
	"github.com/marstack-labs/marstack-secrets/internal/platform/metrics"
)

type telemetry struct {
	registry *metrics.Registry
	requests *metrics.Counter
	audited  *metrics.Counter
}

func newTelemetry(sealManager *seal.Manager, leaseManager *lease.Manager, trail *audit.Log) *telemetry {
	registry := metrics.New()

	instrument := &telemetry{
		registry: registry,
		requests: registry.Counter("marsec_http_requests_total",
			"HTTP requests served, by method and status.", "method", "status"),
		audited: registry.Counter("marsec_audit_records_total",
			"Audit records offered to the sink, by outcome.", "outcome"),
	}

	registry.GaugeFunc("marsec_initialized",
		"Whether the store has been initialized.", func() float64 {
			status, err := sealManager.Status(context.Background())
			if err != nil || status.State == seal.StateUninitialized {
				return 0
			}
			return 1
		})

	registry.GaugeFunc("marsec_sealed",
		"Whether the store is sealed and therefore serving nothing.", func() float64 {
			if sealManager.IsUnsealed() {
				return 0
			}
			return 1
		})

	registry.GaugeFunc("marsec_audit_records",
		"Records written to the audit log since it was created.", func() float64 {
			return float64(trail.Sequence())
		})

	registry.GaugeFunc("marsec_leases_active",
		"Leases currently held across every tenant.", func() float64 {
			held, err := leaseManager.CountActive(context.Background())
			if err != nil {
				return -1
			}
			return float64(held)
		})

	return instrument
}

func (t *telemetry) middleware() httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder := &statusWatcher{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(recorder, r)
			t.requests.Inc(r.Method, http.StatusText(recorder.status))
		})
	}
}

func (t *telemetry) sink(inner audit.Sink) audit.Sink {
	return countingSink{inner: inner, counter: t.audited}
}

type countingSink struct {
	inner   audit.Sink
	counter *metrics.Counter
}

func (c countingSink) Append(ctx context.Context, event audit.Event) error {
	err := c.inner.Append(ctx, event)
	if err != nil {
		c.counter.Inc("refused")
		return err
	}
	c.counter.Inc("written")
	return nil
}

type statusWatcher struct {
	http.ResponseWriter
	status int
	sent   bool
}

func (s *statusWatcher) WriteHeader(status int) {
	if s.sent {
		return
	}
	s.status = status
	s.sent = true
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusWatcher) Write(b []byte) (int, error) {
	s.sent = true
	return s.ResponseWriter.Write(b)
}
