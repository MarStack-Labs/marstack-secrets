package metrics

import (
	"strings"
	"sync"
	"testing"
)

func render(t *testing.T, registry *Registry) string {
	t.Helper()
	var out strings.Builder
	if err := registry.Expose(&out); err != nil {
		t.Fatalf("WriteTo returned error: %v", err)
	}
	return out.String()
}

func TestACounterExposesItsTotal(t *testing.T) {
	registry := New()
	requests := registry.Counter("marsec_requests_total", "Requests served.", "operation", "result")

	requests.Inc("secret.read", "allow")
	requests.Inc("secret.read", "allow")
	requests.Inc("secret.read", "deny")
	requests.Add(3, "secret.write", "allow")

	rendered := render(t, registry)

	for _, expected := range []string{
		"# HELP marsec_requests_total Requests served.",
		"# TYPE marsec_requests_total counter",
		`marsec_requests_total{operation="secret.read",result="allow"} 2`,
		`marsec_requests_total{operation="secret.read",result="deny"} 1`,
		`marsec_requests_total{operation="secret.write",result="allow"} 3`,
	} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("the output is missing %q:\n%s", expected, rendered)
		}
	}
}

func TestACounterNeverGoesBackwards(t *testing.T) {
	registry := New()
	failures := registry.Counter("marsec_failures_total", "Failures.")

	failures.Inc()
	failures.Add(-5)

	if !strings.Contains(render(t, registry), "marsec_failures_total 1") {
		t.Errorf("a negative addition changed the total:\n%s", render(t, registry))
	}
}

func TestAGaugeHoldsTheLastValue(t *testing.T) {
	registry := New()
	active := registry.Gauge("marsec_leases_active", "Active leases.")

	active.Set(7)
	active.Set(4)

	rendered := render(t, registry)
	if !strings.Contains(rendered, "# TYPE marsec_leases_active gauge") {
		t.Errorf("the gauge is not typed:\n%s", rendered)
	}
	if !strings.Contains(rendered, "marsec_leases_active 4") {
		t.Errorf("the gauge does not hold the last value:\n%s", rendered)
	}
}

func TestAGaugeFuncIsReadAtScrapeTime(t *testing.T) {
	registry := New()
	value := 0.0
	reads := 0

	registry.GaugeFunc("marsec_sealed", "Whether the store is sealed.", func() float64 {
		reads++
		return value
	})

	value = 1
	if !strings.Contains(render(t, registry), "marsec_sealed 1") {
		t.Error("the first scrape did not see the current value")
	}

	value = 0
	if !strings.Contains(render(t, registry), "marsec_sealed 0") {
		t.Error("the second scrape did not see the new value")
	}
	if reads != 2 {
		t.Errorf("the function was read %d times, want once per scrape", reads)
	}
}

func TestLabelValuesAreEscaped(t *testing.T) {
	registry := New()
	requests := registry.Counter("marsec_requests_total", "Requests.", "operation")

	requests.Inc(`say "hi"\` + "\nagain")

	rendered := render(t, registry)
	if !strings.Contains(rendered, `operation="say \"hi\"\\\nagain"`) {
		t.Errorf("the label value is not escaped:\n%s", rendered)
	}
	if strings.Count(rendered, "\n") != 3 {
		t.Errorf("a newline escaped into the output as a line break:\n%q", rendered)
	}
}

func TestOutputIsStableAcrossScrapes(t *testing.T) {
	registry := New()
	requests := registry.Counter("marsec_requests_total", "Requests.", "operation")

	for _, operation := range []string{"zebra", "alpha", "middle"} {
		requests.Inc(operation)
	}

	first := render(t, registry)
	for range 5 {
		if render(t, registry) != first {
			t.Fatal("two scrapes of an unchanged registry produced different output")
		}
	}

	alpha := strings.Index(first, `operation="alpha"`)
	middle := strings.Index(first, `operation="middle"`)
	zebra := strings.Index(first, `operation="zebra"`)
	if !(alpha < middle && middle < zebra) {
		t.Errorf("samples are not sorted:\n%s", first)
	}
}

func TestMetricsAreSortedByName(t *testing.T) {
	registry := New()
	registry.Counter("marsec_zebra_total", "Zebra.")
	registry.Counter("marsec_alpha_total", "Alpha.")

	rendered := render(t, registry)
	if strings.Index(rendered, "marsec_alpha_total") > strings.Index(rendered, "marsec_zebra_total") {
		t.Errorf("metrics are not sorted:\n%s", rendered)
	}
}

func TestInvalidNamesAreRefusedAtRegistration(t *testing.T) {
	cases := map[string]func(){
		"metric with a dash":           func() { New().Counter("marsec-requests", "Requests.") },
		"metric starting with a digit": func() { New().Counter("1marsec", "Requests.") },
		"empty metric":                 func() { New().Counter("", "Requests.") },
		"label with a dash":            func() { New().Counter("marsec_requests_total", "Requests.", "the-op") },
		"duplicate metric": func() {
			registry := New()
			registry.Counter("marsec_requests_total", "Requests.")
			registry.Gauge("marsec_requests_total", "Requests.")
		},
	}

	for name, register := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered == nil {
					t.Fatal("expected registration to panic")
				}
			}()
			register()
		})
	}
}

func TestCountersAreSafeUnderConcurrentUse(t *testing.T) {
	registry := New()
	requests := registry.Counter("marsec_requests_total", "Requests.", "operation")
	active := registry.Gauge("marsec_leases_active", "Leases.")

	var group sync.WaitGroup
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for round := range 250 {
				requests.Inc("secret.read")
				active.Set(float64(worker * round))
			}
		}()
	}
	group.Wait()

	if !strings.Contains(render(t, registry), `marsec_requests_total{operation="secret.read"} 2000`) {
		t.Errorf("the total is wrong:\n%s", render(t, registry))
	}
}

func TestAnEmptyRegistryRendersNothing(t *testing.T) {
	if rendered := render(t, New()); rendered != "" {
		t.Errorf("an empty registry rendered %q", rendered)
	}
}
