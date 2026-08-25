package metrics

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	validMetricName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	validLabelName  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

type Registry struct {
	mu      sync.RWMutex
	order   []string
	metrics map[string]collector
}

type collector interface {
	name() string
	help() string
	kind() string
	samples() []sample
}

type sample struct {
	labels []string
	value  float64
}

func New() *Registry {
	return &Registry{metrics: make(map[string]collector)}
}

func (r *Registry) Counter(name, help string, labelNames ...string) *Counter {
	counter := &Counter{
		metricName:  name,
		metricHelp:  help,
		labelNames:  labelNames,
		labelValues: make(map[string]float64),
	}
	r.register(name, labelNames, counter)
	return counter
}

func (r *Registry) Gauge(name, help string, labelNames ...string) *Gauge {
	gauge := &Gauge{
		metricName:  name,
		metricHelp:  help,
		labelNames:  labelNames,
		labelValues: make(map[string]float64),
	}
	r.register(name, labelNames, gauge)
	return gauge
}

func (r *Registry) GaugeFunc(name, help string, read func() float64) {
	r.register(name, nil, &gaugeFunc{metricName: name, metricHelp: help, read: read})
}

func (r *Registry) register(name string, labelNames []string, metric collector) {
	if !validMetricName.MatchString(name) {
		panic("metrics: invalid metric name " + name)
	}
	for _, label := range labelNames {
		if !validLabelName.MatchString(label) {
			panic("metrics: invalid label name " + label)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, taken := r.metrics[name]; taken {
		panic("metrics: metric already registered: " + name)
	}
	r.metrics[name] = metric
	r.order = append(r.order, name)
}

func (r *Registry) Expose(w io.Writer) error {
	r.mu.RLock()
	names := append([]string{}, r.order...)
	collectors := make([]collector, 0, len(names))
	for _, name := range names {
		collectors = append(collectors, r.metrics[name])
	}
	r.mu.RUnlock()

	sort.Strings(names)
	sort.Slice(collectors, func(i, j int) bool {
		return collectors[i].name() < collectors[j].name()
	})

	var out strings.Builder
	for _, metric := range collectors {
		fmt.Fprintf(&out, "# HELP %s %s\n", metric.name(), metric.help())
		fmt.Fprintf(&out, "# TYPE %s %s\n", metric.name(), metric.kind())

		for _, one := range metric.samples() {
			out.WriteString(metric.name())
			out.WriteString(formatLabels(labelNamesOf(metric), one.labels))
			out.WriteString(" ")
			out.WriteString(strconv.FormatFloat(one.value, 'g', -1, 64))
			out.WriteString("\n")
		}
	}

	_, err := io.WriteString(w, out.String())
	return err
}

type Counter struct {
	metricName  string
	metricHelp  string
	labelNames  []string
	mu          sync.Mutex
	labelValues map[string]float64
}

func (c *Counter) Inc(labels ...string) {
	c.Add(1, labels...)
}

func (c *Counter) Add(delta float64, labels ...string) {
	if delta < 0 {
		return
	}
	key := joinLabels(labels)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.labelValues[key] += delta
}

func (c *Counter) name() string { return c.metricName }
func (c *Counter) help() string { return c.metricHelp }
func (c *Counter) kind() string { return "counter" }

func (c *Counter) samples() []sample {
	c.mu.Lock()
	defer c.mu.Unlock()
	return collect(c.labelValues)
}

type Gauge struct {
	metricName  string
	metricHelp  string
	labelNames  []string
	mu          sync.Mutex
	labelValues map[string]float64
}

func (g *Gauge) Set(value float64, labels ...string) {
	key := joinLabels(labels)

	g.mu.Lock()
	defer g.mu.Unlock()
	g.labelValues[key] = value
}

func (g *Gauge) name() string { return g.metricName }
func (g *Gauge) help() string { return g.metricHelp }
func (g *Gauge) kind() string { return "gauge" }

func (g *Gauge) samples() []sample {
	g.mu.Lock()
	defer g.mu.Unlock()
	return collect(g.labelValues)
}

type gaugeFunc struct {
	metricName string
	metricHelp string
	read       func() float64
}

func (g *gaugeFunc) name() string { return g.metricName }
func (g *gaugeFunc) help() string { return g.metricHelp }
func (g *gaugeFunc) kind() string { return "gauge" }

func (g *gaugeFunc) samples() []sample {
	return []sample{{value: g.read()}}
}

func labelNamesOf(metric collector) []string {
	switch typed := metric.(type) {
	case *Counter:
		return typed.labelNames
	case *Gauge:
		return typed.labelNames
	default:
		return nil
	}
}

const separator = "\x1f"

func joinLabels(values []string) string {
	return strings.Join(values, separator)
}

func collect(values map[string]float64) []sample {
	gathered := make([]sample, 0, len(values))
	for key, value := range values {
		var labels []string
		if key != "" {
			labels = strings.Split(key, separator)
		}
		gathered = append(gathered, sample{labels: labels, value: value})
	}

	sort.Slice(gathered, func(i, j int) bool {
		return joinLabels(gathered[i].labels) < joinLabels(gathered[j].labels)
	})
	return gathered
}

func formatLabels(names, values []string) string {
	if len(names) == 0 || len(values) == 0 {
		return ""
	}

	pairs := make([]string, 0, len(names))
	for index, name := range names {
		value := ""
		if index < len(values) {
			value = values[index]
		}
		pairs = append(pairs, name+`="`+escape(value)+`"`)
	}
	return "{" + strings.Join(pairs, ",") + "}"
}

func escape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(value)
}
