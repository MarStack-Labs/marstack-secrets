package observe

import (
	"net/http"

	"github.com/marstack-labs/marstack-secrets/internal/platform/metrics"
)

const (
	moduleName  = "observe"
	pathMetrics = "/v1/sys/metrics"
	contentType = "text/plain; version=0.0.4; charset=utf-8"
)

type Module struct {
	registry *metrics.Registry
}

func NewModule(registry *metrics.Registry) *Module {
	return &Module{registry: registry}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+pathMetrics, m.handleMetrics)
}

func (m *Module) PathsAllowedWhileSealed() []string {
	return []string{pathMetrics}
}

func (m *Module) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", contentType)
	if err := m.registry.Expose(w); err != nil {
		return
	}
}
