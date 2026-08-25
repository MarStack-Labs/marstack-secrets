package health

import (
	"net/http"

	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

type Module struct{}

type status struct {
	Status string `json:"status"`
}

func New() *Module {
	return &Module{}
}

func (m *Module) Name() string {
	return "health"
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/sys/health", m.handleHealth)
}

func (m *Module) handleHealth(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, status{Status: "ok"})
}
