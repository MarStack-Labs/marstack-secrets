package health

import (
	"net/http"

	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const path = "/v1/sys/health"

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
	mux.HandleFunc("GET "+path, m.handleHealth)
}

func (m *Module) PathsAllowedWhileSealed() []string {
	return []string{path}
}

func (m *Module) handleHealth(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, status{Status: "ok"})
}
