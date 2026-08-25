package policy

import (
	"log/slog"
	"net/http"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const pathCheck = "/v1/sys/policies/check"

type Module struct {
	manager *Manager
	guard   httpx.Middleware
	logger  *slog.Logger
}

type checkRequest struct {
	Tenant     string `json:"tenant"`
	Path       string `json:"path"`
	Capability string `json:"capability"`
}

type checkResponse struct {
	Allowed  bool     `json:"allowed"`
	Policy   string   `json:"policy,omitempty"`
	Rule     string   `json:"rule,omitempty"`
	Reason   string   `json:"reason"`
	Policies []string `json:"policies"`
}

func NewModule(manager *Manager, guard httpx.Middleware, logger *slog.Logger) *Module {
	return &Module{manager: manager, guard: guard, logger: logger}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.Handle("POST "+pathCheck, m.guard(http.HandlerFunc(m.handleCheck)))
}

func (m *Module) handleCheck(w http.ResponseWriter, r *http.Request) {
	identity, present := authn.IdentityFrom(r.Context())
	if !present {
		httpx.Problem(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	var request checkRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	capability := authz.Capability(request.Capability)
	if !capability.Grantable() {
		httpx.Problem(w, http.StatusBadRequest, "invalid_capability")
		return
	}

	decision, err := m.manager.Authorize(r.Context(), identity, request.Tenant, request.Path, capability)
	if err != nil {
		m.logger.Error("checking a policy",
			"request_id", httpx.RequestIDFrom(r.Context()), "error", err)
		httpx.Problem(w, http.StatusInternalServerError, "internal_error")
		return
	}

	bound, err := m.manager.BindingsFor(r.Context(), identity.Tenant, identity.ID)
	if err != nil {
		m.logger.Error("listing bound policies",
			"request_id", httpx.RequestIDFrom(r.Context()), "error", err)
		httpx.Problem(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if bound == nil {
		bound = []string{}
	}

	httpx.JSON(w, http.StatusOK, checkResponse{
		Allowed:  decision.Allowed,
		Policy:   decision.Policy,
		Rule:     decision.Rule,
		Reason:   decision.Reason,
		Policies: bound,
	})
}
