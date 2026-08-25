package param

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/audit"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const (
	pathData = "/v1/param/data/{tenant}/{path...}"
	pathList = "/v1/param/list/{tenant}"
)

type Module struct {
	service    *Service
	authorizer Authorizer
	audit      audit.Sink
	guard      httpx.Middleware
	logger     *slog.Logger
}

type ModuleOptions struct {
	Authorizer Authorizer
	Audit      audit.Sink
	Guard      httpx.Middleware
	Logger     *slog.Logger
}

type writeRequest struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type readResponse struct {
	Path         string   `json:"path"`
	ResolvedFrom string   `json:"resolved_from"`
	Inherited    bool     `json:"inherited"`
	Kind         string   `json:"kind"`
	Value        string   `json:"value"`
	Sensitive    bool     `json:"sensitive"`
	References   []string `json:"references"`
	UpdatedAt    string   `json:"updated_at"`
	UpdatedBy    string   `json:"updated_by"`
}

type listEntry struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	UpdatedAt string `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

type listResponse struct {
	Parameters []listEntry `json:"parameters"`
}

func NewModule(service *Service, opts ModuleOptions) *Module {
	return &Module{
		service:    service,
		authorizer: opts.Authorizer,
		audit:      opts.Audit,
		guard:      opts.Guard,
		logger:     opts.Logger,
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.Handle("GET "+pathData, m.guard(http.HandlerFunc(m.handleRead)))
	mux.Handle("PUT "+pathData, m.guard(http.HandlerFunc(m.handleWrite)))
	mux.Handle("DELETE "+pathData, m.guard(http.HandlerFunc(m.handleDelete)))
	mux.Handle("GET "+pathList, m.guard(http.HandlerFunc(m.handleList)))
}

func (m *Module) handleRead(w http.ResponseWriter, r *http.Request) {
	identity, tenant, path, ok := m.permitted(w, r, authz.Read, r.PathValue("path"))
	if !ok {
		return
	}

	resolved, err := m.service.Resolve(r.Context(), identity, tenant, path)
	if err != nil {
		m.fail(w, r, err)
		return
	}

	if !m.recorded(w, r, "param.read", identity, tenant, path, audit.ResultAllow, authz.Decision{}) {
		return
	}

	references := resolved.References
	if references == nil {
		references = []string{}
	}

	httpx.JSON(w, http.StatusOK, readResponse{
		Path:         resolved.Path,
		ResolvedFrom: resolved.ResolvedFrom,
		Inherited:    resolved.Inherited(),
		Kind:         string(resolved.Kind),
		Value:        resolved.Value,
		Sensitive:    resolved.Sensitive,
		References:   references,
		UpdatedAt:    resolved.UpdatedAt.UTC().Format(time.RFC3339),
		UpdatedBy:    resolved.UpdatedBy,
	})
}

func (m *Module) handleWrite(w http.ResponseWriter, r *http.Request) {
	identity, tenant, path, ok := m.permitted(w, r, authz.Write, r.PathValue("path"))
	if !ok {
		return
	}

	var request writeRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	if err := m.service.Store().Put(r.Context(), tenant, path, Kind(request.Kind), request.Value, identity.ID); err != nil {
		m.fail(w, r, err)
		return
	}
	if !m.recorded(w, r, "param.write", identity, tenant, path, audit.ResultAllow, authz.Decision{}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	identity, tenant, path, ok := m.permitted(w, r, authz.Delete, r.PathValue("path"))
	if !ok {
		return
	}

	if err := m.service.Store().Delete(r.Context(), tenant, path); err != nil {
		m.fail(w, r, err)
		return
	}
	if !m.recorded(w, r, "param.delete", identity, tenant, path, audit.ResultAllow, authz.Decision{}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	identity, tenant, _, ok := m.permitted(w, r, authz.List, prefix+"*")
	if !ok {
		return
	}

	found, err := m.service.Store().List(r.Context(), tenant, prefix)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if !m.recorded(w, r, "param.list", identity, tenant, prefix, audit.ResultAllow, authz.Decision{}) {
		return
	}

	entries := make([]listEntry, 0, len(found))
	for _, one := range found {
		entries = append(entries, listEntry{
			Path:      one.Path,
			Kind:      string(one.Kind),
			UpdatedAt: one.UpdatedAt.UTC().Format(time.RFC3339),
			UpdatedBy: one.UpdatedBy,
		})
	}
	httpx.JSON(w, http.StatusOK, listResponse{Parameters: entries})
}

func (m *Module) permitted(w http.ResponseWriter, r *http.Request, capability authz.Capability, path string) (authn.Identity, string, string, bool) {
	identity, present := authn.IdentityFrom(r.Context())
	if !present {
		httpx.Problem(w, http.StatusUnauthorized, "unauthenticated")
		return authn.Identity{}, "", "", false
	}

	tenant := r.PathValue("tenant")
	if tenant == "" {
		httpx.Problem(w, http.StatusNotFound, "not_found")
		return authn.Identity{}, "", "", false
	}

	decision, err := m.authorizer.Authorize(r.Context(), identity, tenant, PolicyPath(tenant, path), capability)
	if err != nil {
		m.logger.Error("authorizing a parameter request",
			"request_id", httpx.RequestIDFrom(r.Context()), "error", err)
		httpx.Problem(w, http.StatusInternalServerError, "internal_error")
		return authn.Identity{}, "", "", false
	}
	if !decision.Allowed {
		m.logger.Warn("parameter request refused",
			"request_id", httpx.RequestIDFrom(r.Context()),
			"identity", identity,
			"capability", string(capability),
			"decision", decision)

		if !m.recorded(w, r, "param."+string(capability), identity, tenant, path, audit.ResultDeny, decision) {
			return authn.Identity{}, "", "", false
		}
		httpx.Problem(w, http.StatusForbidden, "forbidden")
		return authn.Identity{}, "", "", false
	}
	return identity, tenant, path, true
}

func (m *Module) recorded(w http.ResponseWriter, r *http.Request, operation string, identity authn.Identity, tenant, path, result string, decision authz.Decision) bool {
	err := m.audit.Append(r.Context(), audit.Event{
		Operation: operation,
		Identity:  identity.ID,
		Tenant:    tenant,
		Path:      PolicyPath(tenant, path),
		Result:    result,
		Policy:    decision.Policy,
		Rule:      decision.Rule,
		RequestID: httpx.RequestIDFrom(r.Context()),
		SourceIP:  httpx.RemoteIP(r),
	})
	if err == nil {
		return true
	}

	m.logger.Error("the audit sink refused a record; the request is refused with it",
		"request_id", httpx.RequestIDFrom(r.Context()), "operation", operation, "error", err)
	httpx.Problem(w, http.StatusServiceUnavailable, "audit_unavailable")
	return false
}

func (m *Module) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrReferenceMissing):
		httpx.Problem(w, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrReferenceForbidden):
		httpx.Problem(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, ErrInvalidKind), errors.Is(err, ErrInvalidValue):
		httpx.Problem(w, http.StatusBadRequest, "invalid_value")
	case errors.Is(err, ErrBadReference), errors.Is(err, ErrTooManyReferences):
		httpx.Problem(w, http.StatusUnprocessableEntity, "invalid_reference")
	case errors.Is(err, ErrInvalidTenant), errors.Is(err, ErrInvalidPath), errors.Is(err, ErrValueTooLarge):
		httpx.Problem(w, http.StatusBadRequest, "invalid_location")
	default:
		m.logger.Error("serving a parameter request",
			"request_id", httpx.RequestIDFrom(r.Context()),
			"path", r.URL.Path,
			"error", err)
		httpx.Problem(w, http.StatusInternalServerError, "internal_error")
	}
}
