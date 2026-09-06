package lease

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const (
	pathList         = "/v1/sys/leases"
	pathRenew        = "/v1/sys/leases/renew"
	pathRevoke       = "/v1/sys/leases/revoke"
	pathRevokePrefix = "/v1/sys/leases/revoke-prefix"
)

type Authorizer interface {
	Permitted(ctx context.Context, identity authn.Identity, tenant, path string) (bool, error)
}

type Module struct {
	manager    *Manager
	authorizer Authorizer
	guard      httpx.Middleware
	logger     *slog.Logger
}

type ModuleOptions struct {
	Authorizer Authorizer
	Guard      httpx.Middleware
	Logger     *slog.Logger
}

type leaseView struct {
	ID        string `json:"lease_id"`
	Path      string `json:"path"`
	Version   int    `json:"version"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

type listResponse struct {
	Leases []leaseView `json:"leases"`
}

type renewRequest struct {
	LeaseID string `json:"lease_id"`
	TTL     int    `json:"ttl"`
}

type revokeRequest struct {
	LeaseID string `json:"lease_id"`
}

type prefixRequest struct {
	Prefix string `json:"prefix"`
}

type revocationResponse struct {
	Leases     int      `json:"leases"`
	Identities []string `json:"identities"`
	Tokens     int      `json:"tokens"`
}

func NewModule(manager *Manager, opts ModuleOptions) *Module {
	return &Module{
		manager:    manager,
		authorizer: opts.Authorizer,
		guard:      opts.Guard,
		logger:     opts.Logger,
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.Handle("GET "+pathList, m.guard(http.HandlerFunc(m.handleList)))
	mux.Handle("PUT "+pathRenew, m.guard(http.HandlerFunc(m.handleRenew)))
	mux.Handle("PUT "+pathRevoke, m.guard(http.HandlerFunc(m.handleRevoke)))
	mux.Handle("PUT "+pathRevokePrefix, m.guard(http.HandlerFunc(m.handleRevokePrefix)))
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) {
	identity, ok := caller(w, r)
	if !ok {
		return
	}

	held, err := m.manager.Active(r.Context(), identity.Tenant, identity.ID)
	if err != nil {
		m.internal(w, r, "listing leases", err)
		return
	}

	views := make([]leaseView, 0, len(held))
	for _, one := range held {
		views = append(views, render(one))
	}
	httpx.JSON(w, http.StatusOK, listResponse{Leases: views})
}

func (m *Module) handleRenew(w http.ResponseWriter, r *http.Request) {
	identity, ok := caller(w, r)
	if !ok {
		return
	}

	var request renewRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	ttl := DefaultTTL
	if request.TTL > 0 {
		ttl = time.Duration(request.TTL) * time.Second
	}

	renewed, err := m.manager.Renew(r.Context(), request.LeaseID, identity.ID, ttl)
	if err != nil {
		m.refuse(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, render(renewed))
}

func (m *Module) handleRevoke(w http.ResponseWriter, r *http.Request) {
	identity, ok := caller(w, r)
	if !ok {
		return
	}

	var request revokeRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	held, err := m.manager.read(r.Context(), m.manager.db, request.LeaseID)
	if err != nil {
		m.refuse(w, r, err)
		return
	}
	if held.IdentityID != identity.ID || held.Tenant != identity.Tenant {
		httpx.Problem(w, http.StatusNotFound, "not_found")
		return
	}

	if err := m.manager.Revoke(r.Context(), request.LeaseID); err != nil {
		m.refuse(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleRevokePrefix(w http.ResponseWriter, r *http.Request) {
	identity, ok := caller(w, r)
	if !ok {
		return
	}

	var request prefixRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	permitted, err := m.authorizer.Permitted(r.Context(), identity, identity.Tenant, request.Prefix)
	if err != nil {
		m.internal(w, r, "authorizing a prefix revocation", err)
		return
	}
	if !permitted {
		m.logger.Warn("prefix revocation refused",
			"request_id", httpx.RequestIDFrom(r.Context()),
			"identity", identity,
			"prefix", request.Prefix)
		httpx.Problem(w, http.StatusForbidden, "forbidden")
		return
	}

	revocation, err := m.manager.RevokePrefix(r.Context(), identity.Tenant, request.Prefix)
	if err != nil {
		m.refuse(w, r, err)
		return
	}

	m.logger.Warn("leases revoked by prefix",
		"request_id", httpx.RequestIDFrom(r.Context()),
		"identity", identity,
		"prefix", request.Prefix,
		"leases", revocation.Leases,
		"identities", revocation.Identities,
		"tokens", revocation.Tokens)

	httpx.JSON(w, http.StatusOK, revocationResponse(revocation))
}

func (m *Module) refuse(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrGone), errors.Is(err, ErrNotFound), errors.Is(err, ErrNotHolder):
		httpx.Problem(w, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrInvalidTTL), errors.Is(err, ErrInvalidPath), errors.Is(err, ErrInvalidTenant):
		httpx.Problem(w, http.StatusBadRequest, "invalid_request")
	default:
		m.internal(w, r, "serving a lease request", err)
	}
}

func (m *Module) internal(w http.ResponseWriter, r *http.Request, what string, err error) {
	m.logger.Error(what, "request_id", httpx.RequestIDFrom(r.Context()), "error", err)
	httpx.Problem(w, http.StatusInternalServerError, "internal_error")
}

func caller(w http.ResponseWriter, r *http.Request) (authn.Identity, bool) {
	identity, present := authn.IdentityFrom(r.Context())
	if !present {
		httpx.Problem(w, http.StatusUnauthorized, "unauthenticated")
		return authn.Identity{}, false
	}
	return identity, true
}

func render(held Lease) leaseView {
	return leaseView{
		ID:        held.ID,
		Path:      held.Path,
		Version:   held.Version,
		IssuedAt:  held.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt: held.ExpiresAt.UTC().Format(time.RFC3339),
	}
}
