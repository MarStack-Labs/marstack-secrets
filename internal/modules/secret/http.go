package secret

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const (
	pathData     = "/v1/secret/data/{tenant}/{path...}"
	pathMetadata = "/v1/secret/metadata/{tenant}/{path...}"
	namespace    = "secret"
)

type Authorizer interface {
	Authorize(ctx context.Context, identity authn.Identity, tenant, path string, capability authz.Capability) (authz.Decision, error)
}

type Module struct {
	service    *Service
	authorizer Authorizer
	guard      httpx.Middleware
	logger     *slog.Logger
}

type writeRequest struct {
	Value string `json:"value"`
	CAS   *int   `json:"cas"`
}

type writeResponse struct {
	Version int `json:"version"`
}

type readResponse struct {
	Value     string `json:"value"`
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
}

type metadataResponse struct {
	CurrentVersion int    `json:"current_version"`
	MaxVersions    int    `json:"max_versions"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

func NewModule(service *Service, authorizer Authorizer, guard httpx.Middleware, logger *slog.Logger) *Module {
	return &Module{service: service, authorizer: authorizer, guard: guard, logger: logger}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.Handle("GET "+pathData, m.guard(http.HandlerFunc(m.handleRead)))
	mux.Handle("PUT "+pathData, m.guard(http.HandlerFunc(m.handleWrite)))
	mux.Handle("DELETE "+pathData, m.guard(http.HandlerFunc(m.handleDelete)))
	mux.Handle("GET "+pathMetadata, m.guard(http.HandlerFunc(m.handleMetadata)))
}

func (m *Module) handleRead(w http.ResponseWriter, r *http.Request) {
	tenant, path, ok := m.permitted(w, r, authz.Read)
	if !ok {
		return
	}

	version, err := requestedVersion(r)
	if err != nil {
		httpx.Problem(w, http.StatusBadRequest, "invalid_version")
		return
	}

	value, err := m.service.Get(r.Context(), tenant, path, version)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	defer value.Data.Zero()

	httpx.JSON(w, http.StatusOK, readResponse{
		Value:     string(value.Data),
		Version:   value.Version,
		CreatedAt: value.CreatedAt.UTC().Format(time.RFC3339),
	})
}

func (m *Module) handleWrite(w http.ResponseWriter, r *http.Request) {
	tenant, path, ok := m.permitted(w, r, authz.Write)
	if !ok {
		return
	}

	var request writeRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	value := crypto.Sensitive(request.Value)
	defer value.Zero()

	expectation := Any()
	if request.CAS != nil {
		if *request.CAS < 0 {
			httpx.Problem(w, http.StatusBadRequest, "invalid_version")
			return
		}
		expectation = AtVersion(*request.CAS)
	}

	version, err := m.service.Put(r.Context(), tenant, path, value, expectation)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, writeResponse{Version: version})
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	tenant, path, ok := m.permitted(w, r, authz.Delete)
	if !ok {
		return
	}

	if err := m.service.Delete(r.Context(), tenant, path); err != nil {
		m.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleMetadata(w http.ResponseWriter, r *http.Request) {
	tenant, path, ok := m.permitted(w, r, authz.Read)
	if !ok {
		return
	}

	metadata, err := m.service.Metadata(r.Context(), tenant, path)
	if err != nil {
		m.fail(w, r, err)
		return
	}

	httpx.JSON(w, http.StatusOK, metadataResponse{
		CurrentVersion: metadata.CurrentVersion,
		MaxVersions:    metadata.MaxVersions,
		CreatedAt:      metadata.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      metadata.UpdatedAt.UTC().Format(time.RFC3339),
	})
}

func (m *Module) permitted(w http.ResponseWriter, r *http.Request, capability authz.Capability) (string, string, bool) {
	identity, present := authn.IdentityFrom(r.Context())
	if !present {
		httpx.Problem(w, http.StatusUnauthorized, "unauthenticated")
		return "", "", false
	}

	tenant := r.PathValue("tenant")
	path := r.PathValue("path")
	if tenant == "" || path == "" {
		httpx.Problem(w, http.StatusNotFound, "not_found")
		return "", "", false
	}

	decision, err := m.authorizer.Authorize(r.Context(), identity, tenant, PolicyPath(tenant, path), capability)
	if err != nil {
		m.logger.Error("authorizing a request",
			"request_id", httpx.RequestIDFrom(r.Context()), "error", err)
		httpx.Problem(w, http.StatusInternalServerError, "internal_error")
		return "", "", false
	}
	if !decision.Allowed {
		m.logger.Warn("request refused",
			"request_id", httpx.RequestIDFrom(r.Context()),
			"identity", identity,
			"capability", string(capability),
			"decision", decision)
		httpx.Problem(w, http.StatusForbidden, "forbidden")
		return "", "", false
	}
	return tenant, path, true
}

func (m *Module) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrDeleted), errors.Is(err, ErrDestroyed):
		httpx.Problem(w, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrConflict):
		httpx.Problem(w, http.StatusConflict, "version_conflict")
	case errors.Is(err, ErrInvalidTenant), errors.Is(err, ErrInvalidPath), errors.Is(err, ErrInvalidVersion):
		httpx.Problem(w, http.StatusBadRequest, "invalid_location")
	default:
		m.logger.Error("serving a secret request",
			"request_id", httpx.RequestIDFrom(r.Context()),
			"path", r.URL.Path,
			"error", err)
		httpx.Problem(w, http.StatusInternalServerError, "internal_error")
	}
}

func requestedVersion(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("version")
	if raw == "" {
		return currentVersion, nil
	}
	version, err := strconv.Atoi(raw)
	if err != nil || version < 0 {
		return 0, ErrInvalidVersion
	}
	return version, nil
}

func PolicyPath(tenant, path string) string {
	return namespace + "/" + tenant + "/" + path
}
