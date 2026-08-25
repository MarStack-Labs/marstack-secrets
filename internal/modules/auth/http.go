package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const (
	pathBootstrapLogin = "/v1/auth/bootstrap/login"
	pathInstanceLogin  = "/v1/auth/instance/login"
	pathSelf           = "/v1/auth/self"
	pathLogout         = "/v1/auth/logout"

	headerAuthorization = "Authorization"
	bearerScheme        = "Bearer "
)

type Module struct {
	manager    *Manager
	logger     *slog.Logger
	assertions Assertions
}

type loginRequest struct {
	Token string `json:"token"`
}

type instanceLoginRequest struct {
	Assertion string `json:"assertion"`
}

type loginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type selfResponse struct {
	Identity string `json:"identity"`
	Kind     string `json:"kind"`
	Tenant   string `json:"tenant"`
}

func NewModule(manager *Manager, logger *slog.Logger, assertions Assertions) *Module {
	return &Module{manager: manager, logger: logger, assertions: assertions}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+pathBootstrapLogin, m.handleBootstrapLogin)
	if m.assertions != nil {
		mux.HandleFunc("POST "+pathInstanceLogin, m.handleInstanceLogin)
	}
	mux.Handle("GET "+pathSelf, m.Require(http.HandlerFunc(m.handleSelf)))
	mux.Handle("POST "+pathLogout, m.Require(http.HandlerFunc(m.handleLogout)))
}

func (m *Module) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, ok := bearerToken(r)
		if !ok {
			unauthorized(w)
			return
		}
		defer presented.Zero()

		identity, err := m.manager.Authenticate(r.Context(), presented, NoBinding)
		if err != nil {
			if !errors.Is(err, ErrUnauthenticated) {
				m.logger.Error("authenticating a request",
					"request_id", httpx.RequestIDFrom(r.Context()), "error", err)
			}
			unauthorized(w)
			return
		}

		next.ServeHTTP(w, r.WithContext(authn.WithIdentity(r.Context(), identity)))
	})
}

func (m *Module) handleBootstrapLogin(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	presented := crypto.Sensitive(request.Token)
	defer presented.Zero()

	session, err := m.manager.Exchange(r.Context(), presented, NoBinding, DefaultTTL)
	if err != nil {
		m.refuse(w, r, "exchanging a bootstrap token", err)
		return
	}
	defer session.Value.Zero()

	m.logger.Info("bootstrap token exchanged",
		"request_id", httpx.RequestIDFrom(r.Context()), "identity", session.Identity)

	httpx.JSON(w, http.StatusOK, loginResponse{
		Token:     string(session.Value),
		ExpiresAt: session.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (m *Module) handleInstanceLogin(w http.ResponseWriter, r *http.Request) {
	var request instanceLoginRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	session, err := m.manager.LoginInstance(r.Context(), m.assertions, []byte(request.Assertion))
	if err != nil {
		m.refuse(w, r, "verifying an instance assertion", err)
		return
	}
	defer session.Value.Zero()

	m.logger.Info("instance authenticated",
		"request_id", httpx.RequestIDFrom(r.Context()), "identity", session.Identity)

	httpx.JSON(w, http.StatusOK, loginResponse{
		Token:     string(session.Value),
		ExpiresAt: session.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (m *Module) refuse(w http.ResponseWriter, r *http.Request, what string, err error) {
	switch {
	case errors.Is(err, ErrUnauthenticated),
		errors.Is(err, ErrReplayed),
		errors.Is(err, ErrTenantMismatch),
		errors.Is(err, ErrKindMismatch):
		m.logger.Warn(what,
			"request_id", httpx.RequestIDFrom(r.Context()), "reason", err)
	default:
		m.logger.Error(what,
			"request_id", httpx.RequestIDFrom(r.Context()), "error", err)
	}
	unauthorized(w)
}

func (m *Module) handleSelf(w http.ResponseWriter, r *http.Request) {
	identity, ok := authn.IdentityFrom(r.Context())
	if !ok {
		unauthorized(w)
		return
	}
	httpx.JSON(w, http.StatusOK, selfResponse{
		Identity: identity.ID,
		Kind:     string(identity.Kind),
		Tenant:   identity.Tenant,
	})
}

func (m *Module) handleLogout(w http.ResponseWriter, r *http.Request) {
	presented, ok := bearerToken(r)
	if !ok {
		unauthorized(w)
		return
	}
	defer presented.Zero()

	if err := m.manager.Revoke(r.Context(), presented); err != nil {
		if !errors.Is(err, ErrUnauthenticated) {
			m.logger.Error("revoking a token",
				"request_id", httpx.RequestIDFrom(r.Context()), "error", err)
			httpx.Problem(w, http.StatusInternalServerError, "internal_error")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func bearerToken(r *http.Request) (crypto.Sensitive, bool) {
	header := r.Header.Get(headerAuthorization)
	if len(header) <= len(bearerScheme) || !strings.EqualFold(header[:len(bearerScheme)], bearerScheme) {
		return nil, false
	}
	value := strings.TrimSpace(header[len(bearerScheme):])
	if value == "" {
		return nil, false
	}
	return crypto.Sensitive(value), true
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	httpx.Problem(w, http.StatusUnauthorized, "unauthenticated")
}
