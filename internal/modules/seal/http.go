package seal

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const (
	pathStatus = "/v1/sys/seal-status"
	pathInit   = "/v1/sys/init"
	pathUnseal = "/v1/sys/unseal"
)

type Module struct {
	manager *Manager
	logger  *slog.Logger
}

type statusResponse struct {
	State     string `json:"state"`
	Shares    int    `json:"shares"`
	Threshold int    `json:"threshold"`
	Progress  int    `json:"progress"`
}

type initRequest struct {
	Shares    int `json:"shares"`
	Threshold int `json:"threshold"`
}

type initResponse struct {
	Shares    []string `json:"shares"`
	Threshold int      `json:"threshold"`
}

type unsealRequest struct {
	Share string `json:"share"`
}

func NewModule(manager *Manager, logger *slog.Logger) *Module {
	return &Module{manager: manager, logger: logger}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+pathStatus, m.handleStatus)
	mux.HandleFunc("POST "+pathInit, m.handleInit)
	mux.HandleFunc("POST "+pathUnseal, m.handleUnseal)
}

func (m *Module) PathsAllowedWhileSealed() []string {
	return []string{pathStatus, pathInit, pathUnseal}
}

func (m *Module) handleStatus(w http.ResponseWriter, r *http.Request) {
	status, err := m.manager.Status(r.Context())
	if err != nil {
		m.fail(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, render(status))
}

func (m *Module) handleInit(w http.ResponseWriter, r *http.Request) {
	var request initRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	shares, err := m.manager.Initialize(r.Context(), request.Shares, request.Threshold)
	if err != nil {
		m.fail(w, r, err)
		return
	}

	encoded := make([]string, len(shares))
	for index, share := range shares {
		encoded[index] = base64.StdEncoding.EncodeToString(share)
		share.Zero()
	}

	m.logger.Warn("store initialized; the unseal shares are returned once and never again",
		"request_id", httpx.RequestIDFrom(r.Context()),
		"shares", request.Shares,
		"threshold", request.Threshold,
	)
	httpx.JSON(w, http.StatusOK, initResponse{Shares: encoded, Threshold: request.Threshold})
}

func (m *Module) handleUnseal(w http.ResponseWriter, r *http.Request) {
	var request unsealRequest
	if err := httpx.DecodeJSON(w, r, &request); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	share, err := base64.StdEncoding.DecodeString(request.Share)
	if err != nil {
		httpx.Problem(w, http.StatusBadRequest, "invalid_share")
		return
	}
	defer crypto.Sensitive(share).Zero()

	status, err := m.manager.Unseal(r.Context(), share)
	if err != nil {
		m.fail(w, r, err)
		return
	}

	if status.State == StateUnsealed {
		m.logger.Info("store unsealed", "request_id", httpx.RequestIDFrom(r.Context()))
	}
	httpx.JSON(w, http.StatusOK, render(status))
}

func (m *Module) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code := classify(err)
	if status == http.StatusInternalServerError {
		m.logger.Error("seal operation failed",
			"request_id", httpx.RequestIDFrom(r.Context()),
			"path", r.URL.Path,
			"error", err,
		)
	}
	httpx.Problem(w, status, code)
}

func classify(err error) (int, string) {
	switch {
	case errors.Is(err, ErrAlreadyInitialized):
		return http.StatusConflict, "already_initialized"
	case errors.Is(err, ErrNotInitialized):
		return http.StatusPreconditionFailed, "not_initialized"
	case errors.Is(err, ErrUnsealFailed):
		return http.StatusBadRequest, "unseal_failed"
	case errors.Is(err, ErrInvalidShare):
		return http.StatusBadRequest, "invalid_share"
	case errors.Is(err, crypto.ErrShareCount), errors.Is(err, crypto.ErrThreshold):
		return http.StatusBadRequest, "invalid_parameters"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func render(status Status) statusResponse {
	return statusResponse{
		State:     string(status.State),
		Shares:    status.Shares,
		Threshold: status.Threshold,
		Progress:  status.Progress,
	}
}
