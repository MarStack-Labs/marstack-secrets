package rotate

import (
	"errors"
	"net/http"

	"github.com/marstack-labs/marstack-secrets/internal/platform/audit"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const (
	pathRotate = "/v1/sys/rotate"
	policyPath = "sys/rotate"
)

type request struct {
	CurrentVersion int `json:"current_version"`
}

type subjectView struct {
	Name      string `json:"name"`
	Examined  int    `json:"examined"`
	Rewrapped int    `json:"rewrapped"`
}

type response struct {
	From     int           `json:"from"`
	To       int           `json:"to"`
	Subjects []subjectView `json:"subjects"`
}

func (m *Module) Register(mux *http.ServeMux) {
	mux.Handle("POST "+pathRotate, m.guard(http.HandlerFunc(m.handleRotate)))
}

func (m *Module) handleRotate(w http.ResponseWriter, r *http.Request) {
	identity, present := authn.IdentityFrom(r.Context())
	if !present {
		httpx.Problem(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	var body request
	if err := httpx.DecodeJSON(w, r, &body); err != nil {
		httpx.Problem(w, http.StatusBadRequest, "malformed_body")
		return
	}

	permitted, err := m.authorizer.Permitted(r.Context(), identity, identity.Tenant, policyPath)
	if err != nil {
		m.internal(w, r, "authorizing a rotation", err)
		return
	}
	if !permitted {
		m.record(r, identity, audit.ResultDeny)
		m.logger.Warn("rotation refused",
			"request_id", httpx.RequestIDFrom(r.Context()), "identity", identity)
		httpx.Problem(w, http.StatusForbidden, "forbidden")
		return
	}

	current, err := m.keys.KEKVersion(r.Context())
	if err != nil {
		m.refuse(w, r, err)
		return
	}
	if body.CurrentVersion != current {
		httpx.Problem(w, http.StatusConflict, "version_mismatch")
		return
	}

	result, err := m.rotate(r.Context())
	if err != nil {
		m.report(r, identity, result, err)
		m.refuse(w, r, err)
		return
	}

	m.record(r, identity, audit.ResultAllow)
	m.report(r, identity, result, nil)
	httpx.JSON(w, http.StatusOK, render(result))
}

func (m *Module) report(r *http.Request, identity authn.Identity, result outcome, err error) {
	attributes := []any{
		"request_id", httpx.RequestIDFrom(r.Context()),
		"identity", identity,
		"from", result.from,
		"to", result.to,
	}
	for _, subject := range result.subjects {
		attributes = append(attributes,
			subject.name+"_examined", subject.progress.Examined,
			subject.name+"_rewrapped", subject.progress.Rewrapped)
	}

	if err != nil {
		m.logger.Error("the key encryption key rotated but not every value followed it",
			append(attributes, "error", err)...)
		return
	}
	m.logger.Warn("the key encryption key rotated", attributes...)
}

func (m *Module) record(r *http.Request, identity authn.Identity, result string) {
	if m.audit == nil {
		return
	}
	if err := m.audit.Append(r.Context(), audit.Event{
		Operation: "rotate.kek",
		Identity:  identity.ID,
		Tenant:    identity.Tenant,
		Path:      policyPath,
		Result:    result,
		RequestID: httpx.RequestIDFrom(r.Context()),
		SourceIP:  httpx.RemoteIP(r),
	}); err != nil {
		m.logger.Error("recording a rotation",
			"request_id", httpx.RequestIDFrom(r.Context()), "error", err)
	}
}

func (m *Module) refuse(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrInProgress) {
		httpx.Problem(w, http.StatusConflict, "rotation_in_progress")
		return
	}
	m.internal(w, r, "rotating the key encryption key", err)
}

func (m *Module) internal(w http.ResponseWriter, r *http.Request, what string, err error) {
	m.logger.Error(what, "request_id", httpx.RequestIDFrom(r.Context()), "error", err)
	httpx.Problem(w, http.StatusInternalServerError, "internal_error")
}

func render(result outcome) response {
	view := response{From: result.from, To: result.to}
	for _, subject := range result.subjects {
		view.Subjects = append(view.Subjects, subjectView{
			Name:      subject.name,
			Examined:  subject.progress.Examined,
			Rewrapped: subject.progress.Rewrapped,
		})
	}
	return view
}
