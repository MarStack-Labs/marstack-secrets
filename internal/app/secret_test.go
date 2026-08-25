package app

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/modules/auth"
	"github.com/marstack-labs/marstack-secrets/internal/modules/policy"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

type harness struct {
	app     *App
	handler http.Handler
	auth    *auth.Manager
	policy  *policy.Manager
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	cfg := testConfig(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	db, err := sqlite.Open(t.Context(), cfg.DataDir+"/"+DatabaseFile)
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	application, err := assemble(t.Context(), cfg, logger, db)
	if err != nil {
		t.Fatalf("assemble returned error: %v", err)
	}
	if _, err := application.seal.Initialize(t.Context(), 3, 2); err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}

	authManager, err := auth.NewManager(db, auth.Options{})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	policyManager, err := policy.NewManager(db, policy.Options{})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	return &harness{
		app:     application,
		handler: application.Handler(),
		auth:    authManager,
		policy:  policyManager,
	}
}

func (h *harness) session(t *testing.T, identityID, tenant string, policies ...policy.Policy) string {
	t.Helper()

	if _, err := h.auth.RegisterIdentity(t.Context(), identityID, authn.KindService, tenant); err != nil {
		t.Fatalf("RegisterIdentity returned error: %v", err)
	}
	for _, definition := range policies {
		if err := h.policy.Put(t.Context(), tenant, definition); err != nil {
			t.Fatalf("Put returned error: %v", err)
		}
		if err := h.policy.Bind(t.Context(), tenant, identityID, definition.Name); err != nil {
			t.Fatalf("Bind returned error: %v", err)
		}
	}

	token, err := h.auth.Issue(t.Context(), identityID, auth.NoBinding, auth.DefaultTTL)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	return string(token.Value)
}

func (h *harness) do(t *testing.T, method, path, body, bearer string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func readerPolicy(t *testing.T) policy.Policy {
	t.Helper()
	definition, err := policy.New("reader", []policy.Rule{
		{Path: "secret/prod/*", Capabilities: []authz.Capability{authz.Read}},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return definition
}

func writerPolicy(t *testing.T) policy.Policy {
	t.Helper()
	definition, err := policy.New("writer", []policy.Rule{
		{Path: "secret/prod/*", Capabilities: []authz.Capability{authz.Read, authz.Write, authz.Delete}},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return definition
}

func TestASecretRoundTripsOverHTTP(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", writerPolicy(t))

	written := h.do(t, http.MethodPut, "/v1/secret/data/prod/payment-api",
		`{"value":"db_password=s3cr3t"}`, token)
	if written.Code != http.StatusOK {
		t.Fatalf("write returned %d: %s", written.Code, written.Body.String())
	}

	var created struct{ Version int }
	if err := json.Unmarshal(written.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding the write response: %v", err)
	}
	if created.Version != 1 {
		t.Errorf("version = %d, want 1", created.Version)
	}

	read := h.do(t, http.MethodGet, "/v1/secret/data/prod/payment-api", "", token)
	if read.Code != http.StatusOK {
		t.Fatalf("read returned %d: %s", read.Code, read.Body.String())
	}

	var value struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &value); err != nil {
		t.Fatalf("decoding the read response: %v", err)
	}
	if value.Value != "db_password=s3cr3t" || value.Version != 1 {
		t.Errorf("read = %+v", value)
	}
}

func TestWithoutAPolicyEverythingIsForbidden(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod")

	cases := map[string]struct {
		method string
		path   string
		body   string
	}{
		"read":     {method: http.MethodGet, path: "/v1/secret/data/prod/payment-api"},
		"write":    {method: http.MethodPut, path: "/v1/secret/data/prod/payment-api", body: `{"value":"x"}`},
		"delete":   {method: http.MethodDelete, path: "/v1/secret/data/prod/payment-api"},
		"metadata": {method: http.MethodGet, path: "/v1/secret/metadata/prod/payment-api"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := h.do(t, tc.method, tc.path, tc.body, token)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
			}
			if !strings.Contains(recorder.Body.String(), "forbidden") {
				t.Errorf("body = %q", recorder.Body.String())
			}
		})
	}
}

func TestAReadOnlyPolicyCannotWrite(t *testing.T) {
	h := newHarness(t)
	writer := h.session(t, "service/ci", "prod", writerPolicy(t))
	reader := h.session(t, "service/app", "prod", readerPolicy(t))

	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/payment-api", `{"value":"v"}`, writer); recorder.Code != http.StatusOK {
		t.Fatalf("seeding the secret returned %d", recorder.Code)
	}

	if recorder := h.do(t, http.MethodGet, "/v1/secret/data/prod/payment-api", "", reader); recorder.Code != http.StatusOK {
		t.Fatalf("the reader could not read: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/payment-api", `{"value":"v2"}`, reader); recorder.Code != http.StatusForbidden {
		t.Fatalf("the reader wrote: %d", recorder.Code)
	}
	if recorder := h.do(t, http.MethodDelete, "/v1/secret/data/prod/payment-api", "", reader); recorder.Code != http.StatusForbidden {
		t.Fatalf("the reader deleted: %d", recorder.Code)
	}
}

func TestATenantCannotReachAnother(t *testing.T) {
	h := newHarness(t)
	prod := h.session(t, "service/ci", "prod", writerPolicy(t))
	staging := h.session(t, "service/staging-ci", "staging", writerPolicy(t))

	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/payment-api", `{"value":"prod value"}`, prod); recorder.Code != http.StatusOK {
		t.Fatalf("seeding returned %d: %s", recorder.Code, recorder.Body.String())
	}

	recorder := h.do(t, http.MethodGet, "/v1/secret/data/prod/payment-api", "", staging)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("staging read a prod secret: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestAForbiddenResponseRevealsNothingAboutExistence(t *testing.T) {
	h := newHarness(t)
	writer := h.session(t, "service/ci", "prod", writerPolicy(t))
	stranger := h.session(t, "service/app", "prod")

	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/exists", `{"value":"v"}`, writer); recorder.Code != http.StatusOK {
		t.Fatalf("seeding returned %d", recorder.Code)
	}

	present := h.do(t, http.MethodGet, "/v1/secret/data/prod/exists", "", stranger)
	absent := h.do(t, http.MethodGet, "/v1/secret/data/prod/absent", "", stranger)

	if present.Code != absent.Code {
		t.Fatalf("a secret that exists returned %d and one that does not returned %d", present.Code, absent.Code)
	}
	if present.Body.String() != absent.Body.String() {
		t.Errorf("the bodies differ:\n%s\n%s", present.Body.String(), absent.Body.String())
	}
}

func TestSecretEndpointsNeedAuthentication(t *testing.T) {
	h := newHarness(t)

	for _, bearer := range []string{"", "mss_" + strings.Repeat("A", 43)} {
		recorder := h.do(t, http.MethodGet, "/v1/secret/data/prod/payment-api", "", bearer)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
		}
	}
}

func TestCheckAndSetOverHTTP(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", writerPolicy(t))

	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"one","cas":0}`, token); recorder.Code != http.StatusOK {
		t.Fatalf("the first write returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"two","cas":0}`, token); recorder.Code != http.StatusConflict {
		t.Fatalf("a stale expectation returned %d, want %d", recorder.Code, http.StatusConflict)
	}
	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"two","cas":1}`, token); recorder.Code != http.StatusOK {
		t.Fatalf("a current expectation returned %d", recorder.Code)
	}
}

func TestVersionsAndDeletionOverHTTP(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", writerPolicy(t))

	for _, value := range []string{"one", "two"} {
		if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"`+value+`"}`, token); recorder.Code != http.StatusOK {
			t.Fatalf("writing %q returned %d", value, recorder.Code)
		}
	}

	older := h.do(t, http.MethodGet, "/v1/secret/data/prod/db?version=1", "", token)
	if older.Code != http.StatusOK {
		t.Fatalf("reading version 1 returned %d", older.Code)
	}
	if !strings.Contains(older.Body.String(), `"one"`) {
		t.Errorf("version 1 = %s", older.Body.String())
	}

	if recorder := h.do(t, http.MethodGet, "/v1/secret/data/prod/db?version=abc", "", token); recorder.Code != http.StatusBadRequest {
		t.Errorf("a malformed version returned %d, want %d", recorder.Code, http.StatusBadRequest)
	}

	metadata := h.do(t, http.MethodGet, "/v1/secret/metadata/prod/db", "", token)
	if metadata.Code != http.StatusOK {
		t.Fatalf("metadata returned %d", metadata.Code)
	}
	if !strings.Contains(metadata.Body.String(), `"current_version":2`) {
		t.Errorf("metadata = %s", metadata.Body.String())
	}

	if recorder := h.do(t, http.MethodDelete, "/v1/secret/data/prod/db", "", token); recorder.Code != http.StatusNoContent {
		t.Fatalf("delete returned %d", recorder.Code)
	}
	if recorder := h.do(t, http.MethodGet, "/v1/secret/data/prod/db", "", token); recorder.Code != http.StatusNotFound {
		t.Fatalf("reading a deleted secret returned %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestNestedPathsAndTraversal(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", writerPolicy(t))

	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/apps/payment/db", `{"value":"v"}`, token); recorder.Code != http.StatusOK {
		t.Fatalf("a nested path returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := h.do(t, http.MethodGet, "/v1/secret/data/prod/apps/payment/db", "", token); recorder.Code != http.StatusOK {
		t.Fatalf("reading a nested path returned %d", recorder.Code)
	}
}

func TestPolicyCheckExplainsTheDecision(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/app", "prod", readerPolicy(t))

	granted := h.do(t, http.MethodPost, "/v1/sys/policies/check",
		`{"tenant":"prod","path":"secret/prod/db","capability":"read"}`, token)
	if granted.Code != http.StatusOK {
		t.Fatalf("check returned %d: %s", granted.Code, granted.Body.String())
	}

	var allowed struct {
		Allowed  bool     `json:"allowed"`
		Policy   string   `json:"policy"`
		Rule     string   `json:"rule"`
		Reason   string   `json:"reason"`
		Policies []string `json:"policies"`
	}
	if err := json.Unmarshal(granted.Body.Bytes(), &allowed); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if !allowed.Allowed || allowed.Policy != "reader" || allowed.Rule != "secret/prod/*" {
		t.Errorf("check = %+v", allowed)
	}
	if len(allowed.Policies) != 1 || allowed.Policies[0] != "reader" {
		t.Errorf("bound policies = %v", allowed.Policies)
	}

	refused := h.do(t, http.MethodPost, "/v1/sys/policies/check",
		`{"tenant":"prod","path":"secret/prod/db","capability":"write"}`, token)
	var denied struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(refused.Body.Bytes(), &denied); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if denied.Allowed {
		t.Error("write was reported as allowed")
	}
	if !strings.Contains(denied.Reason, "does not grant") {
		t.Errorf("reason = %q", denied.Reason)
	}

	crossTenant := h.do(t, http.MethodPost, "/v1/sys/policies/check",
		`{"tenant":"staging","path":"secret/staging/db","capability":"read"}`, token)
	if !strings.Contains(crossTenant.Body.String(), "another tenant") {
		t.Errorf("a cross tenant check = %s", crossTenant.Body.String())
	}

	bad := h.do(t, http.MethodPost, "/v1/sys/policies/check",
		`{"tenant":"prod","path":"secret/prod/db","capability":"deny"}`, token)
	if bad.Code != http.StatusBadRequest {
		t.Errorf("checking deny returned %d, want %d", bad.Code, http.StatusBadRequest)
	}
}

func TestSecretEndpointsAreRefusedWhileSealed(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", writerPolicy(t))

	h.app.seal.Seal()

	for _, path := range []string{"/v1/secret/data/prod/db", "/v1/sys/policies/check"} {
		recorder := h.do(t, http.MethodGet, path, "", token)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Errorf("%s returned %d while sealed, want %d", path, recorder.Code, http.StatusServiceUnavailable)
		}
	}
}
