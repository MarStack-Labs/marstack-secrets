package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/modules/auth"
	"github.com/marstack-labs/marstack-secrets/internal/modules/policy"
	"github.com/marstack-labs/marstack-secrets/internal/modules/secret"
	"github.com/marstack-labs/marstack-secrets/internal/platform/audit"
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

	trail, err := audit.Open(cfg.AuditPath(), audit.Options{})
	if err != nil {
		t.Fatalf("opening the audit log: %v", err)
	}
	t.Cleanup(func() { _ = trail.Close() })

	application, err := assemble(t.Context(), cfg, logger, db, trail)
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

func TestAReadIssuesALease(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", writerPolicy(t))

	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"v"}`, token); recorder.Code != http.StatusOK {
		t.Fatalf("seeding returned %d", recorder.Code)
	}

	read := h.do(t, http.MethodGet, "/v1/secret/data/prod/db", "", token)
	if read.Code != http.StatusOK {
		t.Fatalf("read returned %d: %s", read.Code, read.Body.String())
	}

	var value struct {
		LeaseID  string `json:"lease_id"`
		LeaseTTL int    `json:"lease_ttl"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &value); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if !strings.HasPrefix(value.LeaseID, "secret/prod/db/") {
		t.Errorf("lease_id = %q", value.LeaseID)
	}
	if value.LeaseTTL <= 0 {
		t.Errorf("lease_ttl = %d", value.LeaseTTL)
	}

	listed := h.do(t, http.MethodGet, "/v1/sys/leases", "", token)
	if listed.Code != http.StatusOK {
		t.Fatalf("listing leases returned %d", listed.Code)
	}
	if !strings.Contains(listed.Body.String(), value.LeaseID) {
		t.Errorf("the lease list does not carry the lease: %s", listed.Body.String())
	}
}

func TestALeaseCanBeRenewedAndRevokedByItsHolder(t *testing.T) {
	h := newHarness(t)
	mine := h.session(t, "service/ci", "prod", writerPolicy(t))
	theirs := h.session(t, "service/app", "prod", readerPolicy(t))

	h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"v"}`, mine)
	read := h.do(t, http.MethodGet, "/v1/secret/data/prod/db", "", mine)

	var value struct {
		LeaseID string `json:"lease_id"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &value); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	body := `{"lease_id":"` + value.LeaseID + `"}`

	if recorder := h.do(t, http.MethodPut, "/v1/sys/leases/renew", body, theirs); recorder.Code != http.StatusNotFound {
		t.Errorf("another identity renewed the lease: %d", recorder.Code)
	}
	if recorder := h.do(t, http.MethodPut, "/v1/sys/leases/revoke", body, theirs); recorder.Code != http.StatusNotFound {
		t.Errorf("another identity revoked the lease: %d", recorder.Code)
	}

	if recorder := h.do(t, http.MethodPut, "/v1/sys/leases/renew", body, mine); recorder.Code != http.StatusOK {
		t.Fatalf("the holder could not renew: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := h.do(t, http.MethodPut, "/v1/sys/leases/revoke", body, mine); recorder.Code != http.StatusNoContent {
		t.Fatalf("the holder could not revoke: %d", recorder.Code)
	}
	if recorder := h.do(t, http.MethodPut, "/v1/sys/leases/renew", body, mine); recorder.Code != http.StatusNotFound {
		t.Errorf("a revoked lease was renewed: %d", recorder.Code)
	}
}

func TestPrefixRevocationNeedsDeleteOnThePrefix(t *testing.T) {
	h := newHarness(t)
	writer := h.session(t, "service/ci", "prod", writerPolicy(t))
	reader := h.session(t, "service/app", "prod", readerPolicy(t))

	h.do(t, http.MethodPut, "/v1/secret/data/prod/payment/db", `{"value":"v"}`, writer)
	h.do(t, http.MethodGet, "/v1/secret/data/prod/payment/db", "", writer)
	h.do(t, http.MethodGet, "/v1/secret/data/prod/payment/db", "", reader)

	body := `{"prefix":"secret/prod/payment/"}`

	if recorder := h.do(t, http.MethodPut, "/v1/sys/leases/revoke-prefix", body, reader); recorder.Code != http.StatusForbidden {
		t.Fatalf("a read-only identity revoked a prefix: %d %s", recorder.Code, recorder.Body.String())
	}

	revoked := h.do(t, http.MethodPut, "/v1/sys/leases/revoke-prefix", body, writer)
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke-prefix returned %d: %s", revoked.Code, revoked.Body.String())
	}

	var revocation struct {
		Leases     int      `json:"leases"`
		Identities []string `json:"identities"`
		Tokens     int      `json:"tokens"`
	}
	if err := json.Unmarshal(revoked.Body.Bytes(), &revocation); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if revocation.Leases != 2 || len(revocation.Identities) != 2 {
		t.Errorf("revocation = %+v, want both holders", revocation)
	}
	if revocation.Tokens < 2 {
		t.Errorf("Tokens = %d, want the holders' tokens revoked", revocation.Tokens)
	}

	if recorder := h.do(t, http.MethodGet, "/v1/secret/data/prod/payment/db", "", reader); recorder.Code != http.StatusUnauthorized {
		t.Errorf("a holder kept working after prefix revocation: %d", recorder.Code)
	}
	if recorder := h.do(t, http.MethodGet, "/v1/secret/data/prod/payment/db", "", writer); recorder.Code != http.StatusUnauthorized {
		t.Errorf("the caller kept working after revoking its own prefix: %d", recorder.Code)
	}
}

type refusingSink struct {
	refusing bool
}

func (s *refusingSink) Append(context.Context, audit.Event) error {
	if s.refusing {
		return errors.New("the audit device is full")
	}
	return nil
}

func TestEveryAccessLeavesARecord(t *testing.T) {
	h := newHarness(t)
	writer := h.session(t, "service/ci", "prod", writerPolicy(t))
	stranger := h.session(t, "service/app", "prod")

	h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"v"}`, writer)
	h.do(t, http.MethodGet, "/v1/secret/data/prod/db", "", writer)
	h.do(t, http.MethodDelete, "/v1/secret/data/prod/db", "", writer)
	h.do(t, http.MethodGet, "/v1/secret/data/prod/db", "", stranger)

	report, err := audit.Verify(h.app.cfg.AuditPath())
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if report.Records < 4 {
		t.Fatalf("the log holds %d records, want at least the four accesses", report.Records)
	}

	raw, err := os.ReadFile(h.app.cfg.AuditPath())
	if err != nil {
		t.Fatalf("reading the log: %v", err)
	}
	trail := string(raw)

	for _, expected := range []string{
		`"op":"secret.write"`,
		`"op":"secret.read"`,
		`"op":"secret.delete"`,
		`"result":"deny"`,
		`"identity":"service/app"`,
		`"path":"secret/prod/db"`,
	} {
		if !strings.Contains(trail, expected) {
			t.Errorf("the log is missing %s", expected)
		}
	}
	if strings.Contains(trail, `"v"`) {
		t.Error("the log carries the written value")
	}
}

func TestARefusedRecordRefusesTheRequestAndSealsTheStore(t *testing.T) {
	cfg := testConfig(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	db, err := sqlite.Open(t.Context(), cfg.DataDir+"/"+DatabaseFile)
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	trail, err := audit.Open(cfg.AuditPath(), audit.Options{})
	if err != nil {
		t.Fatalf("opening the audit log: %v", err)
	}
	t.Cleanup(func() { _ = trail.Close() })

	application, err := assemble(t.Context(), cfg, logger, db, trail)
	if err != nil {
		t.Fatalf("assemble returned error: %v", err)
	}
	if _, err := application.seal.Initialize(t.Context(), 3, 2); err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}

	broken := &refusingSink{}
	guarded := sealingSink{sink: broken, seal: application.seal, logger: logger}

	authManager, err := auth.NewManager(db, auth.Options{})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	policyManager, err := policy.NewManager(db, policy.Options{})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	h := &harness{app: application, auth: authManager, policy: policyManager}

	store, err := secret.NewStore(db, secret.Options{})
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	service, err := secret.NewService(store, application.seal.Cipher())
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}

	mux := http.NewServeMux()
	secret.NewModule(service, secret.ModuleOptions{
		Authorizer: policyManager,
		Leases:     leaseIssuer{manager: application.leases},
		Audit:      guarded,
		LeaseTTL:   cfg.LeaseTTL,
		Guard:      auth.NewModule(authManager, logger, nil, auth.Limits{}, auth.Recording{}).Require,
		Logger:     logger,
	}).Register(mux)
	h.handler = mux

	token := h.session(t, "service/ci", "prod", writerPolicy(t))

	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"v"}`, token); recorder.Code != http.StatusOK {
		t.Fatalf("seeding returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if !application.seal.IsUnsealed() {
		t.Fatal("the store should still be open")
	}

	broken.refusing = true

	recorder := h.do(t, http.MethodGet, "/v1/secret/data/prod/db", "", token)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("a read with a broken audit sink returned %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(recorder.Body.String(), "value") {
		t.Errorf("the secret was served despite the missing record: %s", recorder.Body.String())
	}
	if application.seal.IsUnsealed() {
		t.Error("a failing audit sink did not seal the store")
	}
}

func TestMetricsAreExposedAndScrapableWhileSealed(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", writerPolicy(t))

	h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"v"}`, token)
	h.do(t, http.MethodGet, "/v1/secret/data/prod/db", "", token)

	scraped := h.do(t, http.MethodGet, "/v1/sys/metrics", "", "")
	if scraped.Code != http.StatusOK {
		t.Fatalf("scraping returned %d: %s", scraped.Code, scraped.Body.String())
	}
	if got := scraped.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("content type = %q", got)
	}

	body := scraped.Body.String()
	for _, expected := range []string{
		"# TYPE marsec_http_requests_total counter",
		"marsec_http_requests_total{",
		"marsec_sealed 0",
		"marsec_initialized 1",
		"marsec_leases_active 1",
		`marsec_audit_records_total{outcome="written"}`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("the scrape is missing %q:\n%s", expected, body)
		}
	}
	if strings.Contains(body, "secret/prod/db") {
		t.Error("a secret path reached the metrics output")
	}

	h.app.seal.Seal()

	sealed := h.do(t, http.MethodGet, "/v1/sys/metrics", "", "")
	if sealed.Code != http.StatusOK {
		t.Fatalf("scraping a sealed store returned %d", sealed.Code)
	}
	if !strings.Contains(sealed.Body.String(), "marsec_sealed 1") {
		t.Errorf("the sealed store does not report itself sealed:\n%s", sealed.Body.String())
	}
}
