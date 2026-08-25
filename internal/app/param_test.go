package app

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/modules/policy"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
)

func paramPolicy(t *testing.T, name string, rules ...policy.Rule) policy.Policy {
	t.Helper()
	definition, err := policy.New(name, rules)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return definition
}

func configPolicy(t *testing.T) policy.Policy {
	return paramPolicy(t, "config",
		policy.Rule{Path: "param/prod/*", Capabilities: []authz.Capability{authz.Read, authz.Write, authz.Delete, authz.List}},
	)
}

func configAndSecretsPolicy(t *testing.T) policy.Policy {
	return paramPolicy(t, "config-and-secrets",
		policy.Rule{Path: "param/prod/*", Capabilities: []authz.Capability{authz.Read, authz.Write, authz.List}},
		policy.Rule{Path: "secret/prod/*", Capabilities: []authz.Capability{authz.Read, authz.Write}},
	)
}

type paramView struct {
	Path         string   `json:"path"`
	ResolvedFrom string   `json:"resolved_from"`
	Inherited    bool     `json:"inherited"`
	Kind         string   `json:"kind"`
	Value        string   `json:"value"`
	Sensitive    bool     `json:"sensitive"`
	References   []string `json:"references"`
}

func readParam(t *testing.T, h *harness, path, token string) (paramView, int) {
	t.Helper()
	recorder := h.do(t, http.MethodGet, "/v1/param/data/prod/"+path, "", token)

	var view paramView
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &view); err != nil {
			t.Fatalf("decoding: %v", err)
		}
	}
	return view, recorder.Code
}

func TestAParameterRoundTripsOverHTTP(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", configPolicy(t))

	written := h.do(t, http.MethodPut, "/v1/param/data/prod/apps/payment/log_level",
		`{"kind":"string","value":"debug"}`, token)
	if written.Code != http.StatusNoContent {
		t.Fatalf("write returned %d: %s", written.Code, written.Body.String())
	}

	view, status := readParam(t, h, "apps/payment/log_level", token)
	if status != http.StatusOK {
		t.Fatalf("read returned %d", status)
	}
	if view.Value != "debug" || view.Kind != "string" || view.Inherited {
		t.Errorf("read = %+v", view)
	}
}

func TestInheritanceIsVisibleInTheResponse(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", configPolicy(t))

	h.do(t, http.MethodPut, "/v1/param/data/prod/log_level", `{"kind":"string","value":"warn"}`, token)

	view, status := readParam(t, h, "apps/billing/log_level", token)
	if status != http.StatusOK {
		t.Fatalf("read returned %d", status)
	}
	if view.Value != "warn" || !view.Inherited || view.ResolvedFrom != "log_level" {
		t.Errorf("read = %+v", view)
	}
}

func TestAWrongTypeIsRefusedAtTheEndpoint(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", configPolicy(t))

	recorder := h.do(t, http.MethodPut, "/v1/param/data/prod/apps/replicas",
		`{"kind":"int","value":"three"}`, token)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalid_value") {
		t.Errorf("body = %q", recorder.Body.String())
	}
}

func TestAReferenceResolvesAndMarksTheResultSensitive(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", configAndSecretsPolicy(t))

	if recorder := h.do(t, http.MethodPut, "/v1/secret/data/prod/db",
		`{"value":"s3cr3t"}`, token); recorder.Code != http.StatusOK {
		t.Fatalf("seeding the secret returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := h.do(t, http.MethodPut, "/v1/param/data/prod/apps/db_url",
		`{"kind":"string","value":"postgres://app:${secret/prod/db}@db:5432/app"}`, token); recorder.Code != http.StatusNoContent {
		t.Fatalf("writing the parameter returned %d: %s", recorder.Code, recorder.Body.String())
	}

	view, status := readParam(t, h, "apps/db_url", token)
	if status != http.StatusOK {
		t.Fatalf("read returned %d", status)
	}
	if view.Value != "postgres://app:s3cr3t@db:5432/app" {
		t.Errorf("Value = %q", view.Value)
	}
	if !view.Sensitive {
		t.Error("a resolved reference did not mark the result sensitive")
	}
	if len(view.References) != 1 || view.References[0] != "secret/prod/db" {
		t.Errorf("References = %v", view.References)
	}
}

func TestAReferenceNeedsReadOnTheSecretItself(t *testing.T) {
	h := newHarness(t)
	writer := h.session(t, "service/ci", "prod", configAndSecretsPolicy(t))
	configOnly := h.session(t, "service/app", "prod", configPolicy(t))

	h.do(t, http.MethodPut, "/v1/secret/data/prod/db", `{"value":"s3cr3t"}`, writer)
	h.do(t, http.MethodPut, "/v1/param/data/prod/apps/db_url",
		`{"kind":"string","value":"postgres://app:${secret/prod/db}@db/app"}`, writer)

	if _, status := readParam(t, h, "apps/db_url", configOnly); status != http.StatusForbidden {
		t.Fatalf("an identity with parameter access but no secret access read the reference: %d", status)
	}

	plain := h.do(t, http.MethodPut, "/v1/param/data/prod/apps/log_level",
		`{"kind":"string","value":"info"}`, writer)
	if plain.Code != http.StatusNoContent {
		t.Fatalf("writing a plain parameter returned %d", plain.Code)
	}
	if _, status := readParam(t, h, "apps/log_level", configOnly); status != http.StatusOK {
		t.Errorf("a parameter without references was refused: %d", status)
	}
}

func TestAReferenceCannotReachAnotherTenant(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", configAndSecretsPolicy(t))

	h.do(t, http.MethodPut, "/v1/param/data/prod/apps/db_url",
		`{"kind":"string","value":"${secret/staging/db}"}`, token)

	recorder := h.do(t, http.MethodGet, "/v1/param/data/prod/apps/db_url", "", token)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a cross tenant reference returned %d, want %d: %s",
			recorder.Code, http.StatusUnprocessableEntity, recorder.Body.String())
	}
}

func TestAReferenceIsNotResolvedRecursively(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", configAndSecretsPolicy(t))

	h.do(t, http.MethodPut, "/v1/secret/data/prod/nested",
		`{"value":"${secret/prod/other}"}`, token)
	h.do(t, http.MethodPut, "/v1/param/data/prod/apps/value",
		`{"kind":"string","value":"${secret/prod/nested}"}`, token)

	view, status := readParam(t, h, "apps/value", token)
	if status != http.StatusOK {
		t.Fatalf("read returned %d", status)
	}
	if view.Value != "${secret/prod/other}" {
		t.Errorf("Value = %q, want the secret's literal contents", view.Value)
	}
}

func TestAMissingReferenceIsNotFound(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", configAndSecretsPolicy(t))

	h.do(t, http.MethodPut, "/v1/param/data/prod/apps/db_url",
		`{"kind":"string","value":"${secret/prod/absent}"}`, token)

	if _, status := readParam(t, h, "apps/db_url", token); status != http.StatusNotFound {
		t.Fatalf("a reference to a missing secret returned %d, want %d", status, http.StatusNotFound)
	}
}

func TestListingParametersNeedsTheListCapability(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", configPolicy(t))
	reader := h.session(t, "service/app", "prod", paramPolicy(t, "read-only",
		policy.Rule{Path: "param/prod/*", Capabilities: []authz.Capability{authz.Read}},
	))

	h.do(t, http.MethodPut, "/v1/param/data/prod/apps/payment/log_level", `{"kind":"string","value":"debug"}`, token)
	h.do(t, http.MethodPut, "/v1/param/data/prod/apps/payment/replicas", `{"kind":"int","value":"3"}`, token)

	listed := h.do(t, http.MethodGet, "/v1/param/list/prod?prefix=apps/payment/", "", token)
	if listed.Code != http.StatusOK {
		t.Fatalf("listing returned %d: %s", listed.Code, listed.Body.String())
	}

	var response struct {
		Parameters []struct {
			Path  string `json:"path"`
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &response); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(response.Parameters) != 2 {
		t.Fatalf("listing returned %d entries, want 2", len(response.Parameters))
	}
	for _, entry := range response.Parameters {
		if entry.Value != "" {
			t.Errorf("listing returned a value for %q", entry.Path)
		}
	}

	if refused := h.do(t, http.MethodGet, "/v1/param/list/prod?prefix=apps/", "", reader); refused.Code != http.StatusForbidden {
		t.Errorf("an identity without list returned %d", refused.Code)
	}
}

func TestParameterAccessIsAudited(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", configPolicy(t))

	h.do(t, http.MethodPut, "/v1/param/data/prod/apps/log_level", `{"kind":"string","value":"debug"}`, token)
	h.do(t, http.MethodGet, "/v1/param/data/prod/apps/log_level", "", token)
	h.do(t, http.MethodDelete, "/v1/param/data/prod/apps/log_level", "", token)

	raw, err := readFile(h.app.cfg.AuditPath())
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	for _, expected := range []string{
		`"op":"param.write"`,
		`"op":"param.read"`,
		`"op":"param.delete"`,
		`"path":"param/prod/apps/log_level"`,
	} {
		if !strings.Contains(raw, expected) {
			t.Errorf("the audit log is missing %s", expected)
		}
	}
	if strings.Contains(raw, "debug") {
		t.Error("the audit log carries the parameter value")
	}
}

func readFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
