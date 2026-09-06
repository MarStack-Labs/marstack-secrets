package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/modules/policy"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
)

func rotatorPolicy(t *testing.T) policy.Policy {
	t.Helper()

	definition, err := policy.New("rotator", []policy.Rule{
		{Path: "sys/rotate", Capabilities: []authz.Capability{authz.Write}},
		{Path: "secret/prod/*", Capabilities: []authz.Capability{authz.Read, authz.Write}},
		{Path: "param/prod/*", Capabilities: []authz.Capability{authz.Read, authz.Write}},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return definition
}

func reportedKEKVersion(t *testing.T, h *harness) int {
	t.Helper()

	recorder := h.do(t, http.MethodGet, "/v1/sys/seal-status", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("seal-status returned %d", recorder.Code)
	}

	var status struct {
		KEKVersion int `json:"kek_version"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decoding seal-status: %v", err)
	}
	return status.KEKVersion
}

func TestARotationKeepsEveryValueReadableOverHTTP(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", rotatorPolicy(t))

	written := h.do(t, http.MethodPut, "/v1/secret/data/prod/payment-api",
		`{"value":"db_password=s3cr3t"}`, token)
	if written.Code != http.StatusOK {
		t.Fatalf("writing the secret returned %d: %s", written.Code, written.Body)
	}
	stored := h.do(t, http.MethodPut, "/v1/param/data/prod/app/log_level",
		`{"kind":"string","value":"info"}`, token)
	if stored.Code != http.StatusNoContent {
		t.Fatalf("writing the parameter returned %d: %s", stored.Code, stored.Body)
	}

	if got := reportedKEKVersion(t, h); got != 1 {
		t.Fatalf("the store starts at key encryption key version %d, want 1", got)
	}

	recorder := h.do(t, http.MethodPost, "/v1/sys/rotate", `{"current_version":1}`, token)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rotate returned %d: %s", recorder.Code, recorder.Body)
	}

	var result struct {
		From     int `json:"from"`
		To       int `json:"to"`
		Subjects []struct {
			Name      string `json:"name"`
			Examined  int    `json:"examined"`
			Rewrapped int    `json:"rewrapped"`
		} `json:"subjects"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decoding the rotation: %v", err)
	}
	if result.From != 1 || result.To != 2 {
		t.Errorf("rotation = %+v, want a move from 1 to 2", result)
	}
	for _, subject := range result.Subjects {
		if subject.Rewrapped != 1 {
			t.Errorf("%s rewrapped %d, want 1", subject.Name, subject.Rewrapped)
		}
	}
	if got := reportedKEKVersion(t, h); got != 2 {
		t.Errorf("seal-status reports version %d after the rotation, want 2", got)
	}

	read := h.do(t, http.MethodGet, "/v1/secret/data/prod/payment-api", "", token)
	if read.Code != http.StatusOK {
		t.Fatalf("reading the secret after the rotation returned %d: %s", read.Code, read.Body)
	}
	var value struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &value); err != nil {
		t.Fatalf("decoding the secret: %v", err)
	}
	if value.Value != "db_password=s3cr3t" {
		t.Errorf("the secret read back as %q", value.Value)
	}

	fetched := h.do(t, http.MethodGet, "/v1/param/data/prod/app/log_level", "", token)
	if fetched.Code != http.StatusOK {
		t.Fatalf("reading the parameter after the rotation returned %d: %s", fetched.Code, fetched.Body)
	}
	var parameter struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(fetched.Body.Bytes(), &parameter); err != nil {
		t.Fatalf("decoding the parameter: %v", err)
	}
	if parameter.Value != "info" {
		t.Errorf("the parameter read back as %q", parameter.Value)
	}
}

func TestARotationReachesTenantsTheCallerCannotRead(t *testing.T) {
	h := newHarness(t)

	staging := h.session(t, "service/staging", "staging", func() policy.Policy {
		definition, err := policy.New("staging-writer", []policy.Rule{
			{Path: "secret/staging/*", Capabilities: []authz.Capability{authz.Read, authz.Write}},
		})
		if err != nil {
			t.Fatalf("New returned error: %v", err)
		}
		return definition
	}())

	written := h.do(t, http.MethodPut, "/v1/secret/data/staging/billing-api",
		`{"value":"staging-secret"}`, staging)
	if written.Code != http.StatusOK {
		t.Fatalf("writing the staging secret returned %d: %s", written.Code, written.Body)
	}

	prod := h.session(t, "service/ci", "prod", rotatorPolicy(t))
	recorder := h.do(t, http.MethodPost, "/v1/sys/rotate", `{"current_version":1}`, prod)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rotate returned %d: %s", recorder.Code, recorder.Body)
	}

	var result struct {
		Subjects []struct {
			Name      string `json:"name"`
			Rewrapped int    `json:"rewrapped"`
		} `json:"subjects"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decoding the rotation: %v", err)
	}
	if result.Subjects[0].Rewrapped != 1 {
		t.Fatalf("the rotation moved %d secrets, want the staging one it cannot read",
			result.Subjects[0].Rewrapped)
	}

	read := h.do(t, http.MethodGet, "/v1/secret/data/staging/billing-api", "", staging)
	if read.Code != http.StatusOK {
		t.Fatalf("the staging secret became unreadable after a rotation it did not ask for: %d %s",
			read.Code, read.Body)
	}

	forbidden := h.do(t, http.MethodGet, "/v1/secret/data/staging/billing-api", "", prod)
	if forbidden.Code != http.StatusForbidden {
		t.Errorf("the rotating caller could read another tenant's secret: %d", forbidden.Code)
	}
}

func TestARotationNeedsItsOwnPermission(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", writerPolicy(t))

	recorder := h.do(t, http.MethodPost, "/v1/sys/rotate", `{"current_version":1}`, token)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("rotate with only a secret writer policy returned %d, want 403", recorder.Code)
	}
	if got := reportedKEKVersion(t, h); got != 1 {
		t.Errorf("the refused rotation moved the version to %d", got)
	}
}

func TestARotationIsRefusedWhileTheStoreIsSealed(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", rotatorPolicy(t))
	h.app.seal.Seal()

	recorder := h.do(t, http.MethodPost, "/v1/sys/rotate", `{"current_version":1}`, token)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("rotate on a sealed store returned %d, want 503", recorder.Code)
	}
}

func TestOldValuesStayReadableAcrossSeveralRotations(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, "service/ci", "prod", rotatorPolicy(t))

	for round := 1; round <= 3; round++ {
		path := fmt.Sprintf("/v1/secret/data/prod/round-%d", round)
		written := h.do(t, http.MethodPut, path, fmt.Sprintf(`{"value":"value-%d"}`, round), token)
		if written.Code != http.StatusOK {
			t.Fatalf("writing round %d returned %d: %s", round, written.Code, written.Body)
		}

		recorder := h.do(t, http.MethodPost, "/v1/sys/rotate",
			fmt.Sprintf(`{"current_version":%d}`, round), token)
		if recorder.Code != http.StatusOK {
			t.Fatalf("rotation %d returned %d: %s", round, recorder.Code, recorder.Body)
		}
	}

	for round := 1; round <= 3; round++ {
		path := fmt.Sprintf("/v1/secret/data/prod/round-%d", round)
		read := h.do(t, http.MethodGet, path, "", token)
		if read.Code != http.StatusOK {
			t.Fatalf("reading round %d returned %d: %s", round, read.Code, read.Body)
		}

		var value struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(read.Body.Bytes(), &value); err != nil {
			t.Fatalf("decoding round %d: %v", round, err)
		}
		if want := fmt.Sprintf("value-%d", round); value.Value != want {
			t.Errorf("round %d read back as %q, want %q", round, value.Value, want)
		}
	}
}
