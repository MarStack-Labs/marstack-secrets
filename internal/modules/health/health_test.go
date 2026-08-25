package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func handler() http.Handler {
	mux := http.NewServeMux()
	New().Register(mux)
	return mux
}

func TestHealthReportsOK(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %v, want ok", body["status"])
	}
	if len(body) != 1 {
		t.Errorf("health must expose nothing beyond status, got %v", body)
	}
}

func TestHealthDoesNotLeakBuildDetails(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil))

	body := strings.ToLower(recorder.Body.String())
	for _, forbidden := range []string{"version", "build", "commit", "go1."} {
		if strings.Contains(body, forbidden) {
			t.Errorf("health response leaks %q: %s", forbidden, recorder.Body.String())
		}
	}
}

func TestHealthRejectsOtherMethods(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/sys/health", nil))

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}

func TestModuleName(t *testing.T) {
	if got := New().Name(); got != "health" {
		t.Errorf("Name() = %q, want health", got)
	}
}
