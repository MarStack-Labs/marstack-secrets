package app

import (
	"io"
	"log/slog"
	"net/http"
	"slices"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/config"
)

func appWithUI(t *testing.T) *App {
	t.Helper()

	cfg := testConfig(t)
	cfg.UIEnabled = true

	application, err := New(t.Context(), cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() { _ = application.Close() })
	return application
}

func TestTheBrowserInterfaceIsAbsentUntilItIsAskedFor(t *testing.T) {
	if config.Default().UIEnabled {
		t.Fatal("the default configuration serves the browser interface")
	}

	h := newHarness(t)
	if slices.Contains(h.app.ModuleNames(), "ui") {
		t.Error("the browser interface registered without being enabled")
	}

	for _, path := range []string{"/ui/", "/ui/app.js", "/ui/app.css"} {
		recorder := h.do(t, http.MethodGet, path, "", "")
		if recorder.Code != http.StatusNotFound {
			t.Errorf("GET %s returned %d with the interface off, want 404", path, recorder.Code)
		}
	}
}

func TestTheBrowserInterfaceLoadsWhenEnabled(t *testing.T) {
	handler := appWithUI(t).Handler()

	for _, path := range []string{"/ui/", "/ui/app.js", "/ui/app.css"} {
		recorder := call(t, handler, http.MethodGet, path, nil)
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200", path, recorder.Code)
		}
		if recorder.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s carried no content security policy", path)
		}
	}
}

func TestTheBrowserInterfaceLoadsWhileTheStoreIsSealed(t *testing.T) {
	handler := appWithUI(t).Handler()

	for _, path := range []string{"/ui/", "/ui/app.js", "/ui/app.css"} {
		recorder := call(t, handler, http.MethodGet, path, nil)
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s returned %d on a sealed store, want the page to load so it can unseal",
				path, recorder.Code)
		}
	}

	refused := call(t, handler, http.MethodGet, "/v1/secret/data/prod/payment-api", nil)
	if refused.Code != http.StatusServiceUnavailable {
		t.Errorf("serving the page made the API answer %d while sealed", refused.Code)
	}
}

func TestTheBrowserInterfaceGrantsNothingOfItsOwn(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config) { cfg.UIEnabled = true })

	page := h.do(t, http.MethodGet, "/ui/", "", "")
	if page.Code != http.StatusOK {
		t.Fatalf("the page did not load: %d", page.Code)
	}

	if anonymous := h.do(t, http.MethodGet, "/v1/secret/data/prod/payment-api", "", ""); anonymous.Code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated read returned %d with the page enabled, want 401", anonymous.Code)
	}

	token := h.session(t, "service/ci", "prod")

	for _, path := range []string{
		"/v1/secret/data/prod/payment-api",
		"/v1/param/data/prod/app/log_level",
	} {
		recorder := h.do(t, http.MethodGet, path, "", token)
		if recorder.Code != http.StatusForbidden {
			t.Errorf("GET %s returned %d for an identity with no policy, want 403", path, recorder.Code)
		}
	}
}
