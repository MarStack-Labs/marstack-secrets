package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/config"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.AllowInsecureHTTP = true
	cfg.DataDir = t.TempDir()
	return cfg
}

func testApp(t *testing.T) *App {
	t.Helper()
	application, err := New(t.Context(), testConfig(t), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() { _ = application.Close() })
	return application
}

func call(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding the request body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, path, reader))
	return recorder
}

func decode(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(recorder.Body.Bytes(), target); err != nil {
		t.Fatalf("decoding the response %q: %v", recorder.Body.String(), err)
	}
}

func TestHandlerServesRegisteredModules(t *testing.T) {
	recorder := call(t, testApp(t).Handler(), http.MethodGet, "/v1/sys/health", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if recorder.Header().Get("X-Request-Id") == "" {
		t.Error("the middleware chain should attach a request id")
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Error("the middleware chain should attach security headers")
	}
}

func TestEveryModuleIsRegistered(t *testing.T) {
	names := testApp(t).ModuleNames()

	registered := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, repeated := registered[name]; repeated {
			t.Errorf("module %q is registered twice", name)
		}
		registered[name] = struct{}{}
	}

	for _, want := range []string{"health", "observe", "seal", "auth", "policy", "lease", "param", "rotate", "secret"} {
		if _, present := registered[want]; !present {
			t.Errorf("module %q is not registered: %v", want, names)
		}
	}
}

func TestAuthEndpointsAreRefusedWhileSealed(t *testing.T) {
	handler := testApp(t).Handler()

	for _, path := range []string{"/v1/auth/bootstrap/login", "/v1/auth/self"} {
		recorder := call(t, handler, http.MethodPost, path, map[string]string{"token": "mss_x"})
		if recorder.Code != http.StatusServiceUnavailable {
			t.Errorf("%s returned %d while sealed, want %d", path, recorder.Code, http.StatusServiceUnavailable)
		}
	}
}

func TestAFreshServerIsSealed(t *testing.T) {
	recorder := call(t, testApp(t).Handler(), http.MethodGet, "/v1/sys/seal-status", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var status struct {
		State string `json:"state"`
	}
	decode(t, recorder, &status)
	if status.State != "uninitialized" {
		t.Errorf("state = %q, want uninitialized", status.State)
	}
}

func TestSealedServerRefusesEverythingElse(t *testing.T) {
	handler := testApp(t).Handler()

	for _, path := range []string{"/v1/secret/prod/payment-api", "/v1/param/prod/log_level", "/anything"} {
		recorder := call(t, handler, http.MethodGet, path, nil)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Errorf("%s returned %d, want %d", path, recorder.Code, http.StatusServiceUnavailable)
		}
		if !strings.Contains(recorder.Body.String(), "sealed") {
			t.Errorf("%s returned %q, want a sealed error", path, recorder.Body.String())
		}
	}
}

func TestSealedServerStillAnswersItsOperationalEndpoints(t *testing.T) {
	handler := testApp(t).Handler()

	for _, path := range []string{"/v1/sys/health", "/v1/sys/seal-status"} {
		if recorder := call(t, handler, http.MethodGet, path, nil); recorder.Code != http.StatusOK {
			t.Errorf("%s returned %d while sealed, want %d", path, recorder.Code, http.StatusOK)
		}
	}
}

func TestInitializeThenUnsealOverHTTP(t *testing.T) {
	application := testApp(t)
	handler := application.Handler()

	initialize := call(t, handler, http.MethodPost, "/v1/sys/init", map[string]int{"shares": 5, "threshold": 3})
	if initialize.Code != http.StatusOK {
		t.Fatalf("init returned %d: %s", initialize.Code, initialize.Body.String())
	}

	var created struct {
		Shares    []string `json:"shares"`
		Threshold int      `json:"threshold"`
	}
	decode(t, initialize, &created)
	if len(created.Shares) != 5 || created.Threshold != 3 {
		t.Fatalf("init returned %d shares with threshold %d, want 5 and 3", len(created.Shares), created.Threshold)
	}

	again := call(t, handler, http.MethodPost, "/v1/sys/init", map[string]int{"shares": 5, "threshold": 3})
	if again.Code != http.StatusConflict {
		t.Errorf("a second init returned %d, want %d", again.Code, http.StatusConflict)
	}

	application.seal.Seal()

	for offered, share := range created.Shares[:2] {
		recorder := call(t, handler, http.MethodPost, "/v1/sys/unseal", map[string]string{"share": share})
		if recorder.Code != http.StatusOK {
			t.Fatalf("unseal returned %d: %s", recorder.Code, recorder.Body.String())
		}

		var status struct {
			State    string `json:"state"`
			Progress int    `json:"progress"`
		}
		decode(t, recorder, &status)
		if status.State != "sealed" || status.Progress != offered+1 {
			t.Fatalf("after %d shares the status is %+v", offered+1, status)
		}
	}

	final := call(t, handler, http.MethodPost, "/v1/sys/unseal", map[string]string{"share": created.Shares[2]})
	var status struct {
		State string `json:"state"`
	}
	decode(t, final, &status)
	if status.State != "unsealed" {
		t.Fatalf("state after the quorum = %q, want unsealed", status.State)
	}

	if recorder := call(t, handler, http.MethodGet, "/anything", nil); recorder.Code != http.StatusNotFound {
		t.Errorf("an unknown path on an unsealed server returned %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestEveryErrorIsJSONIncludingNotFound(t *testing.T) {
	application := testApp(t)
	handler := application.Handler()

	if _, err := application.seal.Initialize(t.Context(), 5, 3); err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}

	cases := map[string]struct {
		method string
		path   string
	}{
		"unknown path":     {method: http.MethodGet, path: "/v1/secret/prod/db"},
		"method mismatch":  {method: http.MethodPost, path: "/v1/sys/health"},
		"unknown sys path": {method: http.MethodGet, path: "/v1/sys/unknown"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := call(t, handler, tc.method, tc.path, nil)

			if recorder.Code != http.StatusNotFound {
				t.Errorf("status = %d, want %d", recorder.Code, http.StatusNotFound)
			}
			if got := recorder.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("content type = %q, want application/json", got)
			}

			var problem struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			decode(t, recorder, &problem)
			if problem.Error.Code != "not_found" {
				t.Errorf("code = %q, want not_found", problem.Error.Code)
			}
		})
	}
}

func TestUnsealRejectsBadInput(t *testing.T) {
	handler := testApp(t).Handler()

	if recorder := call(t, handler, http.MethodPost, "/v1/sys/unseal", map[string]string{"share": "AAAA"}); recorder.Code != http.StatusPreconditionFailed {
		t.Errorf("unseal before init returned %d, want %d", recorder.Code, http.StatusPreconditionFailed)
	}

	initialize := call(t, handler, http.MethodPost, "/v1/sys/init", map[string]int{"shares": 5, "threshold": 3})
	if initialize.Code != http.StatusOK {
		t.Fatalf("init returned %d: %s", initialize.Code, initialize.Body.String())
	}

	cases := map[string]struct {
		body any
		want int
	}{
		"not base64":      {body: map[string]string{"share": "not base64!"}, want: http.StatusBadRequest},
		"unknown field":   {body: map[string]string{"shard": "AAAA"}, want: http.StatusBadRequest},
		"empty body":      {body: map[string]string{}, want: http.StatusBadRequest},
		"share too short": {body: map[string]string{"share": "AQ=="}, want: http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if recorder := call(t, handler, http.MethodPost, "/v1/sys/unseal", tc.body); recorder.Code != tc.want {
				t.Errorf("status = %d, want %d: %s", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

func TestInitializeRejectsImpossibleParameters(t *testing.T) {
	handler := testApp(t).Handler()

	recorder := call(t, handler, http.MethodPost, "/v1/sys/init", map[string]int{"shares": 3, "threshold": 5})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if !strings.Contains(recorder.Body.String(), "invalid_parameters") {
		t.Errorf("body = %q, want invalid_parameters", recorder.Body.String())
	}
}

func TestCloseSealsTheStore(t *testing.T) {
	application, err := New(t.Context(), testConfig(t), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if _, err := application.seal.Initialize(t.Context(), 5, 3); err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}
	if !application.seal.IsUnsealed() {
		t.Fatal("the store should be open after initialization")
	}

	if err := application.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if application.seal.IsUnsealed() {
		t.Error("Close left the root key in memory")
	}
}

func TestRunStartsAndShutsDownCleanly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("could not release the reserved port: %v", err)
	}

	cfg := testConfig(t)
	cfg.ListenAddr = addr
	cfg.ShutdownTimeout = 2 * time.Second

	application, err := New(t.Context(), cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() { _ = application.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Run(ctx) }()

	waitForServer(t, addr)

	response, err := http.Get("http://" + addr + "/v1/sys/health")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestServeRequiresTLSMaterialWhenNotInsecure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := httpx.Serve(ctx, httpx.ServerConfig{
		Addr:            "127.0.0.1:0",
		TLSCertFile:     "/nonexistent/tls.pem",
		TLSKeyFile:      "/nonexistent/tls-key.pem",
		ShutdownTimeout: time.Second,
	}, http.NewServeMux(), slog.New(slog.NewJSONHandler(io.Discard, nil)))

	if err == nil {
		t.Fatal("expected Serve to fail without usable TLS material")
	}
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become reachable", addr)
}
