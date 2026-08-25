package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/config"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

func testApp() *App {
	cfg := config.Default()
	cfg.AllowInsecureHTTP = true
	return New(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

func TestHandlerServesRegisteredModules(t *testing.T) {
	recorder := httptest.NewRecorder()
	testApp().Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil))

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

func TestHandlerRejectsUnknownPaths(t *testing.T) {
	recorder := httptest.NewRecorder()
	testApp().Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/secret/prod/db", nil))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestModuleNames(t *testing.T) {
	names := testApp().ModuleNames()
	if len(names) != 1 || names[0] != "health" {
		t.Fatalf("ModuleNames() = %v, want [health]", names)
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

	cfg := config.Default()
	cfg.AllowInsecureHTTP = true
	cfg.ListenAddr = addr
	cfg.ShutdownTimeout = 2 * time.Second
	application := New(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))

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
