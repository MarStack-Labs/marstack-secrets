package httpx

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestChainAppliesMiddlewareOutermostFirst(t *testing.T) {
	var order []string
	tag := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	handler := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "handler")
	}), tag("first"), tag("second"))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"first", "second", "handler"}
	if len(order) != len(want) {
		t.Fatalf("call order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("call order = %v, want %v", order, want)
		}
	}
}

func TestRequestIDIsGeneratedAndExposed(t *testing.T) {
	var seen string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Request-Id", "client-supplied-value")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if seen == "" {
		t.Fatal("expected a request id in the context")
	}
	if seen == "client-supplied-value" {
		t.Fatal("client supplied request ids must not be trusted")
	}
	if got := recorder.Header().Get("X-Request-Id"); got != seen {
		t.Errorf("response header = %q, want %q", got, seen)
	}
}

func TestRequestIDIsUniquePerRequest(t *testing.T) {
	ids := make(map[string]struct{})
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids[RequestIDFrom(r.Context())] = struct{}{}
	}))
	for range 100 {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if len(ids) != 100 {
		t.Fatalf("got %d unique request ids out of 100", len(ids))
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for header, value := range want {
		if got := recorder.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

func TestRecoverReturnsOpaqueError(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := Recover(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("database password is hunter2")
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	body := recorder.Body.String()
	if bytes.Contains([]byte(body), []byte("hunter2")) {
		t.Fatalf("panic detail leaked to the client: %s", body)
	}
	var decoded problemBody
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if decoded.Error.Code != "internal_error" {
		t.Errorf("error code = %q, want internal_error", decoded.Error.Code)
	}
	if !bytes.Contains(logs.Bytes(), []byte("handler panicked")) {
		t.Error("the panic should still be recorded in the server log")
	}
}

func TestAccessLogRecordsOutcome(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("nope"))
	}), RequestID, AccessLog(logger))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil))

	var record map[string]any
	if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
		t.Fatalf("log line is not valid JSON: %v", err)
	}
	if record["status"] != float64(http.StatusTeapot) {
		t.Errorf("logged status = %v, want %d", record["status"], http.StatusTeapot)
	}
	if record["path"] != "/v1/sys/health" {
		t.Errorf("logged path = %v", record["path"])
	}
	if record["request_id"] == "" || record["request_id"] == nil {
		t.Error("access log should carry the request id")
	}
	if record["bytes"] != float64(4) {
		t.Errorf("logged bytes = %v, want 4", record["bytes"])
	}
}

func TestJSONWritesContentType(t *testing.T) {
	recorder := httptest.NewRecorder()
	JSON(recorder, http.StatusCreated, map[string]string{"status": "ok"})

	if recorder.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content type = %q", got)
	}
	if recorder.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Errorf("body = %q", recorder.Body.String())
	}
}
