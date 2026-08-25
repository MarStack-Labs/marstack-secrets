package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
)

func newTestModule(t *testing.T) (*Module, *Manager, *clock) {
	t.Helper()
	manager, tick, _ := newTestManager(t)
	return NewModule(manager, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, Limits{}), manager, tick
}

func handlerFor(t *testing.T, module *Module) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	module.Register(mux)
	return mux
}

func post(t *testing.T, handler http.Handler, path string, body any, bearer string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding the body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}

	request := httptest.NewRequest(http.MethodPost, path, reader)
	if bearer != "" {
		request.Header.Set(headerAuthorization, bearerScheme+bearer)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func get(t *testing.T, handler http.Handler, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		request.Header.Set(headerAuthorization, bearerScheme+bearer)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestInstanceLoginIsNotRoutedWhenUnconfigured(t *testing.T) {
	module, _, _ := newTestModule(t)
	handler := handlerFor(t, module)

	recorder := post(t, handler, pathInstanceLogin, instanceLoginRequest{Assertion: "x"}, "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d when no control plane is configured", recorder.Code, http.StatusNotFound)
	}
}

func TestInstanceLoginOverHTTP(t *testing.T) {
	manager, tick, control := instanceSetup(t)
	module := NewModule(manager, slog.New(slog.NewJSONHandler(io.Discard, nil)), control.verifier, Limits{})
	handler := handlerFor(t, module)

	assertion := control.assert(t, "instance/web-01", "prod", tick.at)

	recorder := post(t, handler, pathInstanceLogin, instanceLoginRequest{Assertion: string(assertion)}, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response loginResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}

	replay := post(t, handler, pathInstanceLogin, instanceLoginRequest{Assertion: string(assertion)}, "")
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("a replayed assertion returned %d, want %d", replay.Code, http.StatusUnauthorized)
	}

	self := get(t, handler, pathSelf, response.Token)
	if self.Code != http.StatusOK {
		t.Fatalf("the instance session cannot reach a protected endpoint: %d %s", self.Code, self.Body.String())
	}

	var identity selfResponse
	if err := json.Unmarshal(self.Body.Bytes(), &identity); err != nil {
		t.Fatalf("decoding the self response: %v", err)
	}
	if identity.Identity != "instance/web-01" || identity.Tenant != "prod" || identity.Kind != "instance" {
		t.Errorf("self = %+v", identity)
	}
}

func TestBootstrapLoginReturnsASessionToken(t *testing.T) {
	module, manager, _ := newTestModule(t)
	handler := handlerFor(t, module)
	registered(t, manager, "instance/web-01", authn.KindBootstrap)

	bootstrap, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}

	recorder := post(t, handler, pathBootstrapLogin, loginRequest{Token: string(bootstrap.Value)}, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response loginResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if !strings.HasPrefix(response.Token, tokenPrefix) {
		t.Errorf("token = %q, want the %q prefix", response.Token, tokenPrefix)
	}
	if response.ExpiresAt == "" {
		t.Error("the response carries no expiry")
	}

	self := get(t, handler, pathSelf, response.Token)
	if self.Code != http.StatusOK {
		t.Fatalf("self returned %d: %s", self.Code, self.Body.String())
	}

	var identity selfResponse
	if err := json.Unmarshal(self.Body.Bytes(), &identity); err != nil {
		t.Fatalf("decoding the self response: %v", err)
	}
	if identity.Identity != "instance/web-01" || identity.Tenant != "prod" {
		t.Errorf("self = %+v", identity)
	}
}

func TestBootstrapLoginRejectionsAreUniform(t *testing.T) {
	module, manager, _ := newTestModule(t)
	handler := handlerFor(t, module)
	registered(t, manager, "instance/web-01", authn.KindBootstrap)

	spent, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}
	if _, err := manager.Exchange(t.Context(), spent.Value, NoBinding, DefaultTTL); err != nil {
		t.Fatalf("Exchange returned error: %v", err)
	}
	session := issued(t, manager, "instance/web-01", NoBinding)

	cases := map[string]string{
		"already spent": string(spent.Value),
		"session token": string(session.Value),
		"never issued":  tokenPrefix + strings.Repeat("C", 43),
		"malformed":     "mss_short",
		"empty":         "",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := post(t, handler, pathBootstrapLogin, loginRequest{Token: token}, "")
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
			}
			if !strings.Contains(recorder.Body.String(), "unauthenticated") {
				t.Errorf("body = %q", recorder.Body.String())
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", got)
			}
		})
	}
}

func TestBootstrapLoginRejectsABadBody(t *testing.T) {
	module, _, _ := newTestModule(t)
	handler := handlerFor(t, module)

	for name, body := range map[string]any{
		"unknown field": map[string]string{"tokn": "mss_x"},
		"wrong type":    map[string]int{"token": 7},
	} {
		t.Run(name, func(t *testing.T) {
			if recorder := post(t, handler, pathBootstrapLogin, body, ""); recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestProtectedEndpointsNeedABearerToken(t *testing.T) {
	module, manager, _ := newTestModule(t)
	handler := handlerFor(t, module)
	registered(t, manager, "instance/web-01", authn.KindInstance)
	session := issued(t, manager, "instance/web-01", NoBinding)

	headers := map[string]string{
		"absent":      "",
		"empty":       bearerScheme,
		"scheme only": "Bearer",
		"wrong":       bearerScheme + tokenPrefix + strings.Repeat("D", 43),
		"basic":       "Basic dXNlcjpwYXNz",
		"raw token":   string(session.Value),
	}
	for name, header := range headers {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, pathSelf, nil)
			if header != "" {
				request.Header.Set(headerAuthorization, header)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestTheBearerSchemeIsCaseInsensitive(t *testing.T) {
	module, manager, _ := newTestModule(t)
	handler := handlerFor(t, module)
	registered(t, manager, "instance/web-01", authn.KindInstance)
	session := issued(t, manager, "instance/web-01", NoBinding)

	request := httptest.NewRequest(http.MethodGet, pathSelf, nil)
	request.Header.Set(headerAuthorization, "bearer "+string(session.Value))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestLogoutRevokesThePresentedToken(t *testing.T) {
	module, manager, _ := newTestModule(t)
	handler := handlerFor(t, module)
	registered(t, manager, "instance/web-01", authn.KindInstance)
	session := issued(t, manager, "instance/web-01", NoBinding)

	if recorder := post(t, handler, pathLogout, nil, string(session.Value)); recorder.Code != http.StatusNoContent {
		t.Fatalf("logout returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := get(t, handler, pathSelf, string(session.Value)); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("the token still works after logout: %d", recorder.Code)
	}
	if recorder := post(t, handler, pathLogout, nil, string(session.Value)); recorder.Code != http.StatusUnauthorized {
		t.Errorf("a repeated logout returned %d, want %d: a revoked token is no longer a credential",
			recorder.Code, http.StatusUnauthorized)
	}
}

func TestLogoutCannotRevokeSomebodyElsesToken(t *testing.T) {
	module, manager, _ := newTestModule(t)
	handler := handlerFor(t, module)
	registered(t, manager, "instance/web-01", authn.KindInstance)
	registered(t, manager, "instance/web-02", authn.KindInstance)

	mine := issued(t, manager, "instance/web-01", NoBinding)
	theirs := issued(t, manager, "instance/web-02", NoBinding)

	request := httptest.NewRequest(http.MethodPost, pathLogout, nil)
	request.Header.Set(headerAuthorization, bearerScheme+string(mine.Value))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("logout returned %d", recorder.Code)
	}
	if got := get(t, handler, pathSelf, string(theirs.Value)); got.Code != http.StatusOK {
		t.Errorf("another identity's token was revoked too: %d", got.Code)
	}
}

func TestNoResponseCarriesTheTokenBack(t *testing.T) {
	module, manager, _ := newTestModule(t)
	handler := handlerFor(t, module)
	registered(t, manager, "instance/web-01", authn.KindInstance)
	session := issued(t, manager, "instance/web-01", NoBinding)

	self := get(t, handler, pathSelf, string(session.Value))
	if bytes.Contains(self.Body.Bytes(), session.Value) {
		t.Errorf("the self response echoes the token: %s", self.Body.String())
	}
}

type countingLimiter struct {
	allowed int
	budget  int
}

func (c *countingLimiter) Allow(string) bool {
	if c.allowed >= c.budget {
		return false
	}
	c.allowed++
	return true
}

func TestLoginAttemptsAreRateLimitedPerSource(t *testing.T) {
	manager, tick, _ := newTestManager(t)
	_ = tick
	limiter := &countingLimiter{budget: 2}
	module := NewModule(manager, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, Limits{Logins: limiter})
	handler := handlerFor(t, module)

	for attempt := 1; attempt <= 2; attempt++ {
		recorder := post(t, handler, pathBootstrapLogin, loginRequest{Token: "mss_" + strings.Repeat("E", 43)}, "")
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d, want %d", attempt, recorder.Code, http.StatusUnauthorized)
		}
	}

	recorder := post(t, handler, pathBootstrapLogin, loginRequest{Token: "mss_" + strings.Repeat("E", 43)}, "")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("the third attempt returned %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}
	if got := recorder.Header().Get("Retry-After"); got == "" {
		t.Error("a rate limited response carries no Retry-After")
	}
	if !strings.Contains(recorder.Body.String(), "rate_limited") {
		t.Errorf("body = %q", recorder.Body.String())
	}
}

func TestAuthenticatedRequestsAreRateLimitedPerIdentity(t *testing.T) {
	manager, _, _ := newTestManager(t)
	limiter := &countingLimiter{budget: 1}
	module := NewModule(manager, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, Limits{Requests: limiter})
	handler := handlerFor(t, module)

	registered(t, manager, "instance/web-01", authn.KindInstance)
	session := issued(t, manager, "instance/web-01", NoBinding)

	if recorder := get(t, handler, pathSelf, string(session.Value)); recorder.Code != http.StatusOK {
		t.Fatalf("the first request returned %d", recorder.Code)
	}
	if recorder := get(t, handler, pathSelf, string(session.Value)); recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("the second request returned %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}
}

func TestAnUnauthenticatedRequestDoesNotSpendTheIdentityBudget(t *testing.T) {
	manager, _, _ := newTestManager(t)
	limiter := &countingLimiter{budget: 1}
	module := NewModule(manager, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, Limits{Requests: limiter})
	handler := handlerFor(t, module)

	registered(t, manager, "instance/web-01", authn.KindInstance)
	session := issued(t, manager, "instance/web-01", NoBinding)

	for range 5 {
		if recorder := get(t, handler, pathSelf, "mss_"+strings.Repeat("F", 43)); recorder.Code != http.StatusUnauthorized {
			t.Fatalf("an unknown token returned %d", recorder.Code)
		}
	}
	if recorder := get(t, handler, pathSelf, string(session.Value)); recorder.Code != http.StatusOK {
		t.Fatalf("the real token was refused with %d: unauthenticated traffic spent its budget", recorder.Code)
	}
}
