package rotate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/audit"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

type fakeKeys struct {
	version    int
	rotateErr  error
	versionErr error
	rotations  int
}

func (k *fakeKeys) KEKVersion(context.Context) (int, error) {
	if k.versionErr != nil {
		return 0, k.versionErr
	}
	return k.version, nil
}

func (k *fakeKeys) Rotate(context.Context) (int, int, error) {
	if k.rotateErr != nil {
		return 0, 0, k.rotateErr
	}
	k.rotations++
	from := k.version
	k.version++
	return from, k.version, nil
}

type fakeSubject struct {
	name     string
	progress Progress
	err      error
	calls    int
	before   func()
}

func (s *fakeSubject) Name() string {
	return s.name
}

func (s *fakeSubject) Rewrap(context.Context) (Progress, error) {
	s.calls++
	if s.before != nil {
		s.before()
	}
	return s.progress, s.err
}

type fakeAuthorizer struct {
	permitted bool
	err       error
	tenant    string
	path      string
}

func (a *fakeAuthorizer) Permitted(_ context.Context, _ authn.Identity, tenant, path string) (bool, error) {
	a.tenant, a.path = tenant, path
	return a.permitted, a.err
}

type recordingSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *recordingSink) Append(_ context.Context, event audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *recordingSink) recorded() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.events...)
}

func identityGuard(identity authn.Identity, present bool) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !present {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(authn.WithIdentity(r.Context(), identity)))
		})
	}
}

type harness struct {
	handler http.Handler
	keys    *fakeKeys
	authz   *fakeAuthorizer
	sink    *recordingSink
	secrets *fakeSubject
	params  *fakeSubject
}

func newHarness(t *testing.T, opts ...func(*Options)) *harness {
	t.Helper()

	keys := &fakeKeys{version: 1}
	authz := &fakeAuthorizer{permitted: true}
	sink := &recordingSink{}
	secrets := &fakeSubject{name: "secret", progress: Progress{Examined: 4, Rewrapped: 4}}
	params := &fakeSubject{name: "param", progress: Progress{Examined: 2, Rewrapped: 2}}

	options := Options{
		Keys:       keys,
		Subjects:   []Subject{secrets, params},
		Authorizer: authz,
		Audit:      sink,
		Guard:      identityGuard(authn.Identity{ID: "service/ci", Tenant: "prod"}, true),
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, apply := range opts {
		apply(&options)
	}

	module, err := NewModule(options)
	if err != nil {
		t.Fatalf("NewModule returned error: %v", err)
	}

	mux := http.NewServeMux()
	module.Register(mux)

	return &harness{handler: mux, keys: keys, authz: authz, sink: sink, secrets: secrets, params: params}
}

func (h *harness) post(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, pathRotate, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestARotationMovesTheKeyAndReportsEverySubject(t *testing.T) {
	h := newHarness(t)

	recorder := h.post(t, `{"current_version":1}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST %s returned %d, want 200: %s", pathRotate, recorder.Code, recorder.Body)
	}

	var body response
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if body.From != 1 || body.To != 2 {
		t.Errorf("response = %+v, want a move from 1 to 2", body)
	}
	if len(body.Subjects) != 2 {
		t.Fatalf("the response names %d subjects, want 2", len(body.Subjects))
	}
	if body.Subjects[0].Name != "secret" || body.Subjects[0].Rewrapped != 4 {
		t.Errorf("subject = %+v, want the secret module's four", body.Subjects[0])
	}
	if body.Subjects[1].Name != "param" || body.Subjects[1].Rewrapped != 2 {
		t.Errorf("subject = %+v, want the param module's two", body.Subjects[1])
	}
}

func TestARotationIsRecorded(t *testing.T) {
	h := newHarness(t)
	h.post(t, `{"current_version":1}`)

	events := h.sink.recorded()
	if len(events) != 1 {
		t.Fatalf("the sink saw %d events, want 1", len(events))
	}
	if events[0].Operation != "rotate.kek" || events[0].Result != audit.ResultAllow {
		t.Errorf("event = %+v, want an allowed rotate.kek", events[0])
	}
	if events[0].Identity != "service/ci" {
		t.Errorf("the record names %q rather than the caller", events[0].Identity)
	}
}

func TestARefusedRotationIsRecordedAndChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.authz.permitted = false

	recorder := h.post(t, `{"current_version":1}`)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("POST returned %d, want 403", recorder.Code)
	}
	if h.keys.rotations != 0 {
		t.Error("a refused rotation moved the key anyway")
	}
	if h.secrets.calls != 0 || h.params.calls != 0 {
		t.Error("a refused rotation still walked the stores")
	}

	events := h.sink.recorded()
	if len(events) != 1 || events[0].Result != audit.ResultDeny {
		t.Fatalf("events = %+v, want one denial", events)
	}
}

func TestARotationIsAuthorizedOnItsOwnPath(t *testing.T) {
	h := newHarness(t)
	h.post(t, `{"current_version":1}`)

	if h.authz.path != policyPath {
		t.Errorf("the rotation was authorized on %q, want %q", h.authz.path, policyPath)
	}
	if h.authz.tenant != "prod" {
		t.Errorf("the rotation was authorized against tenant %q, want the caller's own", h.authz.tenant)
	}
}

func TestARotationNeedsTheCallerToKnowTheCurrentVersion(t *testing.T) {
	for name, body := range map[string]string{
		"behind": `{"current_version":1}`,
		"ahead":  `{"current_version":9}`,
		"absent": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.keys.version = 4

			recorder := h.post(t, body)
			if recorder.Code != http.StatusConflict {
				t.Errorf("POST with a %s version returned %d, want 409", name, recorder.Code)
			}
			if h.keys.rotations != 0 {
				t.Error("the key moved despite the mismatch")
			}
		})
	}
}

func TestARotationNeedsAnIdentity(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.Guard = identityGuard(authn.Identity{}, false)
	})

	recorder := h.post(t, `{"current_version":1}`)
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("POST without an identity returned %d, want 401", recorder.Code)
	}
	if h.keys.rotations != 0 {
		t.Error("an unauthenticated request moved the key")
	}
}

func TestAMalformedBodyIsRefusedBeforeAnythingMoves(t *testing.T) {
	h := newHarness(t)

	recorder := h.post(t, `{"current_version":`)
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("POST with a malformed body returned %d, want 400", recorder.Code)
	}
	if h.keys.rotations != 0 {
		t.Error("a malformed request moved the key")
	}
}

func TestASubjectFailureLeavesTheRotationRecordedAsIncomplete(t *testing.T) {
	h := newHarness(t)
	h.params.err = errors.New("the param store is unavailable")

	recorder := h.post(t, `{"current_version":1}`)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("POST returned %d, want 500", recorder.Code)
	}
	if h.keys.rotations != 1 {
		t.Error("the key did not move before the failure")
	}
	if h.secrets.calls != 1 {
		t.Error("the earlier subject was not walked")
	}

	events := h.sink.recorded()
	if len(events) != 0 {
		t.Errorf("an incomplete rotation was recorded as allowed: %+v", events)
	}
}

func TestOnlyOneRotationRunsAtATime(t *testing.T) {
	h := newHarness(t)

	var second *httptest.ResponseRecorder
	h.secrets.before = func() {
		second = h.post(t, `{"current_version":2}`)
	}

	first := h.post(t, `{"current_version":1}`)
	if first.Code != http.StatusOK {
		t.Fatalf("the first rotation returned %d, want 200", first.Code)
	}
	if second == nil {
		t.Fatal("the second request never ran")
	}
	if second.Code != http.StatusConflict {
		t.Errorf("the overlapping rotation returned %d, want 409", second.Code)
	}
	if h.keys.rotations != 1 {
		t.Errorf("the key moved %d times, want once", h.keys.rotations)
	}
}

func TestNewModuleInsistsOnItsDependencies(t *testing.T) {
	base := func() Options {
		return Options{
			Keys:       &fakeKeys{version: 1},
			Subjects:   []Subject{&fakeSubject{name: "secret"}},
			Authorizer: &fakeAuthorizer{},
			Guard:      identityGuard(authn.Identity{}, true),
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
	}

	cases := map[string]struct {
		spoil func(*Options)
		want  error
	}{
		"no keys":       {spoil: func(o *Options) { o.Keys = nil }, want: ErrNoKeys},
		"no authorizer": {spoil: func(o *Options) { o.Authorizer = nil }, want: ErrNoAuthorizer},
		"no guard":      {spoil: func(o *Options) { o.Guard = nil }, want: ErrNoGuard},
		"no subjects":   {spoil: func(o *Options) { o.Subjects = nil }, want: ErrNoSubjects},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			options := base()
			tc.spoil(&options)
			if _, err := NewModule(options); !errors.Is(err, tc.want) {
				t.Fatalf("NewModule with %s = %v, want %v", name, err, tc.want)
			}
		})
	}
}
