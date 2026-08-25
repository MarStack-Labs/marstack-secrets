package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type store struct {
	mu        sync.Mutex
	secrets   map[string]string
	params    map[string]string
	issued    map[string]bool
	renewed   []string
	down      bool
	failReads bool
}

func newStore() *store {
	return &store{
		secrets: map[string]string{},
		params:  map[string]string{},
		issued:  map[string]bool{},
	}
}

func (s *store) set(path, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[path] = value
}

func (s *store) breakDown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = true
}

func (s *store) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		if s.down {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":"sealed"}}`))
			return
		}

		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/auth/"):
			_, _ = w.Write([]byte(`{"token":"mss_session","expires_at":"2026-08-25T14:00:00Z"}`))

		case strings.HasPrefix(r.URL.Path, "/v1/secret/data/prod/"):
			if s.failReads {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":"forbidden"}}`))
				return
			}
			path := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/prod/")
			value, known := s.secrets[path]
			if !known {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":{"code":"not_found"}}`))
				return
			}
			lease := "secret/prod/" + path + "/AB"
			s.issued[lease] = true
			response, _ := json.Marshal(map[string]any{
				"value": value, "version": 1,
				"lease_id": lease, "lease_ttl": 60,
			})
			_, _ = w.Write(response)

		case strings.HasPrefix(r.URL.Path, "/v1/param/data/prod/"):
			path := strings.TrimPrefix(r.URL.Path, "/v1/param/data/prod/")
			response, _ := json.Marshal(map[string]any{
				"path": path, "resolved_from": path, "kind": "string",
				"value": s.params[path], "references": []string{},
			})
			_, _ = w.Write(response)

		case r.URL.Path == "/v1/sys/leases/renew":
			body, _ := io.ReadAll(r.Body)

			var asked struct {
				LeaseID string `json:"lease_id"`
			}
			_ = json.Unmarshal(body, &asked)
			if !s.issued[asked.LeaseID] {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":{"code":"not_found"}}`))
				return
			}

			s.renewed = append(s.renewed, asked.LeaseID)
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found"}}`))
		}
	})
}

type recorder struct {
	mu   sync.Mutex
	runs [][]string
	fail error
}

func (r *recorder) Run(_ context.Context, argv []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.runs = append(r.runs, argv)
	return nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.runs)
}

type fixture struct {
	agent       *Agent
	store       *store
	commands    *recorder
	destination string
}

func newFixture(t *testing.T, body string, command ...string) *fixture {
	t.Helper()

	backing := newStore()
	server := httptest.NewTLSServer(backing.handler())
	t.Cleanup(server.Close)

	directory := t.TempDir()
	caFile := filepath.Join(directory, "ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, encoded, 0o600); err != nil {
		t.Fatalf("writing the certificate: %v", err)
	}

	credential := filepath.Join(directory, "bootstrap")
	if err := os.WriteFile(credential, []byte("mss_bootstrap\n"), 0o600); err != nil {
		t.Fatalf("writing the credential: %v", err)
	}

	source := filepath.Join(directory, "config.tmpl")
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the template: %v", err)
	}
	destination := filepath.Join(directory, "out", "config")

	commands := &recorder{}
	made, err := New(Config{
		Address:    server.URL,
		CACertFile: caFile,
		Tenant:     "prod",
		Auth:       Auth{Method: MethodBootstrap, CredentialFile: credential},
		Templates: []Template{{
			Source:      source,
			Destination: destination,
			Mode:        "0400",
			Command:     command,
		}},
	}, Options{
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Runner: commands,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	return &fixture{agent: made, store: backing, commands: commands, destination: destination}
}

func rendered(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(raw)
}

func TestTheAgentRendersSecretsAndParameters(t *testing.T) {
	fixture := newFixture(t, "password={{ secret \"apps/payment/db\" }}\nlevel={{ param \"apps/log_level\" }}\n")
	fixture.store.set("apps/payment/db", "s3cr3t")
	fixture.store.params["apps/log_level"] = "debug"

	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}

	got := rendered(t, fixture.destination)
	if got != "password=s3cr3t\nlevel=debug\n" {
		t.Errorf("rendered %q", got)
	}
}

func TestTheRenderedFileIsNotReadableByOthers(t *testing.T) {
	fixture := newFixture(t, `{{ secret "db" }}`)
	fixture.store.set("db", "s3cr3t")

	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}

	info, err := os.Stat(fixture.destination)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o400 {
		t.Errorf("mode = %o, want 400", perm)
	}
}

func TestTheCommandRunsOnlyWhenSomethingChanged(t *testing.T) {
	fixture := newFixture(t, `{{ secret "db" }}`, "systemctl", "reload", "app")
	fixture.store.set("db", "first")

	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}
	if fixture.commands.count() != 1 {
		t.Fatalf("the command ran %d times after the first render, want 1", fixture.commands.count())
	}

	for range 3 {
		if err := fixture.agent.Cycle(t.Context()); err != nil {
			t.Fatalf("Cycle returned error: %v", err)
		}
	}
	if fixture.commands.count() != 1 {
		t.Fatalf("the command ran %d times with nothing changed, want 1", fixture.commands.count())
	}

	fixture.store.set("db", "rotated")
	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}
	if fixture.commands.count() != 2 {
		t.Fatalf("the command ran %d times after a rotation, want 2", fixture.commands.count())
	}
	if rendered(t, fixture.destination) != "rotated" {
		t.Errorf("the file was not updated: %q", rendered(t, fixture.destination))
	}
}

func TestAnUnreachableStoreLeavesTheFileAlone(t *testing.T) {
	fixture := newFixture(t, `{{ secret "db" }}`, "reload")
	fixture.store.set("db", "last known good")

	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}
	before := rendered(t, fixture.destination)

	fixture.store.breakDown()

	if err := fixture.agent.Cycle(t.Context()); err == nil {
		t.Fatal("a cycle against a broken store reported success")
	}
	if after := rendered(t, fixture.destination); after != before {
		t.Errorf("the rendered file changed while the store was down: %q became %q", before, after)
	}
	if fixture.commands.count() != 1 {
		t.Errorf("the command ran %d times, want only the first render", fixture.commands.count())
	}
}

func TestAPartialRenderNeverReachesTheDestination(t *testing.T) {
	fixture := newFixture(t, "first={{ secret \"present\" }}\nsecond={{ secret \"absent\" }}\n")
	fixture.store.set("present", "here")

	if err := fixture.agent.Cycle(t.Context()); err == nil {
		t.Fatal("a template with a missing secret rendered")
	}
	if _, err := os.Stat(fixture.destination); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a half rendered file was written: %v", err)
	}
}

func TestNoTemporaryFileIsLeftBehind(t *testing.T) {
	fixture := newFixture(t, `{{ secret "db" }}`)
	fixture.store.set("db", "s3cr3t")

	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}

	entries, err := os.ReadDir(filepath.Dir(fixture.destination))
	if err != nil {
		t.Fatalf("reading the directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			t.Errorf("a temporary file survived: %s", entry.Name())
		}
	}
}

func TestLeasesAreRenewedBeforeTheyExpire(t *testing.T) {
	fixture := newFixture(t, `{{ secret "db" }}`)
	fixture.store.set("db", "s3cr3t")

	at := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	fixture.agent.now = func() time.Time { return at }
	fixture.agent.intervals.renewBefore = 5 * time.Minute

	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}
	if fixture.agent.Tracked() != 1 {
		t.Fatalf("the agent tracks %d leases, want 1", fixture.agent.Tracked())
	}

	fixture.store.mu.Lock()
	renewals := len(fixture.store.renewed)
	fixture.store.mu.Unlock()
	if renewals == 0 {
		t.Error("a lease expiring in a minute was not renewed against a five minute window")
	}
}

func TestAVanishedLeaseIsForgottenRatherThanFatal(t *testing.T) {
	fixture := newFixture(t, `{{ secret "db" }}`)
	fixture.store.set("db", "s3cr3t")

	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}

	fixture.agent.leases["secret/prod/gone/XY"] = time.Now().Add(-time.Hour)
	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}
	if _, still := fixture.agent.leases["secret/prod/gone/XY"]; still {
		t.Error("a lease the store no longer knows about is still tracked")
	}
}

func TestARefusedReadIsReportedRatherThanRendered(t *testing.T) {
	fixture := newFixture(t, `{{ secret "db" }}`)
	fixture.store.set("db", "s3cr3t")

	if err := fixture.agent.Cycle(t.Context()); err != nil {
		t.Fatalf("Cycle returned error: %v", err)
	}

	fixture.store.mu.Lock()
	fixture.store.failReads = true
	fixture.store.mu.Unlock()

	fixture.store.set("db", "never seen")
	if err := fixture.agent.Cycle(t.Context()); err == nil {
		t.Fatal("a refused read rendered")
	}
	if rendered(t, fixture.destination) != "s3cr3t" {
		t.Errorf("the file changed after a refusal: %q", rendered(t, fixture.destination))
	}
}

func TestAFailingCommandIsReported(t *testing.T) {
	fixture := newFixture(t, `{{ secret "db" }}`, "reload")
	fixture.store.set("db", "s3cr3t")
	fixture.commands.fail = errors.New("systemctl is unhappy")

	if err := fixture.agent.Cycle(t.Context()); err == nil {
		t.Fatal("a failing reload was reported as success")
	}
	if rendered(t, fixture.destination) != "s3cr3t" {
		t.Error("the file should still be written; only the reload failed")
	}
}
