package main

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type stub struct {
	server    *httptest.Server
	caFile    string
	tokenFile string
	requests  []string
	bodies    []string
}

func newStub(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *stub {
	t.Helper()

	harness := &stub{}
	harness.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 512)
		read, _ := r.Body.Read(body)
		harness.requests = append(harness.requests, r.Method+" "+r.URL.RequestURI())
		harness.bodies = append(harness.bodies, string(body[:read]))
		handler(w, r)
	}))
	t.Cleanup(harness.server.Close)

	directory := t.TempDir()
	harness.caFile = filepath.Join(directory, "ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: harness.server.Certificate().Raw})
	if err := os.WriteFile(harness.caFile, encoded, 0o600); err != nil {
		t.Fatalf("writing the certificate: %v", err)
	}
	harness.tokenFile = filepath.Join(directory, "token")

	t.Setenv("MARSEC_ADDRESS", harness.server.URL)
	t.Setenv("MARSEC_CACERT", harness.caFile)
	t.Setenv("MARSEC_TOKEN_FILE", harness.tokenFile)
	t.Setenv("MARSEC_TOKEN", "")
	return harness
}

func TestLoginKeepsTheTokenInAPrivateFile(t *testing.T) {
	harness := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"mss_issued","expires_at":"2026-08-25T13:00:00Z"}`))
	})

	bootstrap := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.WriteFile(bootstrap, []byte("mss_bootstrap\n"), 0o600); err != nil {
		t.Fatalf("writing the bootstrap token: %v", err)
	}

	var out bytes.Buffer
	if err := runLogin(t.Context(), &out, []string{"--bootstrap-file", bootstrap}); err != nil {
		t.Fatalf("runLogin returned error: %v", err)
	}
	if !strings.Contains(out.String(), "logged in") {
		t.Errorf("output = %q", out.String())
	}

	stored, err := os.ReadFile(harness.tokenFile)
	if err != nil {
		t.Fatalf("reading the token file: %v", err)
	}
	if strings.TrimSpace(string(stored)) != "mss_issued" {
		t.Errorf("the token file holds %q", stored)
	}

	info, err := os.Stat(harness.tokenFile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != tokenFilePerm {
		t.Errorf("the token file is %o, want %o", perm, tokenFilePerm)
	}
}

func TestLoginNeedsExactlyOneCredential(t *testing.T) {
	newStub(t, func(w http.ResponseWriter, r *http.Request) {})

	var out bytes.Buffer
	if err := runLogin(t.Context(), &out, nil); err == nil {
		t.Error("login without a credential was accepted")
	}
	if err := runLogin(t.Context(), &out, []string{"--bootstrap-file", "a", "--assertion-file", "b"}); err == nil {
		t.Error("login with both credentials was accepted")
	}
}

func TestSecretGetPrintsTheValue(t *testing.T) {
	harness := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":"db_password=s3cr3t","version":2,"lease_id":"secret/prod/db/AB","lease_ttl":1800}`))
	})
	if err := os.WriteFile(harness.tokenFile, []byte("mss_session\n"), 0o600); err != nil {
		t.Fatalf("seeding the token: %v", err)
	}

	var out bytes.Buffer
	if err := runSecret(t.Context(), &out, []string{"get", "prod/apps/payment/db"}); err != nil {
		t.Fatalf("runSecret returned error: %v", err)
	}
	if strings.TrimSpace(out.String()) != "db_password=s3cr3t" {
		t.Errorf("output = %q", out.String())
	}
	if harness.requests[0] != "GET /v1/secret/data/prod/apps/payment/db" {
		t.Errorf("request = %q", harness.requests[0])
	}
}

func TestSecretGetPassesTheVersion(t *testing.T) {
	harness := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":"old","version":1}`))
	})
	if err := os.WriteFile(harness.tokenFile, []byte("mss_session\n"), 0o600); err != nil {
		t.Fatalf("seeding the token: %v", err)
	}

	var out bytes.Buffer
	if err := runSecret(t.Context(), &out, []string{"get", "prod/db", "--version", "1"}); err != nil {
		t.Fatalf("runSecret returned error: %v", err)
	}
	if !strings.Contains(harness.requests[0], "version=1") {
		t.Errorf("request = %q", harness.requests[0])
	}
}

func TestSecretPutReadsStdinAndSendsCheckAndSet(t *testing.T) {
	harness := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":3}`))
	})
	if err := os.WriteFile(harness.tokenFile, []byte("mss_session\n"), 0o600); err != nil {
		t.Fatalf("seeding the token: %v", err)
	}

	withStdin(t, "piped value\n", func() {
		var out bytes.Buffer
		if err := runSecret(t.Context(), &out, []string{"put", "prod/db", "--cas", "2"}); err != nil {
			t.Fatalf("runSecret returned error: %v", err)
		}
		if !strings.Contains(out.String(), "version 3") {
			t.Errorf("output = %q", out.String())
		}
	})

	if !strings.Contains(harness.bodies[0], `"value":"piped value"`) {
		t.Errorf("body = %q: the trailing newline should be trimmed", harness.bodies[0])
	}
	if !strings.Contains(harness.bodies[0], `"cas":2`) {
		t.Errorf("body = %q", harness.bodies[0])
	}
}

func TestSecretPutWithoutAValueIsRefused(t *testing.T) {
	harness := newStub(t, func(w http.ResponseWriter, r *http.Request) {})
	if err := os.WriteFile(harness.tokenFile, []byte("mss_session\n"), 0o600); err != nil {
		t.Fatalf("seeding the token: %v", err)
	}

	withStdin(t, "", func() {
		var out bytes.Buffer
		if err := runSecret(t.Context(), &out, []string{"put", "prod/db"}); err == nil {
			t.Error("a write with no value was accepted")
		}
	})
}

func TestAMissingSessionSaysWhatToDo(t *testing.T) {
	newStub(t, func(w http.ResponseWriter, r *http.Request) {})

	var out bytes.Buffer
	err := runSecret(t.Context(), &out, []string{"get", "prod/db"})
	if err == nil {
		t.Fatal("a read without a session was accepted")
	}
	if !strings.Contains(err.Error(), "marsec login") {
		t.Errorf("error = %q, want it to name the fix", err)
	}
}

func TestTheEnvironmentTokenWinsOverTheFile(t *testing.T) {
	harness := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":"v","version":1}`))
	})
	if err := os.WriteFile(harness.tokenFile, []byte("mss_from_file\n"), 0o600); err != nil {
		t.Fatalf("seeding the token: %v", err)
	}
	t.Setenv("MARSEC_TOKEN", "mss_from_env")

	var out bytes.Buffer
	if err := runSecret(t.Context(), &out, []string{"get", "prod/db"}); err != nil {
		t.Fatalf("runSecret returned error: %v", err)
	}
}

func TestALocationMustNameATenant(t *testing.T) {
	newStub(t, func(w http.ResponseWriter, r *http.Request) {})

	var out bytes.Buffer
	for _, location := range []string{"db", "/db", "prod/", ""} {
		if err := runSecret(t.Context(), &out, []string{"get", location}); err == nil {
			t.Errorf("%q was accepted as a location", location)
		}
	}
}

func TestParamGetReportsProvenanceWhenAsked(t *testing.T) {
	harness := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"path":"apps/log_level","resolved_from":"log_level","inherited":true,
			"kind":"string","value":"warn","sensitive":false,"references":[]}`))
	})
	if err := os.WriteFile(harness.tokenFile, []byte("mss_session\n"), 0o600); err != nil {
		t.Fatalf("seeding the token: %v", err)
	}

	var plain bytes.Buffer
	if err := runParam(t.Context(), &plain, []string{"get", "prod/apps/log_level"}); err != nil {
		t.Fatalf("runParam returned error: %v", err)
	}
	if strings.TrimSpace(plain.String()) != "warn" {
		t.Errorf("plain output = %q", plain.String())
	}

	var verbose bytes.Buffer
	if err := runParam(t.Context(), &verbose, []string{"get", "prod/apps/log_level", "--verbose"}); err != nil {
		t.Fatalf("runParam returned error: %v", err)
	}
	for _, expected := range []string{"from      log_level", "inherited true", "warn"} {
		if !strings.Contains(verbose.String(), expected) {
			t.Errorf("verbose output is missing %q:\n%s", expected, verbose.String())
		}
	}
}

func TestStatusNeedsNoToken(t *testing.T) {
	newStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"state":"sealed","shares":5,"threshold":3,"progress":1,"kek_version":4}`))
	})

	var out bytes.Buffer
	if err := runStatus(t.Context(), &out, nil); err != nil {
		t.Fatalf("runStatus returned error: %v", err)
	}
	for _, expected := range []string{"state       sealed", "threshold   3", "progress    1", "kek version 4"} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("output is missing %q:\n%s", expected, out.String())
		}
	}
}

func TestAnUnknownSubcommandIsRefused(t *testing.T) {
	newStub(t, func(w http.ResponseWriter, r *http.Request) {})

	var out bytes.Buffer
	if err := runSecret(t.Context(), &out, []string{"vanish", "prod/db"}); err == nil {
		t.Error("an unknown secret subcommand was accepted")
	}
	if err := runParam(t.Context(), &out, []string{"vanish", "prod/db"}); err == nil {
		t.Error("an unknown param subcommand was accepted")
	}
	if err := runSecret(t.Context(), &out, nil); err == nil {
		t.Error("secret with no subcommand was accepted")
	}
}

func withStdin(t *testing.T, content string, run func()) {
	t.Helper()

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating a pipe: %v", err)
	}
	original := os.Stdin
	os.Stdin = read
	defer func() {
		os.Stdin = original
		_ = read.Close()
	}()

	go func() {
		defer func() { _ = write.Close() }()
		_, _ = write.WriteString(content)
	}()

	run()
}
