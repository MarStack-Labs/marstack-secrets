package config

import (
	"strings"
	"testing"
	"time"
)

func envFrom(values map[string]string) Getenv {
	return func(key string) string { return values[key] }
}

func TestLoadRequiresTLSByDefault(t *testing.T) {
	_, err := Load(envFrom(nil))
	if err == nil {
		t.Fatal("expected the default configuration to be rejected without TLS material")
	}
	if !strings.Contains(err.Error(), "TLS certificate and key are required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadDefaultsToLoopback(t *testing.T) {
	cfg, err := Load(envFrom(map[string]string{
		"MARSEC_TLS_CERT_FILE": "/etc/marstack-secrets/tls.pem",
		"MARSEC_TLS_KEY_FILE":  "/etc/marstack-secrets/tls-key.pem",
	}))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:8200" {
		t.Errorf("default listen address = %q, want loopback", cfg.ListenAddr)
	}
	if cfg.AllowInsecureHTTP {
		t.Error("plaintext HTTP must be off by default")
	}
}

func TestLoadOverridesFromEnvironment(t *testing.T) {
	cfg, err := Load(envFrom(map[string]string{
		"MARSEC_LISTEN_ADDR":         "0.0.0.0:9000",
		"MARSEC_DATA_DIR":            "/srv/marsec",
		"MARSEC_LOG_LEVEL":           "debug",
		"MARSEC_SHUTDOWN_TIMEOUT":    "5s",
		"MARSEC_ALLOW_INSECURE_HTTP": "true",
	}))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	want := Default()
	want.ListenAddr = "0.0.0.0:9000"
	want.DataDir = "/srv/marsec"
	want.LogLevel = "debug"
	want.ShutdownTimeout = 5 * time.Second
	want.AllowInsecureHTTP = true
	if cfg != want {
		t.Errorf("Load() = %+v, want %+v", cfg, want)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	cases := map[string]map[string]string{
		"relative data dir": {
			"MARSEC_ALLOW_INSECURE_HTTP": "true",
			"MARSEC_DATA_DIR":            "relative/path",
		},
		"unknown log level": {
			"MARSEC_ALLOW_INSECURE_HTTP": "true",
			"MARSEC_LOG_LEVEL":           "verbose",
		},
		"malformed duration": {
			"MARSEC_ALLOW_INSECURE_HTTP": "true",
			"MARSEC_SHUTDOWN_TIMEOUT":    "soon",
		},
		"malformed boolean": {
			"MARSEC_ALLOW_INSECURE_HTTP": "maybe",
		},
		"zero shutdown timeout": {
			"MARSEC_ALLOW_INSECURE_HTTP": "true",
			"MARSEC_SHUTDOWN_TIMEOUT":    "0s",
		},
		"insecure http together with tls": {
			"MARSEC_ALLOW_INSECURE_HTTP": "true",
			"MARSEC_TLS_CERT_FILE":       "/etc/marstack-secrets/tls.pem",
			"MARSEC_TLS_KEY_FILE":        "/etc/marstack-secrets/tls-key.pem",
		},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(envFrom(env)); err == nil {
				t.Fatal("expected the configuration to be rejected")
			}
		})
	}
}

func TestInstanceLoginNeedsItsWholeConfiguration(t *testing.T) {
	base := map[string]string{"MARSEC_ALLOW_INSECURE_HTTP": "true"}

	withEnv := func(extra map[string]string) map[string]string {
		merged := map[string]string{}
		for key, value := range base {
			merged[key] = value
		}
		for key, value := range extra {
			merged[key] = value
		}
		return merged
	}

	if _, err := Load(envFrom(withEnv(nil))); err != nil {
		t.Fatalf("an unconfigured control plane should be fine: %v", err)
	}

	cases := map[string]map[string]string{
		"issuer without keys": {"MARSEC_CONTROL_PLANE_ISSUER": "https://control.example"},
		"keys without issuer": {"MARSEC_CONTROL_PLANE_JWKS_FILE": "/etc/marstack-secrets/jwks.json"},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(envFrom(withEnv(extra))); err == nil {
				t.Fatal("expected the configuration to be rejected")
			}
		})
	}

	cfg, err := Load(envFrom(withEnv(map[string]string{
		"MARSEC_CONTROL_PLANE_ISSUER":    "https://control.example",
		"MARSEC_CONTROL_PLANE_JWKS_FILE": "/etc/marstack-secrets/jwks.json",
		"MARSEC_CONTROL_PLANE_AUDIENCE":  "   ",
	})))
	if err != nil {
		t.Fatalf("a complete control plane configuration was rejected: %v", err)
	}
	if !cfg.InstanceLoginConfigured() {
		t.Error("InstanceLoginConfigured() = false for a complete configuration")
	}
	if cfg.ControlPlaneAudience != Default().ControlPlaneAudience {
		t.Errorf("a whitespace only audience became %q, want the default", cfg.ControlPlaneAudience)
	}
}

func TestWhitespaceIsTreatedAsUnset(t *testing.T) {
	cfg, err := Load(envFrom(map[string]string{
		"MARSEC_ALLOW_INSECURE_HTTP": "true",
		"MARSEC_LISTEN_ADDR":         "   ",
		"MARSEC_DATA_DIR":            "  /srv/marsec  ",
	}))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ListenAddr != Default().ListenAddr {
		t.Errorf("ListenAddr = %q, want the default", cfg.ListenAddr)
	}
	if cfg.DataDir != "/srv/marsec" {
		t.Errorf("DataDir = %q, want it trimmed", cfg.DataDir)
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	cfg := Config{ListenAddr: "", DataDir: "relative", LogLevel: "verbose"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	for _, fragment := range []string{"listen address", "absolute path", "unknown log level", "shutdown timeout", "TLS certificate"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("error is missing %q: %v", fragment, err)
		}
	}
}
