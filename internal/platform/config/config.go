package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/logging"
)

const envPrefix = "MARSEC_"

type Getenv func(string) string

type Config struct {
	ListenAddr             string
	DataDir                string
	TLSCertFile            string
	TLSKeyFile             string
	LogLevel               string
	ShutdownTimeout        time.Duration
	AllowInsecureHTTP      bool
	AllowUnprotectedMemory bool

	ControlPlaneIssuer   string
	ControlPlaneAudience string
	ControlPlaneJWKSFile string
	ControlPlaneSkew     time.Duration
}

func (c Config) InstanceLoginConfigured() bool {
	return c.ControlPlaneIssuer != "" || c.ControlPlaneJWKSFile != ""
}

func Default() Config {
	return Config{
		ListenAddr:           "127.0.0.1:8200",
		DataDir:              "/var/lib/marstack-secrets",
		LogLevel:             "info",
		ShutdownTimeout:      15 * time.Second,
		ControlPlaneAudience: "marstack-secrets",
		ControlPlaneSkew:     30 * time.Second,
	}
}

func Load(getenv Getenv) (Config, error) {
	cfg := Default()

	cfg.ListenAddr = stringVar(getenv, "LISTEN_ADDR", cfg.ListenAddr)
	cfg.DataDir = stringVar(getenv, "DATA_DIR", cfg.DataDir)
	cfg.TLSCertFile = stringVar(getenv, "TLS_CERT_FILE", cfg.TLSCertFile)
	cfg.TLSKeyFile = stringVar(getenv, "TLS_KEY_FILE", cfg.TLSKeyFile)
	cfg.LogLevel = stringVar(getenv, "LOG_LEVEL", cfg.LogLevel)

	timeout, err := durationVar(getenv, "SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout)
	if err != nil {
		return Config{}, err
	}
	cfg.ShutdownTimeout = timeout

	insecure, err := boolVar(getenv, "ALLOW_INSECURE_HTTP", cfg.AllowInsecureHTTP)
	if err != nil {
		return Config{}, err
	}
	cfg.AllowInsecureHTTP = insecure

	unprotected, err := boolVar(getenv, "ALLOW_UNPROTECTED_MEMORY", cfg.AllowUnprotectedMemory)
	if err != nil {
		return Config{}, err
	}
	cfg.AllowUnprotectedMemory = unprotected

	cfg.ControlPlaneIssuer = stringVar(getenv, "CONTROL_PLANE_ISSUER", cfg.ControlPlaneIssuer)
	cfg.ControlPlaneAudience = stringVar(getenv, "CONTROL_PLANE_AUDIENCE", cfg.ControlPlaneAudience)
	cfg.ControlPlaneJWKSFile = stringVar(getenv, "CONTROL_PLANE_JWKS_FILE", cfg.ControlPlaneJWKSFile)

	skew, err := durationVar(getenv, "CONTROL_PLANE_SKEW", cfg.ControlPlaneSkew)
	if err != nil {
		return Config{}, err
	}
	cfg.ControlPlaneSkew = skew

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	var problems []error

	if c.ListenAddr == "" {
		problems = append(problems, errors.New("listen address must not be empty"))
	}
	if c.DataDir == "" {
		problems = append(problems, errors.New("data directory must not be empty"))
	} else if !filepath.IsAbs(c.DataDir) {
		problems = append(problems, fmt.Errorf("data directory %q must be an absolute path", c.DataDir))
	}
	if _, err := logging.ParseLevel(c.LogLevel); err != nil {
		problems = append(problems, err)
	}
	if c.ShutdownTimeout <= 0 {
		problems = append(problems, errors.New("shutdown timeout must be greater than zero"))
	}

	if c.InstanceLoginConfigured() {
		switch {
		case c.ControlPlaneIssuer == "":
			problems = append(problems, errors.New("control plane issuer is required to accept instance logins"))
		case c.ControlPlaneJWKSFile == "":
			problems = append(problems, errors.New("control plane key set file is required to accept instance logins"))
		case c.ControlPlaneAudience == "":
			problems = append(problems, errors.New("control plane audience must not be empty"))
		case c.ControlPlaneSkew < 0:
			problems = append(problems, errors.New("control plane clock skew must not be negative"))
		}
	}

	switch {
	case c.AllowInsecureHTTP && (c.TLSCertFile != "" || c.TLSKeyFile != ""):
		problems = append(problems, errors.New("plaintext HTTP and TLS certificates are mutually exclusive"))
	case !c.AllowInsecureHTTP && (c.TLSCertFile == "" || c.TLSKeyFile == ""):
		problems = append(problems, errors.New("TLS certificate and key are required unless "+envPrefix+"ALLOW_INSECURE_HTTP is set"))
	}

	return errors.Join(problems...)
}

func stringVar(getenv Getenv, name, fallback string) string {
	if raw := strings.TrimSpace(getenv(envPrefix + name)); raw != "" {
		return raw
	}
	return fallback
}

func boolVar(getenv Getenv, name string, fallback bool) (bool, error) {
	raw := getenv(envPrefix + name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s%s: %q is not a boolean", envPrefix, name, raw)
	}
	return value, nil
}

func durationVar(getenv Getenv, name string, fallback time.Duration) (time.Duration, error) {
	raw := getenv(envPrefix + name)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s%s: %q is not a duration", envPrefix, name, raw)
	}
	return value, nil
}
