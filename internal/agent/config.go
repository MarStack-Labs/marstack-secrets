package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	MethodBootstrap = "bootstrap"
	MethodInstance  = "instance"

	defaultPollInterval = time.Minute
	defaultRenewBefore  = 5 * time.Minute
	defaultMode         = "0400"
	maxConfigBytes      = 256 << 10
)

var (
	ErrNoAddress    = errors.New("agent: an address is required")
	ErrNoTenant     = errors.New("agent: a tenant is required")
	ErrNoMethod     = errors.New("agent: the auth method must be bootstrap or instance")
	ErrNoCredential = errors.New("agent: a credential file is required")
	ErrNoTemplates  = errors.New("agent: at least one template is required")
	ErrBadTemplate  = errors.New("agent: a template needs a source and a destination")
	ErrBadMode      = errors.New("agent: a template mode must be an octal file mode")
	ErrConfigLarge  = errors.New("agent: the configuration is larger than the accepted maximum")
	ErrBadInterval  = errors.New("agent: intervals must be positive durations")
)

type Auth struct {
	Method         string `json:"method"`
	CredentialFile string `json:"credential_file"`
}

type Template struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Mode        string   `json:"mode"`
	Command     []string `json:"command"`
}

func (t Template) mode() (os.FileMode, error) {
	raw := t.Mode
	if raw == "" {
		raw = defaultMode
	}
	parsed, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrBadMode, t.Mode)
	}
	return os.FileMode(parsed), nil
}

type Config struct {
	Address        string     `json:"address"`
	CACertFile     string     `json:"ca_cert_file"`
	AllowPlainHTTP bool       `json:"allow_plain_http"`
	Tenant         string     `json:"tenant"`
	Auth           Auth       `json:"auth"`
	PollInterval   string     `json:"poll_interval"`
	RenewBefore    string     `json:"renew_before"`
	Templates      []Template `json:"templates"`
}

type intervals struct {
	poll        time.Duration
	renewBefore time.Duration
}

func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, err
	}
	if info.Size() > maxConfigBytes {
		return Config{}, ErrConfigLarge
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("agent: reading %s: %w", path, err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	switch {
	case c.Address == "":
		return ErrNoAddress
	case c.Tenant == "":
		return ErrNoTenant
	case c.Auth.Method != MethodBootstrap && c.Auth.Method != MethodInstance:
		return ErrNoMethod
	case c.Auth.CredentialFile == "":
		return ErrNoCredential
	case len(c.Templates) == 0:
		return ErrNoTemplates
	}

	for _, one := range c.Templates {
		if one.Source == "" || one.Destination == "" {
			return ErrBadTemplate
		}
		if !filepath.IsAbs(one.Destination) {
			return fmt.Errorf("%w: %q is not an absolute path", ErrBadTemplate, one.Destination)
		}
		if _, err := one.mode(); err != nil {
			return err
		}
	}

	if _, err := c.intervals(); err != nil {
		return err
	}
	return nil
}

func (c Config) intervals() (intervals, error) {
	resolved := intervals{poll: defaultPollInterval, renewBefore: defaultRenewBefore}

	if c.PollInterval != "" {
		parsed, err := time.ParseDuration(c.PollInterval)
		if err != nil || parsed <= 0 {
			return intervals{}, fmt.Errorf("%w: poll_interval %q", ErrBadInterval, c.PollInterval)
		}
		resolved.poll = parsed
	}
	if c.RenewBefore != "" {
		parsed, err := time.ParseDuration(c.RenewBefore)
		if err != nil || parsed <= 0 {
			return intervals{}, fmt.Errorf("%w: renew_before %q", ErrBadInterval, c.RenewBefore)
		}
		resolved.renewBefore = parsed
	}
	return resolved, nil
}
