package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/client"
	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

const (
	maxTemplateBytes = 1 << 20
	tempPrefix       = ".marsec-"
)

var (
	ErrNoStore    = errors.New("agent: the store is not reachable")
	ErrNoRunner   = errors.New("agent: a command runner is required")
	ErrRenderFail = errors.New("agent: a template did not render")
)

type Runner interface {
	Run(ctx context.Context, argv []string) error
}

type Commands struct{}

func (Commands) Run(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

type Options struct {
	Logger *slog.Logger
	Runner Runner
	Now    func() time.Time
}

type Agent struct {
	config    Config
	intervals intervals
	client    *client.Client
	runner    Runner
	logger    *slog.Logger
	now       func() time.Time

	loggedIn bool
	leases   map[string]time.Time
}

func New(config Config, opts Options) (*Agent, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	spans, err := config.intervals()
	if err != nil {
		return nil, err
	}

	made, err := client.New(client.Options{
		Address:        config.Address,
		CACertFile:     config.CACertFile,
		AllowPlainHTTP: config.AllowPlainHTTP,
	})
	if err != nil {
		return nil, err
	}

	runner := opts.Runner
	if runner == nil {
		runner = Commands{}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	return &Agent{
		config:    config,
		intervals: spans,
		client:    made,
		runner:    runner,
		logger:    logger,
		now:       clock,
		leases:    make(map[string]time.Time),
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	for {
		if err := a.Cycle(ctx); err != nil {
			a.logger.Error("cycle failed; leaving the rendered files as they are", "error", err)
			a.loggedIn = false
		}

		wait := a.intervals.poll/2 + time.Duration(rand.Int64N(int64(a.intervals.poll)))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

func (a *Agent) Cycle(ctx context.Context) error {
	if err := a.ensureSession(ctx); err != nil {
		return err
	}

	for _, one := range a.config.Templates {
		changed, err := a.render(ctx, one)
		if err != nil {
			return err
		}
		if !changed {
			continue
		}

		a.logger.Info("rendered", "destination", one.Destination)
		if len(one.Command) > 0 {
			if err := a.runner.Run(ctx, one.Command); err != nil {
				return fmt.Errorf("agent: running %v: %w", one.Command, err)
			}
			a.logger.Info("reloaded", "command", one.Command)
		}
	}

	return a.renewLeases(ctx)
}

func (a *Agent) ensureSession(ctx context.Context) error {
	if a.loggedIn {
		return nil
	}

	credential, err := os.ReadFile(a.config.Auth.CredentialFile)
	if err != nil {
		return err
	}
	trimmed := crypto.Sensitive(strings.TrimSpace(string(credential)))
	defer trimmed.Zero()

	switch a.config.Auth.Method {
	case MethodBootstrap:
		_, err = a.client.LoginBootstrap(ctx, trimmed)
	case MethodInstance:
		_, err = a.client.LoginInstance(ctx, trimmed)
	default:
		return ErrNoMethod
	}
	if err != nil {
		return err
	}

	a.loggedIn = true
	a.logger.Info("authenticated", "method", a.config.Auth.Method)
	return nil
}

func (a *Agent) render(ctx context.Context, spec Template) (bool, error) {
	source, err := os.ReadFile(spec.Source)
	if err != nil {
		return false, err
	}
	if len(source) > maxTemplateBytes {
		return false, fmt.Errorf("%w: %s is too large", ErrRenderFail, spec.Source)
	}

	parsed, err := template.New(filepath.Base(spec.Source)).
		Option("missingkey=error").
		Funcs(a.functions(ctx)).
		Parse(string(source))
	if err != nil {
		return false, errors.Join(ErrRenderFail, err)
	}

	var rendered bytes.Buffer
	if err := parsed.Execute(&rendered, nil); err != nil {
		return false, errors.Join(ErrRenderFail, err)
	}
	defer crypto.Sensitive(rendered.Bytes()).Zero()

	return a.place(spec, rendered.Bytes())
}

func (a *Agent) functions(ctx context.Context) template.FuncMap {
	return template.FuncMap{
		"secret": func(path string) (string, error) {
			found, err := a.client.ReadSecret(ctx, a.config.Tenant, path, 0)
			if err != nil {
				return "", err
			}
			if found.LeaseID != "" {
				a.leases[found.LeaseID] = a.now().Add(found.LeaseTTL)
			}
			return string(found.Value), nil
		},
		"param": func(path string) (string, error) {
			found, err := a.client.ReadParameter(ctx, a.config.Tenant, path)
			if err != nil {
				return "", err
			}
			return string(found.Value), nil
		},
	}
}

func (a *Agent) place(spec Template, content []byte) (bool, error) {
	mode, err := spec.mode()
	if err != nil {
		return false, err
	}

	existing, err := os.ReadFile(spec.Destination)
	if err == nil && bytes.Equal(existing, content) {
		crypto.Sensitive(existing).Zero()
		return false, nil
	}
	crypto.Sensitive(existing).Zero()

	directory := filepath.Dir(spec.Destination)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, err
	}

	temporary, err := os.CreateTemp(directory, tempPrefix)
	if err != nil {
		return false, err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()

	if err := temporary.Chmod(mode); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if _, err := temporary.Write(content); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(name, spec.Destination); err != nil {
		return false, err
	}
	return true, nil
}

func (a *Agent) renewLeases(ctx context.Context) error {
	deadline := a.now().Add(a.intervals.renewBefore)

	for id, expiry := range a.leases {
		if expiry.After(deadline) {
			continue
		}
		if err := a.client.RenewLease(ctx, id, 0); err != nil {
			if errors.Is(err, client.ErrNotFound) {
				delete(a.leases, id)
				a.logger.Warn("a lease is gone; it will be reissued on the next read", "lease", id)
				continue
			}
			return err
		}
		a.leases[id] = a.now().Add(a.intervals.renewBefore * 2)
		a.logger.Info("renewed", "lease", id)
	}
	return nil
}

func (a *Agent) Tracked() int {
	return len(a.leases)
}
