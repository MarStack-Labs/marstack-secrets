package rotate

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/marstack-labs/marstack-secrets/internal/platform/audit"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

const moduleName = "rotate"

var (
	ErrNoKeys       = errors.New("rotate: a key rotator is required")
	ErrNoAuthorizer = errors.New("rotate: an authorizer is required")
	ErrNoGuard      = errors.New("rotate: an authentication guard is required")
	ErrNoSubjects   = errors.New("rotate: at least one subject is required")
	ErrInProgress   = errors.New("rotate: a rotation is already running")
)

type Progress struct {
	Examined  int
	Rewrapped int
}

type Keys interface {
	KEKVersion(ctx context.Context) (int, error)
	Rotate(ctx context.Context) (int, int, error)
}

type Subject interface {
	Name() string
	Rewrap(ctx context.Context) (Progress, error)
}

type Authorizer interface {
	Permitted(ctx context.Context, identity authn.Identity, tenant, path string) (bool, error)
}

type Options struct {
	Keys       Keys
	Subjects   []Subject
	Authorizer Authorizer
	Audit      audit.Sink
	Guard      httpx.Middleware
	Logger     *slog.Logger
}

type Module struct {
	keys       Keys
	subjects   []Subject
	authorizer Authorizer
	audit      audit.Sink
	guard      httpx.Middleware
	logger     *slog.Logger
	running    sync.Mutex
	busy       bool
}

func NewModule(opts Options) (*Module, error) {
	switch {
	case opts.Keys == nil:
		return nil, ErrNoKeys
	case opts.Authorizer == nil:
		return nil, ErrNoAuthorizer
	case opts.Guard == nil:
		return nil, ErrNoGuard
	case len(opts.Subjects) == 0:
		return nil, ErrNoSubjects
	}

	return &Module{
		keys:       opts.Keys,
		subjects:   opts.Subjects,
		authorizer: opts.Authorizer,
		audit:      opts.Audit,
		guard:      opts.Guard,
		logger:     opts.Logger,
	}, nil
}

func (m *Module) Name() string {
	return moduleName
}

type outcome struct {
	from     int
	to       int
	subjects []named
}

type named struct {
	name     string
	progress Progress
}

func (m *Module) rotate(ctx context.Context) (outcome, error) {
	if !m.claim() {
		return outcome{}, ErrInProgress
	}
	defer m.release()

	from, to, err := m.keys.Rotate(ctx)
	if err != nil {
		return outcome{}, err
	}

	result := outcome{from: from, to: to}
	for _, subject := range m.subjects {
		progress, err := subject.Rewrap(ctx)
		result.subjects = append(result.subjects, named{name: subject.Name(), progress: progress})
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func (m *Module) claim() bool {
	m.running.Lock()
	defer m.running.Unlock()

	if m.busy {
		return false
	}
	m.busy = true
	return true
}

func (m *Module) release() {
	m.running.Lock()
	defer m.running.Unlock()
	m.busy = false
}
