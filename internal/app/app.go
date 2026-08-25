package app

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/modules/auth"
	"github.com/marstack-labs/marstack-secrets/internal/modules/health"
	"github.com/marstack-labs/marstack-secrets/internal/modules/lease"
	"github.com/marstack-labs/marstack-secrets/internal/modules/observe"
	"github.com/marstack-labs/marstack-secrets/internal/modules/param"
	"github.com/marstack-labs/marstack-secrets/internal/modules/policy"
	"github.com/marstack-labs/marstack-secrets/internal/modules/seal"
	"github.com/marstack-labs/marstack-secrets/internal/modules/secret"
	"github.com/marstack-labs/marstack-secrets/internal/platform/audit"
	"github.com/marstack-labs/marstack-secrets/internal/platform/config"
	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
	"github.com/marstack-labs/marstack-secrets/internal/platform/jwt"
	"github.com/marstack-labs/marstack-secrets/internal/platform/ratelimit"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

const DatabaseFile = "marsec.db"

type Module interface {
	Name() string
	Register(mux *http.ServeMux)
}

type SealTolerant interface {
	PathsAllowedWhileSealed() []string
}

type App struct {
	cfg     config.Config
	logger  *slog.Logger
	db      *sql.DB
	seal    *seal.Manager
	leases  *lease.Manager
	audit   *audit.Log
	metrics *telemetry
	modules []Module
}

type sealingSink struct {
	sink   audit.Sink
	seal   *seal.Manager
	logger *slog.Logger
}

func (s sealingSink) Append(ctx context.Context, event audit.Event) error {
	err := s.sink.Append(ctx, event)
	if err == nil {
		return nil
	}

	if s.seal.IsUnsealed() {
		s.logger.Error("the audit sink failed; sealing the store", "error", err)
		s.seal.Seal()
	}
	return err
}

type secretReader struct {
	service *secret.Service
}

func (s secretReader) Reveal(ctx context.Context, tenant, path string) (crypto.Sensitive, int, error) {
	value, err := s.service.Get(ctx, tenant, path, 0)
	if err != nil {
		return nil, 0, err
	}
	return value.Data, value.Version, nil
}

type leaseIssuer struct {
	manager *lease.Manager
}

func (l leaseIssuer) Issue(ctx context.Context, tenant, identityID, path string, version int, ttl time.Duration) (string, time.Time, error) {
	held, err := l.manager.Issue(ctx, tenant, identityID, path, version, ttl)
	if err != nil {
		return "", time.Time{}, err
	}
	return held.ID, held.ExpiresAt, nil
}

func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error) {
	db, err := sqlite.Open(ctx, filepath.Join(cfg.DataDir, DatabaseFile))
	if err != nil {
		return nil, err
	}

	trail, err := audit.Open(cfg.AuditPath(), audit.Options{})
	if err != nil {
		return nil, errors.Join(err, db.Close())
	}

	app, err := assemble(ctx, cfg, logger, db, trail)
	if err != nil {
		return nil, errors.Join(err, trail.Close(), db.Close())
	}
	return app, nil
}

func assemble(ctx context.Context, cfg config.Config, logger *slog.Logger, db *sql.DB, trail *audit.Log) (*App, error) {
	sealManager, err := seal.NewManager(db, seal.Options{})
	if err != nil {
		return nil, err
	}
	if err := sealManager.Migrate(ctx); err != nil {
		return nil, err
	}

	authManager, err := auth.NewManager(db, auth.Options{})
	if err != nil {
		return nil, err
	}
	if err := authManager.Migrate(ctx); err != nil {
		return nil, err
	}

	policyManager, err := policy.NewManager(db, policy.Options{})
	if err != nil {
		return nil, err
	}
	if err := policyManager.Migrate(ctx); err != nil {
		return nil, err
	}

	store, err := secret.NewStore(db, secret.Options{})
	if err != nil {
		return nil, err
	}
	secretService, err := secret.NewService(store, sealManager.Cipher())
	if err != nil {
		return nil, err
	}
	if err := secretService.Migrate(ctx); err != nil {
		return nil, err
	}

	paramStore, err := param.NewStore(db, sealManager.Cipher(), param.Options{})
	if err != nil {
		return nil, err
	}
	if err := paramStore.Migrate(ctx); err != nil {
		return nil, err
	}
	paramService, err := param.NewService(paramStore, policyManager, secretReader{service: secretService})
	if err != nil {
		return nil, err
	}

	assertions, err := instanceVerifier(cfg)
	if err != nil {
		return nil, err
	}
	if assertions == nil {
		logger.Warn("instance logins are disabled; set MARSEC_CONTROL_PLANE_ISSUER and MARSEC_CONTROL_PLANE_JWKS_FILE to accept them")
	}

	limits, err := rateLimits(cfg)
	if err != nil {
		return nil, err
	}

	leaseManager, err := lease.NewManager(db, authManager, lease.Options{})
	if err != nil {
		return nil, err
	}
	if err := leaseManager.Migrate(ctx); err != nil {
		return nil, err
	}

	instrument := newTelemetry(sealManager, leaseManager, trail)
	sink := instrument.sink(sealingSink{sink: trail, seal: sealManager, logger: logger})

	authModule := auth.NewModule(authManager, logger, assertions, limits, auth.Recording{Sink: sink})
	guard := authModule.Require

	return &App{
		cfg:     cfg,
		logger:  logger,
		db:      db,
		seal:    sealManager,
		leases:  leaseManager,
		audit:   trail,
		metrics: instrument,
		modules: []Module{
			health.New(),
			observe.NewModule(instrument.registry),
			seal.NewModule(sealManager, logger, sink),
			authModule,
			policy.NewModule(policyManager, guard, logger),
			lease.NewModule(leaseManager, lease.ModuleOptions{
				Authorizer: policyManager,
				Guard:      guard,
				Logger:     logger,
			}),
			param.NewModule(paramService, param.ModuleOptions{
				Authorizer: policyManager,
				Audit:      sink,
				Guard:      guard,
				Logger:     logger,
			}),
			secret.NewModule(secretService, secret.ModuleOptions{
				Authorizer: policyManager,
				Leases:     leaseIssuer{manager: leaseManager},
				Audit:      sink,
				LeaseTTL:   cfg.LeaseTTL,
				Guard:      guard,
				Logger:     logger,
			}),
		},
	}, nil
}

func (a *App) Close() error {
	a.seal.Seal()
	return errors.Join(a.audit.Close(), a.db.Close())
}

func (a *App) ModuleNames() []string {
	names := make([]string, 0, len(a.modules))
	for _, module := range a.modules {
		names = append(names, module.Name())
	}
	return names
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.Problem(w, http.StatusNotFound, "not_found")
	})
	allowedWhileSealed := make(map[string]struct{})

	for _, module := range a.modules {
		module.Register(mux)
		for _, path := range pathsAllowedWhileSealed(module) {
			allowedWhileSealed[path] = struct{}{}
		}
		a.logger.Debug("module registered", "module", module.Name())
	}

	return httpx.Chain(mux,
		httpx.Recover(a.logger),
		httpx.RequestID,
		httpx.SecurityHeaders,
		httpx.AccessLog(a.logger),
		a.metrics.middleware(),
		requireUnsealed(a.seal.IsUnsealed, allowedWhileSealed),
	)
}

func (a *App) Run(ctx context.Context) error {
	if a.cfg.AllowInsecureHTTP {
		a.logger.Warn("serving plaintext HTTP; this is for local development only")
	}
	a.logger.Info("server starting sealed", "modules", a.ModuleNames())

	sweeping, stopSweeping := context.WithCancel(ctx)
	defer stopSweeping()
	go a.sweep(sweeping)

	return httpx.Serve(ctx, httpx.ServerConfig{
		Addr:              a.cfg.ListenAddr,
		TLSCertFile:       a.cfg.TLSCertFile,
		TLSKeyFile:        a.cfg.TLSKeyFile,
		AllowInsecureHTTP: a.cfg.AllowInsecureHTTP,
		ShutdownTimeout:   a.cfg.ShutdownTimeout,
	}, a.Handler(), a.logger)
}

func (a *App) sweep(ctx context.Context) {
	for {
		wait := a.cfg.SweepInterval/2 + time.Duration(rand.Int64N(int64(a.cfg.SweepInterval)))

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		removed, err := a.leases.Sweep(ctx, a.cfg.SweepBatch)
		switch {
		case errors.Is(err, context.Canceled):
			return
		case err != nil:
			a.logger.Error("sweeping expired leases", "error", err)
		case removed > 0:
			a.logger.Info("swept expired leases", "removed", removed)
		}
	}
}

func rateLimits(cfg config.Config) (auth.Limits, error) {
	logins, err := ratelimit.New(ratelimit.Options{
		PerMinute: cfg.LoginRatePerMinute,
		Burst:     cfg.LoginBurst,
	})
	if err != nil {
		return auth.Limits{}, err
	}

	requests, err := ratelimit.New(ratelimit.Options{
		PerMinute: cfg.RequestRatePerMinute,
		Burst:     cfg.RequestBurst,
	})
	if err != nil {
		return auth.Limits{}, err
	}

	return auth.Limits{Logins: logins, Requests: requests}, nil
}

func instanceVerifier(cfg config.Config) (auth.Assertions, error) {
	if !cfg.InstanceLoginConfigured() {
		return nil, nil
	}

	raw, err := os.ReadFile(cfg.ControlPlaneJWKSFile)
	if err != nil {
		return nil, err
	}
	keys, err := jwt.ParseJWKS(raw)
	if err != nil {
		return nil, err
	}

	return jwt.NewVerifier(jwt.Options{
		Keys:     keys,
		Issuer:   cfg.ControlPlaneIssuer,
		Audience: cfg.ControlPlaneAudience,
		Skew:     cfg.ControlPlaneSkew,
	})
}

func requireUnsealed(unsealed func() bool, allowed map[string]struct{}) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, permitted := allowed[r.URL.Path]; permitted || unsealed() {
				next.ServeHTTP(w, r)
				return
			}
			httpx.Problem(w, http.StatusServiceUnavailable, "sealed")
		})
	}
}

func pathsAllowedWhileSealed(module Module) []string {
	tolerant, ok := module.(SealTolerant)
	if !ok {
		return nil
	}
	return tolerant.PathsAllowedWhileSealed()
}
