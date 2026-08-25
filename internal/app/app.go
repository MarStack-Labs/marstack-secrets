package app

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/marstack-labs/marstack-secrets/internal/modules/auth"
	"github.com/marstack-labs/marstack-secrets/internal/modules/health"
	"github.com/marstack-labs/marstack-secrets/internal/modules/policy"
	"github.com/marstack-labs/marstack-secrets/internal/modules/seal"
	"github.com/marstack-labs/marstack-secrets/internal/modules/secret"
	"github.com/marstack-labs/marstack-secrets/internal/platform/config"
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
	modules []Module
}

func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error) {
	db, err := sqlite.Open(ctx, filepath.Join(cfg.DataDir, DatabaseFile))
	if err != nil {
		return nil, err
	}

	app, err := assemble(ctx, cfg, logger, db)
	if err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return app, nil
}

func assemble(ctx context.Context, cfg config.Config, logger *slog.Logger, db *sql.DB) (*App, error) {
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

	authModule := auth.NewModule(authManager, logger, assertions, limits)
	guard := authModule.Require

	return &App{
		cfg:    cfg,
		logger: logger,
		db:     db,
		seal:   sealManager,
		modules: []Module{
			health.New(),
			seal.NewModule(sealManager, logger),
			authModule,
			policy.NewModule(policyManager, guard, logger),
			secret.NewModule(secretService, policyManager, guard, logger),
		},
	}, nil
}

func (a *App) Close() error {
	a.seal.Seal()
	return a.db.Close()
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
		requireUnsealed(a.seal.IsUnsealed, allowedWhileSealed),
	)
}

func (a *App) Run(ctx context.Context) error {
	if a.cfg.AllowInsecureHTTP {
		a.logger.Warn("serving plaintext HTTP; this is for local development only")
	}
	a.logger.Info("server starting sealed", "modules", a.ModuleNames())

	return httpx.Serve(ctx, httpx.ServerConfig{
		Addr:              a.cfg.ListenAddr,
		TLSCertFile:       a.cfg.TLSCertFile,
		TLSKeyFile:        a.cfg.TLSKeyFile,
		AllowInsecureHTTP: a.cfg.AllowInsecureHTTP,
		ShutdownTimeout:   a.cfg.ShutdownTimeout,
	}, a.Handler(), a.logger)
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
