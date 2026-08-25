package app

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/marstack-labs/marstack-secrets/internal/modules/health"
	"github.com/marstack-labs/marstack-secrets/internal/platform/config"
	"github.com/marstack-labs/marstack-secrets/internal/platform/httpx"
)

type Module interface {
	Name() string
	Register(mux *http.ServeMux)
}

type App struct {
	cfg     config.Config
	logger  *slog.Logger
	modules []Module
}

func New(cfg config.Config, logger *slog.Logger) *App {
	return &App{
		cfg:    cfg,
		logger: logger,
		modules: []Module{
			health.New(),
		},
	}
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
	for _, module := range a.modules {
		module.Register(mux)
		a.logger.Debug("module registered", "module", module.Name())
	}
	return httpx.Chain(mux,
		httpx.Recover(a.logger),
		httpx.RequestID,
		httpx.SecurityHeaders,
		httpx.AccessLog(a.logger),
	)
}

func (a *App) Run(ctx context.Context) error {
	if a.cfg.AllowInsecureHTTP {
		a.logger.Warn("serving plaintext HTTP; this is for local development only")
	}
	return httpx.Serve(ctx, httpx.ServerConfig{
		Addr:              a.cfg.ListenAddr,
		TLSCertFile:       a.cfg.TLSCertFile,
		TLSKeyFile:        a.cfg.TLSKeyFile,
		AllowInsecureHTTP: a.cfg.AllowInsecureHTTP,
		ShutdownTimeout:   a.cfg.ShutdownTimeout,
	}, a.Handler(), a.logger)
}
