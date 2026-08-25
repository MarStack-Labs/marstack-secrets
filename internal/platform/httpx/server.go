package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

type ServerConfig struct {
	Addr              string
	TLSCertFile       string
	TLSKeyFile        string
	AllowInsecureHTTP bool
	ShutdownTimeout   time.Duration
}

func Serve(ctx context.Context, cfg ServerConfig, handler http.Handler, logger *slog.Logger) error {
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	listenErr := make(chan error, 1)
	go func() {
		var err error
		if cfg.AllowInsecureHTTP {
			err = server.ListenAndServe()
		} else {
			err = server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		listenErr <- err
	}()

	logger.Info("server listening", "addr", cfg.Addr, "tls", !cfg.AllowInsecureHTTP)

	select {
	case err := <-listenErr:
		return err
	case <-ctx.Done():
		logger.Info("shutdown requested")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-listenErr
	}
}
