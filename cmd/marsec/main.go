package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/marstack-labs/marstack-secrets/internal/app"
	"github.com/marstack-labs/marstack-secrets/internal/platform/config"
	"github.com/marstack-labs/marstack-secrets/internal/platform/hardening"
	"github.com/marstack-labs/marstack-secrets/internal/platform/logging"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("missing command")
	}

	switch args[0] {
	case "server":
		return serve()
	case "operator":
		return runOperator(context.Background(), os.Stdout, args[1:])
	case "version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	logger := logging.New(cfg.LogLevel, os.Stdout)

	if err := protect(logger, cfg.AllowUnprotectedMemory); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	application, err := app.New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := application.Close(); err != nil {
			logger.Error("closing the application", "error", err)
		}
	}()

	return application.Run(ctx)
}

func protect(logger *slog.Logger, allowUnprotected bool) error {
	report, err := hardening.Apply()
	if err == nil {
		logger.Info("process protections applied", "hardening", report)
		return nil
	}
	if allowUnprotected {
		logger.Warn("running without full process protections; key material may reach swap or a core dump",
			"hardening", report, "error", err)
		return nil
	}
	return fmt.Errorf("%w\nset MARSEC_ALLOW_UNPROTECTED_MEMORY=true to run anyway, for local development only", err)
}

func usage() {
	fmt.Fprint(os.Stderr, `marsec - MarStack secret and parameter store

Usage:
  marsec server     start the server
  marsec operator   local administration; see marsec operator
  marsec version    print the binary version
  marsec help       show this message

The server is configured through MARSEC_* environment variables.
See docs/CONFIGURATION.md for the full list.
`)
}
