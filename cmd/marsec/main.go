package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/marstack-labs/marstack-secrets/internal/app"
	"github.com/marstack-labs/marstack-secrets/internal/platform/config"
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

func usage() {
	fmt.Fprint(os.Stderr, `marsec - MarStack secret and parameter store

Usage:
  marsec server     start the server
  marsec version    print the binary version
  marsec help       show this message

The server is configured through MARSEC_* environment variables.
See docs/CONFIGURATION.md for the full list.
`)
}
