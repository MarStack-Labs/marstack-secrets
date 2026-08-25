package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/marstack-labs/marstack-secrets/internal/agent"
	"github.com/marstack-labs/marstack-secrets/internal/platform/logging"
)

func runAgent(out io.Writer, args []string) error {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	flags.SetOutput(out)
	configFile := flags.String("config", "/etc/marstack-secrets/agent.json", "agent configuration")
	logLevel := flags.String("log-level", "info", "debug, info, warn or error")
	once := flags.Bool("once", false, "render once and exit, rather than staying resident")
	if err := flags.Parse(args); err != nil {
		return err
	}

	config, err := agent.Load(*configFile)
	if err != nil {
		return err
	}

	logger := logging.New(*logLevel, os.Stderr)
	running, err := agent.New(config, agent.Options{Logger: logger})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := running.Cycle(ctx); err != nil {
			return err
		}
		fmt.Fprintln(out, "rendered")
		return nil
	}

	if err := running.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
