package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/app"
	"github.com/marstack-labs/marstack-secrets/internal/modules/auth"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/config"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

func runOperator(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		operatorUsage()
		return errors.New("missing operator subcommand")
	}

	switch args[0] {
	case "identity":
		return runIdentity(ctx, out, args[1:])
	case "bootstrap":
		return runBootstrap(ctx, out, args[1:])
	default:
		operatorUsage()
		return fmt.Errorf("unknown operator subcommand %q", args[0])
	}
}

func runIdentity(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		operatorUsage()
		return errors.New("missing identity subcommand")
	}

	switch args[0] {
	case "add":
		return runIdentityAdd(ctx, out, args[1:])
	case "disable":
		return runIdentityDisable(ctx, out, args[1:])
	default:
		operatorUsage()
		return fmt.Errorf("unknown identity subcommand %q", args[0])
	}
}

func runIdentityAdd(ctx context.Context, out io.Writer, args []string) error {
	id, rest, err := positional(args, "marsec operator identity add <id> --tenant <tenant> [--kind <kind>]")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("identity add", flag.ContinueOnError)
	flags.SetOutput(out)
	kind := flags.String("kind", string(authn.KindBootstrap), "identity kind: bootstrap, instance, oidc or service")
	tenant := flags.String("tenant", "", "tenant the identity belongs to")
	dataDir := flags.String("data-dir", "", "override the data directory")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	return withDatabase(ctx, *dataDir, func(manager *auth.Manager) error {
		identity, err := manager.RegisterIdentity(ctx, id, authn.Kind(*kind), *tenant)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "registered %s (kind %s, tenant %s)\n", identity.ID, identity.Kind, identity.Tenant)
		return nil
	})
}

func runIdentityDisable(ctx context.Context, out io.Writer, args []string) error {
	id, rest, err := positional(args, "marsec operator identity disable <id>")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("identity disable", flag.ContinueOnError)
	flags.SetOutput(out)
	dataDir := flags.String("data-dir", "", "override the data directory")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	return withDatabase(ctx, *dataDir, func(manager *auth.Manager) error {
		if err := manager.DisableIdentity(ctx, id); err != nil {
			return err
		}
		revoked, err := manager.RevokeIdentity(ctx, id)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "disabled %s and revoked %d token(s)\n", id, revoked)
		return nil
	})
}

func runBootstrap(ctx context.Context, out io.Writer, args []string) error {
	id, rest, err := positional(args, "marsec operator bootstrap <identity-id> [--ttl 5m]")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flags.SetOutput(out)
	ttl := flags.Duration("ttl", auth.BootstrapTTL, "how long the bootstrap token stays usable")
	dataDir := flags.String("data-dir", "", "override the data directory")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	return withDatabase(ctx, *dataDir, func(manager *auth.Manager) error {
		token, err := manager.IssueBootstrap(ctx, id, *ttl)
		if err != nil {
			return err
		}
		defer token.Value.Zero()

		fmt.Fprintf(out, "%s\n", string(token.Value))
		fmt.Fprintf(os.Stderr, "single use, expires %s; it is not stored and cannot be shown again\n",
			token.ExpiresAt.UTC().Format(time.RFC3339))
		return nil
	})
}

func positional(args []string, usage string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, fmt.Errorf("usage: %s", usage)
	}
	return args[0], args[1:], nil
}

func withDatabase(ctx context.Context, dataDir string, run func(*auth.Manager) error) error {
	if dataDir == "" {
		dataDir = resolveDataDir()
	}

	db, err := sqlite.Open(ctx, filepath.Join(dataDir, app.DatabaseFile))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	manager, err := auth.NewManager(db, auth.Options{})
	if err != nil {
		return err
	}
	if err := manager.Migrate(ctx); err != nil {
		return err
	}
	return run(manager)
}

func resolveDataDir() string {
	if fromEnv := os.Getenv("MARSEC_DATA_DIR"); fromEnv != "" {
		return fromEnv
	}
	return config.Default().DataDir
}

func operatorUsage() {
	fmt.Fprint(os.Stderr, `marsec operator - local administration, run on the server host

Usage:
  marsec operator identity add <id> --tenant <tenant> [--kind <kind>]
  marsec operator identity disable <id>
  marsec operator bootstrap <identity-id> [--ttl 5m]

These commands write to the database directly and need filesystem access to the
data directory. They do not need the store to be unsealed. The data directory
comes from MARSEC_DATA_DIR unless --data-dir is given.
`)
}
