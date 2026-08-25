package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/marstack-labs/marstack-secrets/internal/app"
	"github.com/marstack-labs/marstack-secrets/internal/modules/policy"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

func runPolicy(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		operatorUsage()
		return errors.New("missing policy subcommand")
	}

	switch args[0] {
	case "put":
		return runPolicyPut(ctx, out, args[1:])
	case "list":
		return runPolicyList(ctx, out, args[1:])
	case "delete":
		return runPolicyDelete(ctx, out, args[1:])
	case "bind":
		return runPolicyBinding(ctx, out, args[1:], true)
	case "unbind":
		return runPolicyBinding(ctx, out, args[1:], false)
	default:
		operatorUsage()
		return fmt.Errorf("unknown policy subcommand %q", args[0])
	}
}

func runPolicyPut(ctx context.Context, out io.Writer, args []string) error {
	name, rest, err := positional(args, "marsec operator policy put <name> --tenant <tenant> --rules <file>")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("policy put", flag.ContinueOnError)
	flags.SetOutput(out)
	tenant := flags.String("tenant", "", "tenant the policy belongs to")
	rulesFile := flags.String("rules", "", "file holding the rules as JSON")
	dataDir := flags.String("data-dir", "", "override the data directory")
	if err := flags.Parse(rest); err != nil {
		return err
	}
	if *rulesFile == "" {
		return errors.New("a --rules file is required")
	}

	raw, err := os.ReadFile(*rulesFile)
	if err != nil {
		return err
	}
	var rules []policy.Rule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return fmt.Errorf("reading %s: %w", *rulesFile, err)
	}

	definition, err := policy.New(name, rules)
	if err != nil {
		return err
	}

	return withPolicies(ctx, *dataDir, func(manager *policy.Manager) error {
		if err := manager.Put(ctx, *tenant, definition); err != nil {
			return err
		}
		fmt.Fprintf(out, "stored policy %s for tenant %s with %d rule(s)\n", name, *tenant, len(rules))
		return nil
	})
}

func runPolicyList(ctx context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("policy list", flag.ContinueOnError)
	flags.SetOutput(out)
	tenant := flags.String("tenant", "", "tenant to list")
	dataDir := flags.String("data-dir", "", "override the data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}

	return withPolicies(ctx, *dataDir, func(manager *policy.Manager) error {
		names, err := manager.List(ctx, *tenant)
		if err != nil {
			return err
		}
		for _, name := range names {
			fmt.Fprintln(out, name)
		}
		return nil
	})
}

func runPolicyDelete(ctx context.Context, out io.Writer, args []string) error {
	name, rest, err := positional(args, "marsec operator policy delete <name> --tenant <tenant>")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("policy delete", flag.ContinueOnError)
	flags.SetOutput(out)
	tenant := flags.String("tenant", "", "tenant the policy belongs to")
	dataDir := flags.String("data-dir", "", "override the data directory")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	return withPolicies(ctx, *dataDir, func(manager *policy.Manager) error {
		if err := manager.Delete(ctx, *tenant, name); err != nil {
			return err
		}
		fmt.Fprintf(out, "deleted policy %s and any bindings to it\n", name)
		return nil
	})
}

func runPolicyBinding(ctx context.Context, out io.Writer, args []string, bind bool) error {
	action := "unbind"
	if bind {
		action = "bind"
	}

	identity, rest, err := positional(args,
		"marsec operator policy "+action+" <identity> --tenant <tenant> --policy <name>")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("policy "+action, flag.ContinueOnError)
	flags.SetOutput(out)
	tenant := flags.String("tenant", "", "tenant the binding belongs to")
	name := flags.String("policy", "", "policy to bind")
	dataDir := flags.String("data-dir", "", "override the data directory")
	if err := flags.Parse(rest); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("a --policy name is required")
	}

	return withPolicies(ctx, *dataDir, func(manager *policy.Manager) error {
		if bind {
			if err := manager.Bind(ctx, *tenant, identity, *name); err != nil {
				return err
			}
			fmt.Fprintf(out, "bound %s to %s\n", *name, identity)
			return nil
		}
		if err := manager.Unbind(ctx, *tenant, identity, *name); err != nil {
			return err
		}
		fmt.Fprintf(out, "unbound %s from %s\n", *name, identity)
		return nil
	})
}

func withPolicies(ctx context.Context, dataDir string, run func(*policy.Manager) error) error {
	if dataDir == "" {
		dataDir = resolveDataDir()
	}

	db, err := sqlite.Open(ctx, filepath.Join(dataDir, app.DatabaseFile))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	manager, err := policy.NewManager(db, policy.Options{})
	if err != nil {
		return err
	}
	if err := manager.Migrate(ctx); err != nil {
		return err
	}
	return run(manager)
}
