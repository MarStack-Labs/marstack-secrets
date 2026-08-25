package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/marstack-labs/marstack-secrets/internal/platform/audit"
)

func runAudit(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		operatorUsage()
		return errors.New("missing audit subcommand")
	}

	switch args[0] {
	case "verify":
		return runAuditVerify(ctx, out, args[1:])
	default:
		operatorUsage()
		return fmt.Errorf("unknown audit subcommand %q", args[0])
	}
}

func runAuditVerify(_ context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	flags.SetOutput(out)
	file := flags.String("file", "", "audit log to verify")
	dataDir := flags.String("data-dir", "", "override the data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}

	path := *file
	if path == "" {
		directory := *dataDir
		if directory == "" {
			directory = resolveDataDir()
		}
		path = filepath.Join(directory, "audit.log")
	}

	report, err := audit.Verify(path)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "%s verifies: %d record(s), tip %s\n", path, report.Records, report.LastHash)
	return nil
}
