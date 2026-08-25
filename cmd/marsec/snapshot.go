package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/marstack-labs/marstack-secrets/internal/app"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

func runSnapshot(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		operatorUsage()
		return errors.New("missing snapshot subcommand")
	}

	switch args[0] {
	case "save":
		return runSnapshotSave(ctx, out, args[1:])
	case "verify":
		return runSnapshotVerify(ctx, out, args[1:])
	case "restore":
		return runSnapshotRestore(ctx, out, args[1:])
	default:
		operatorUsage()
		return fmt.Errorf("unknown snapshot subcommand %q", args[0])
	}
}

func runSnapshotSave(ctx context.Context, out io.Writer, args []string) error {
	target, rest, err := positional(args, "marsec operator snapshot save <path>")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("snapshot save", flag.ContinueOnError)
	flags.SetOutput(out)
	dataDir := flags.String("data-dir", "", "override the data directory")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	directory := *dataDir
	if directory == "" {
		directory = resolveDataDir()
	}

	db, err := sqlite.Open(ctx, filepath.Join(directory, app.DatabaseFile))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	report, err := sqlite.Snapshot(ctx, db, target)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "saved %s: %d bytes, %d migration(s)\n", report.Path, report.Bytes, report.Migrations)
	return nil
}

func runSnapshotVerify(ctx context.Context, out io.Writer, args []string) error {
	target, rest, err := positional(args, "marsec operator snapshot verify <path>")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("snapshot verify", flag.ContinueOnError)
	flags.SetOutput(out)
	if err := flags.Parse(rest); err != nil {
		return err
	}

	report, err := sqlite.Verify(ctx, target)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s verifies: %d bytes, %d migration(s)\n", report.Path, report.Bytes, report.Migrations)
	return nil
}

func runSnapshotRestore(ctx context.Context, out io.Writer, args []string) error {
	source, rest, err := positional(args, "marsec operator snapshot restore <path> --data-dir <dir>")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("snapshot restore", flag.ContinueOnError)
	flags.SetOutput(out)
	dataDir := flags.String("data-dir", "", "data directory to restore into")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	directory := *dataDir
	if directory == "" {
		directory = resolveDataDir()
	}

	report, err := sqlite.Restore(ctx, source, filepath.Join(directory, app.DatabaseFile))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "restored %s: %d migration(s)\n", report.Path, report.Migrations)
	fmt.Fprintln(out, "the store is sealed; unseal it with a quorum of shares")
	return nil
}
