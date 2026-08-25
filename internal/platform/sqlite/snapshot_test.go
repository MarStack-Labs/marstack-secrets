package sqlite

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotVerifiesWhatItWrote(t *testing.T) {
	db, _ := openTestDB(t)
	if err := Migrate(t.Context(), db, "secret", []Migration{
		{Name: "0001_create", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY, value TEXT)`},
	}); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	if _, err := db.ExecContext(t.Context(),
		`INSERT INTO secrets (value) VALUES ('a recognisable ciphertext stand-in')`); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	path := filepath.Join(t.TempDir(), "backup", "marsec.snap")
	report, err := Snapshot(t.Context(), db, path)
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	if report.Migrations != 1 {
		t.Errorf("Migrations = %d, want 1", report.Migrations)
	}
	if report.Bytes == 0 {
		t.Error("the snapshot reports no size")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != filePerm {
		t.Errorf("the snapshot is %o, want %o", perm, filePerm)
	}
}

func TestSnapshotRefusesToOverwrite(t *testing.T) {
	db, _ := openTestDB(t)
	if err := Migrate(t.Context(), db, "secret", []Migration{
		{Name: "0001", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY)`},
	}); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}

	path := filepath.Join(t.TempDir(), "marsec.snap")
	if _, err := Snapshot(t.Context(), db, path); err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	if _, err := Snapshot(t.Context(), db, path); !errors.Is(err, ErrSnapshotExists) {
		t.Fatalf("a second Snapshot = %v, want ErrSnapshotExists", err)
	}
}

func TestSnapshotRefusesAQuotedPath(t *testing.T) {
	db, _ := openTestDB(t)

	if _, err := Snapshot(t.Context(), db, filepath.Join(t.TempDir(), "it's.snap")); !errors.Is(err, ErrSnapshotQuoted) {
		t.Fatalf("Snapshot = %v, want ErrSnapshotQuoted", err)
	}
}

func TestVerifyRefusesRubbish(t *testing.T) {
	directory := t.TempDir()

	empty := filepath.Join(directory, "empty.snap")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	garbage := filepath.Join(directory, "garbage.snap")
	if err := os.WriteFile(garbage, []byte(strings.Repeat("not a database", 100)), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	for name, path := range map[string]string{
		"an empty file":  empty,
		"random bytes":   garbage,
		"a missing file": filepath.Join(directory, "absent.snap"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(t.Context(), path); err == nil {
				t.Fatal("Verify accepted it")
			}
		})
	}

	if _, err := Verify(t.Context(), ""); !errors.Is(err, ErrEmptyPath) {
		t.Errorf("Verify with no path = %v, want ErrEmptyPath", err)
	}
}

func TestVerifyRefusesADatabaseWithNoMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bare.db")
	bare, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if _, err := bare.ExecContext(t.Context(), `CREATE TABLE unrelated (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("creating a table: %v", err)
	}
	if err := bare.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if _, err := Verify(t.Context(), path); !errors.Is(err, ErrSnapshotEmpty) {
		t.Fatalf("Verify = %v, want ErrSnapshotEmpty", err)
	}
}

func TestRestoreBringsTheDataBack(t *testing.T) {
	db, _ := openTestDB(t)
	if err := Migrate(t.Context(), db, "secret", []Migration{
		{Name: "0001", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY, value TEXT)`},
	}); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO secrets (value) VALUES ('kept')`); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	directory := t.TempDir()
	snapshot := filepath.Join(directory, "marsec.snap")
	if _, err := Snapshot(t.Context(), db, snapshot); err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}

	target := filepath.Join(directory, "restored", "marsec.db")
	report, err := Restore(t.Context(), snapshot, target)
	if err != nil {
		t.Fatalf("Restore returned error: %v", err)
	}
	if report.Path != target || report.Migrations != 1 {
		t.Errorf("report = %+v", report)
	}

	reopened, err := Open(t.Context(), target)
	if err != nil {
		t.Fatalf("opening the restored database: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	var value string
	if err := reopened.QueryRowContext(t.Context(), `SELECT value FROM secrets`).Scan(&value); err != nil {
		t.Fatalf("reading the restored row: %v", err)
	}
	if value != "kept" {
		t.Errorf("the restored value is %q", value)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != filePerm {
		t.Errorf("the restored database is %o, want %o", perm, filePerm)
	}
}

func TestRestoreRefusesToClobber(t *testing.T) {
	db, _ := openTestDB(t)
	if err := Migrate(t.Context(), db, "secret", []Migration{
		{Name: "0001", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY)`},
	}); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}

	directory := t.TempDir()
	snapshot := filepath.Join(directory, "marsec.snap")
	if _, err := Snapshot(t.Context(), db, snapshot); err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}

	target := filepath.Join(directory, "existing.db")
	if err := os.WriteFile(target, []byte("something already here"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if _, err := Restore(t.Context(), snapshot, target); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("Restore = %v, want ErrTargetExists", err)
	}

	remaining, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading the target: %v", err)
	}
	if string(remaining) != "something already here" {
		t.Error("the refused restore overwrote the target anyway")
	}
}

func TestRestoreRefusesAnUnverifiableSnapshot(t *testing.T) {
	directory := t.TempDir()
	rubbish := filepath.Join(directory, "rubbish.snap")
	if err := os.WriteFile(rubbish, []byte("not a database at all"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	target := filepath.Join(directory, "restored.db")
	if _, err := Restore(t.Context(), rubbish, target); err == nil {
		t.Fatal("Restore accepted an unverifiable snapshot")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused restore left a target behind")
	}
}
