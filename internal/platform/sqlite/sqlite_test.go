package sqlite

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data", "marsec.db")
	db, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func TestOpenAppliesDurabilityPragmas(t *testing.T) {
	db, _ := openTestDB(t)

	for pragma, want := range map[string]string{
		"journal_mode":  "wal",
		"synchronous":   "2",
		"foreign_keys":  "1",
		"secure_delete": "1",
		"busy_timeout":  "5000",
	} {
		var got string
		if err := db.QueryRowContext(t.Context(), "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatalf("reading pragma %s: %v", pragma, err)
		}
		if got != want {
			t.Errorf("pragma %s = %q, want %q", pragma, got, want)
		}
	}
}

func TestOpenRestrictsPermissions(t *testing.T) {
	_, path := openTestDB(t)

	file, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat on the database file: %v", err)
	}
	if perm := file.Mode().Perm(); perm != filePerm {
		t.Errorf("database file mode = %o, want %o", perm, filePerm)
	}

	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat on the data directory: %v", err)
	}
	if perm := dir.Mode().Perm(); perm != dirPerm {
		t.Errorf("data directory mode = %o, want %o", perm, dirPerm)
	}
}

func TestOpenCreatesMissingDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "c", "marsec.db")
	db, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file was not created: %v", err)
	}
}

func TestOpenRejectsAnEmptyPath(t *testing.T) {
	if _, err := Open(t.Context(), ""); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("Open = %v, want ErrEmptyPath", err)
	}
}

func TestOpenSurvivesReopening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marsec.db")

	first, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if _, err := first.ExecContext(t.Context(), `CREATE TABLE kept (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("creating a table: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	second, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("reopening returned error: %v", err)
	}
	defer func() { _ = second.Close() }()

	var name string
	err = second.QueryRowContext(t.Context(),
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'kept'`).Scan(&name)
	if err != nil {
		t.Fatalf("the table did not survive reopening: %v", err)
	}
}

func TestOpenSerialisesWrites(t *testing.T) {
	db, _ := openTestDB(t)
	if got := db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d, want 1", got)
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := t.Context()

	if _, err := db.ExecContext(ctx, `CREATE TABLE parent (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("creating parent: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))`); err != nil {
		t.Fatalf("creating child: %v", err)
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO child (parent_id) VALUES (404)`); err == nil {
		t.Fatal("expected the foreign key constraint to reject an orphan row")
	}
}
