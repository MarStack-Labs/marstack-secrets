package sqlite

import (
	"database/sql"
	"errors"
	"testing"
)

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var found string
	err := db.QueryRowContext(t.Context(),
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		t.Fatalf("looking up table %s: %v", name, err)
	}
	return true
}

func appliedCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("counting applied migrations: %v", err)
	}
	return count
}

func TestMigrateAppliesInOrder(t *testing.T) {
	db, _ := openTestDB(t)
	migrations := []Migration{
		{Name: "0001_create", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY)`},
		{Name: "0002_add_column", SQL: `ALTER TABLE secrets ADD COLUMN tenant TEXT`},
	}

	if err := Migrate(t.Context(), db, "secret", migrations); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	if !tableExists(t, db, "secrets") {
		t.Fatal("the table was not created")
	}
	if got := appliedCount(t, db); got != 2 {
		t.Errorf("applied migrations = %d, want 2", got)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	db, _ := openTestDB(t)
	migrations := []Migration{
		{Name: "0001_create", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY)`},
	}

	for range 3 {
		if err := Migrate(t.Context(), db, "secret", migrations); err != nil {
			t.Fatalf("Migrate returned error: %v", err)
		}
	}
	if got := appliedCount(t, db); got != 1 {
		t.Errorf("applied migrations = %d, want 1", got)
	}
}

func TestMigrateDetectsAnEditedMigration(t *testing.T) {
	db, _ := openTestDB(t)

	if err := Migrate(t.Context(), db, "secret", []Migration{
		{Name: "0001_create", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY)`},
	}); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}

	err := Migrate(t.Context(), db, "secret", []Migration{
		{Name: "0001_create", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY, tenant TEXT)`},
	})
	if !errors.Is(err, ErrMigrationChanged) {
		t.Fatalf("Migrate = %v, want ErrMigrationChanged", err)
	}
}

func TestMigrateRollsBackAFailedMigration(t *testing.T) {
	db, _ := openTestDB(t)

	err := Migrate(t.Context(), db, "secret", []Migration{
		{Name: "0001_create", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY); CREATE TABLE nonsense (`},
	})
	if err == nil {
		t.Fatal("expected the malformed migration to fail")
	}
	if tableExists(t, db, "secrets") {
		t.Error("the first statement was committed even though the migration failed")
	}
	if got := appliedCount(t, db); got != 0 {
		t.Errorf("applied migrations = %d, want 0", got)
	}
}

func TestMigrateAppliesMultipleStatements(t *testing.T) {
	db, _ := openTestDB(t)

	err := Migrate(t.Context(), db, "secret", []Migration{{
		Name: "0001_create",
		SQL: `
			CREATE TABLE secrets (id INTEGER PRIMARY KEY);
			CREATE TABLE parameters (id INTEGER PRIMARY KEY);
		`,
	}})
	if err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	for _, name := range []string{"secrets", "parameters"} {
		if !tableExists(t, db, name) {
			t.Errorf("table %s was not created", name)
		}
	}
}

func TestMigrateKeepsModulesIndependent(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := t.Context()

	if err := Migrate(ctx, db, "secret", []Migration{
		{Name: "0001_create", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY)`},
	}); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	if err := Migrate(ctx, db, "parameter", []Migration{
		{Name: "0001_create", SQL: `CREATE TABLE parameters (id INTEGER PRIMARY KEY)`},
	}); err != nil {
		t.Fatalf("Migrate for a second module returned error: %v", err)
	}

	if got := appliedCount(t, db); got != 2 {
		t.Errorf("applied migrations = %d, want 2", got)
	}
	for _, name := range []string{"secrets", "parameters"} {
		if !tableExists(t, db, name) {
			t.Errorf("table %s was not created", name)
		}
	}
}

func TestMigrateRejectsInvalidInput(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := t.Context()

	cases := map[string]struct {
		module     string
		migrations []Migration
		want       error
	}{
		"empty module": {
			module:     "",
			migrations: []Migration{{Name: "0001", SQL: `SELECT 1`}},
			want:       ErrEmptyModule,
		},
		"empty name": {
			module:     "secret",
			migrations: []Migration{{Name: "", SQL: `SELECT 1`}},
			want:       ErrEmptyMigrationName,
		},
		"duplicate name": {
			module: "secret",
			migrations: []Migration{
				{Name: "0001", SQL: `SELECT 1`},
				{Name: "0001", SQL: `SELECT 2`},
			},
			want: ErrDuplicateMigration,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Migrate(ctx, db, tc.module, tc.migrations); !errors.Is(err, tc.want) {
				t.Fatalf("Migrate = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMigrateSurvivesReopening(t *testing.T) {
	db, path := openTestDB(t)
	migrations := []Migration{
		{Name: "0001_create", SQL: `CREATE TABLE secrets (id INTEGER PRIMARY KEY)`},
	}

	if err := Migrate(t.Context(), db, "secret", migrations); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	reopened, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("reopening returned error: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if err := Migrate(t.Context(), reopened, "secret", migrations); err != nil {
		t.Fatalf("Migrate after reopening returned error: %v", err)
	}
	if got := appliedCount(t, reopened); got != 1 {
		t.Errorf("applied migrations = %d, want 1", got)
	}
}
