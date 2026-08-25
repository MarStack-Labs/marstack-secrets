package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	ErrMigrationChanged   = errors.New("sqlite: an already applied migration has changed")
	ErrEmptyMigrationName = errors.New("sqlite: migration name must not be empty")
	ErrDuplicateMigration = errors.New("sqlite: duplicate migration name")
	ErrEmptyModule        = errors.New("sqlite: module must not be empty")
)

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	module     TEXT NOT NULL,
	name       TEXT NOT NULL,
	checksum   TEXT NOT NULL,
	applied_at TEXT NOT NULL,
	PRIMARY KEY (module, name)
)`

type Migration struct {
	Name string
	SQL  string
}

func Migrate(ctx context.Context, db *sql.DB, module string, migrations []Migration) error {
	if module == "" {
		return ErrEmptyModule
	}
	if err := validate(migrations); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, createMigrationsTable); err != nil {
		return err
	}
	for _, migration := range migrations {
		if err := apply(ctx, db, module, migration); err != nil {
			return fmt.Errorf("sqlite: migration %s/%s: %w", module, migration.Name, err)
		}
	}
	return nil
}

func validate(migrations []Migration) error {
	seen := make(map[string]struct{}, len(migrations))
	for _, migration := range migrations {
		if migration.Name == "" {
			return ErrEmptyMigrationName
		}
		if _, duplicate := seen[migration.Name]; duplicate {
			return fmt.Errorf("%w: %s", ErrDuplicateMigration, migration.Name)
		}
		seen[migration.Name] = struct{}{}
	}
	return nil
}

func apply(ctx context.Context, db *sql.DB, module string, migration Migration) error {
	sum := checksum(migration.SQL)

	var recorded string
	err := db.QueryRowContext(ctx,
		`SELECT checksum FROM schema_migrations WHERE module = ? AND name = ?`,
		module, migration.Name,
	).Scan(&recorded)

	switch {
	case err == nil && recorded == sum:
		return nil
	case err == nil:
		return ErrMigrationChanged
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (module, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		module, migration.Name, sum, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func checksum(statements string) string {
	sum := sha256.Sum256([]byte(statements))
	return hex.EncodeToString(sum[:])
}
