package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	dirPerm  = 0o700
	filePerm = 0o600
)

var ErrEmptyPath = errors.New("sqlite: database path must not be empty")

var pragmas = []string{
	"journal_mode(WAL)",
	"synchronous(FULL)",
	"foreign_keys(ON)",
	"busy_timeout(5000)",
}

var expected = map[string]string{
	"journal_mode": "wal",
	"synchronous":  "2",
	"foreign_keys": "1",
}

func Open(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := verifyPragmas(ctx, db); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := os.Chmod(path, filePerm); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return db, nil
}

func dsn(path string) string {
	query := url.Values{}
	for _, pragma := range pragmas {
		query.Add("_pragma", pragma)
	}
	return "file:" + path + "?" + query.Encode()
}

func verifyPragmas(ctx context.Context, db *sql.DB) error {
	for pragma, want := range expected {
		var got string
		if err := db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
			return fmt.Errorf("sqlite: reading pragma %s: %w", pragma, err)
		}
		if !strings.EqualFold(got, want) {
			return fmt.Errorf("sqlite: pragma %s is %q, want %q", pragma, got, want)
		}
	}
	return nil
}
