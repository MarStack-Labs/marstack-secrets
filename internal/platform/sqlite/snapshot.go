package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrSnapshotExists  = errors.New("sqlite: the snapshot path is already taken")
	ErrSnapshotEmpty   = errors.New("sqlite: the snapshot holds no applied migrations")
	ErrSnapshotCorrupt = errors.New("sqlite: the snapshot fails its integrity check")
	ErrTargetExists    = errors.New("sqlite: the target already holds a database; move it aside first")
	ErrSnapshotQuoted  = errors.New("sqlite: a snapshot path may not contain a single quote")
)

type SnapshotReport struct {
	Path       string
	Bytes      int64
	Migrations int
}

func Snapshot(ctx context.Context, db *sql.DB, path string) (SnapshotReport, error) {
	if path == "" {
		return SnapshotReport{}, ErrEmptyPath
	}
	if strings.Contains(path, "'") {
		return SnapshotReport{}, ErrSnapshotQuoted
	}
	if _, err := os.Stat(path); err == nil {
		return SnapshotReport{}, fmt.Errorf("%w: %s", ErrSnapshotExists, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return SnapshotReport{}, err
	}

	if _, err := db.ExecContext(ctx, `VACUUM INTO '`+path+`'`); err != nil {
		return SnapshotReport{}, err
	}
	if err := os.Chmod(path, filePerm); err != nil {
		return SnapshotReport{}, err
	}
	return Verify(ctx, path)
}

func Verify(ctx context.Context, path string) (SnapshotReport, error) {
	if path == "" {
		return SnapshotReport{}, ErrEmptyPath
	}

	info, err := os.Stat(path)
	if err != nil {
		return SnapshotReport{}, err
	}

	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return SnapshotReport{}, err
	}
	defer func() { _ = db.Close() }()

	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return SnapshotReport{}, errors.Join(ErrSnapshotCorrupt, err)
	}
	if integrity != "ok" {
		return SnapshotReport{}, fmt.Errorf("%w: %s", ErrSnapshotCorrupt, integrity)
	}

	var migrations int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&migrations); err != nil {
		return SnapshotReport{}, errors.Join(ErrSnapshotEmpty, err)
	}
	if migrations == 0 {
		return SnapshotReport{}, ErrSnapshotEmpty
	}

	return SnapshotReport{Path: path, Bytes: info.Size(), Migrations: migrations}, nil
}

func Restore(ctx context.Context, snapshot, target string) (SnapshotReport, error) {
	report, err := Verify(ctx, snapshot)
	if err != nil {
		return SnapshotReport{}, err
	}
	if target == "" {
		return SnapshotReport{}, ErrEmptyPath
	}
	if _, err := os.Stat(target); err == nil {
		return SnapshotReport{}, fmt.Errorf("%w: %s", ErrTargetExists, target)
	}
	if err := os.MkdirAll(filepath.Dir(target), dirPerm); err != nil {
		return SnapshotReport{}, err
	}

	source, err := os.Open(snapshot)
	if err != nil {
		return SnapshotReport{}, err
	}
	defer func() { _ = source.Close() }()

	destination, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return SnapshotReport{}, err
	}

	if _, err := io.Copy(destination, source); err != nil {
		return SnapshotReport{}, errors.Join(err, destination.Close(), os.Remove(target))
	}
	if err := destination.Sync(); err != nil {
		return SnapshotReport{}, errors.Join(err, destination.Close())
	}
	if err := destination.Close(); err != nil {
		return SnapshotReport{}, err
	}

	report.Path = target
	return report, nil
}
