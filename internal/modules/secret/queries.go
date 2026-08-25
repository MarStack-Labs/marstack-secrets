package secret

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type executor interface {
	querier
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type versionState struct {
	exists    bool
	deleted   bool
	destroyed bool
}

func validateLocation(tenant, path string) error {
	switch {
	case tenant == "" || len(tenant) > maxTenantLen:
		return ErrInvalidTenant
	case path == "" || len(path) > maxPathLen:
		return ErrInvalidPath
	}
	return nil
}

func readCurrentVersion(ctx context.Context, q querier, tenant, path string) (int, bool, error) {
	var version int
	err := q.QueryRowContext(ctx,
		`SELECT current_version FROM secret_metadata WHERE tenant = ? AND path = ?`,
		tenant, path).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return version, true, nil
}

func readVersionState(ctx context.Context, q querier, tenant, path string, version int) (versionState, error) {
	var deletedAt, destroyedAt sql.NullString
	err := q.QueryRowContext(ctx,
		`SELECT deleted_at, destroyed_at FROM secret_versions WHERE tenant = ? AND path = ? AND version = ?`,
		tenant, path, version).Scan(&deletedAt, &destroyedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return versionState{}, nil
	}
	if err != nil {
		return versionState{}, err
	}
	return versionState{exists: true, deleted: deletedAt.Valid, destroyed: destroyedAt.Valid}, nil
}

func pruneOldVersions(ctx context.Context, e executor, tenant, path string, newest, keep int, now string) error {
	threshold := newest - keep
	if threshold < 1 {
		return nil
	}
	_, err := e.ExecContext(ctx,
		`UPDATE secret_versions SET destroyed_at = ?, wrapped_dek = x'', ciphertext = x''
		 WHERE tenant = ? AND path = ? AND version <= ? AND destroyed_at IS NULL`,
		now, tenant, path, threshold)
	return err
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}

func parseNullTime(value sql.NullString) (time.Time, error) {
	if !value.Valid {
		return time.Time{}, nil
	}
	return parseTime(value.String)
}
