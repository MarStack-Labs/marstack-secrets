package secret

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

const (
	maxTenantLen       = 64
	maxPathLen         = 512
	defaultMaxVersions = 10
	currentVersion     = 0
)

type Record struct {
	Tenant      string
	Path        string
	Version     int
	Envelope    crypto.Envelope
	CreatedAt   time.Time
	DeletedAt   time.Time
	DestroyedAt time.Time
}

type Metadata struct {
	Tenant         string
	Path           string
	CurrentVersion int
	MaxVersions    int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Options struct {
	Now         func() time.Time
	MaxVersions int
}

type Store struct {
	db          *sql.DB
	now         func() time.Time
	maxVersions int
}

func NewStore(db *sql.DB, opts Options) (*Store, error) {
	if opts.MaxVersions < 0 {
		return nil, ErrMaxVersions
	}
	store := &Store{
		db:          db,
		now:         opts.Now,
		maxVersions: opts.MaxVersions,
	}
	if store.now == nil {
		store.now = time.Now
	}
	if store.maxVersions == 0 {
		store.maxVersions = defaultMaxVersions
	}
	return store, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	return sqlite.Migrate(ctx, s.db, moduleName, migrations)
}

func (s *Store) Put(ctx context.Context, tenant, path string, envelope crypto.Envelope, expect Expectation) (int, error) {
	if err := validateLocation(tenant, path); err != nil {
		return 0, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	current, known, err := readCurrentVersion(ctx, tx, tenant, path)
	if err != nil {
		return 0, err
	}
	if !expect.satisfiedBy(current) {
		return 0, ErrConflict
	}

	now := s.timestamp()
	next := current + 1

	if known {
		_, err = tx.ExecContext(ctx,
			`UPDATE secret_metadata SET current_version = ?, updated_at = ? WHERE tenant = ? AND path = ?`,
			next, now, tenant, path)
	} else {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO secret_metadata (tenant, path, current_version, max_versions, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			tenant, path, next, s.maxVersions, now, now)
	}
	if err != nil {
		return 0, err
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO secret_versions (tenant, path, version, kek_version, wrapped_dek, ciphertext, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		tenant, path, next, envelope.KEKVersion, envelope.WrappedDEK, envelope.Ciphertext, now,
	); err != nil {
		return 0, err
	}

	if err := pruneOldVersions(ctx, tx, tenant, path, next, s.maxVersions, now); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

func (s *Store) Get(ctx context.Context, tenant, path string, version int) (Record, error) {
	if err := validateLocation(tenant, path); err != nil {
		return Record{}, err
	}
	if version < 0 {
		return Record{}, ErrInvalidVersion
	}

	if version == currentVersion {
		resolved, known, err := readCurrentVersion(ctx, s.db, tenant, path)
		if err != nil {
			return Record{}, err
		}
		if !known {
			return Record{}, ErrNotFound
		}
		version = resolved
	}

	record := Record{Tenant: tenant, Path: path, Version: version}
	var createdAt string
	var deletedAt, destroyedAt sql.NullString

	err := s.db.QueryRowContext(ctx,
		`SELECT kek_version, wrapped_dek, ciphertext, created_at, deleted_at, destroyed_at
		 FROM secret_versions WHERE tenant = ? AND path = ? AND version = ?`,
		tenant, path, version,
	).Scan(
		&record.Envelope.KEKVersion,
		&record.Envelope.WrappedDEK,
		&record.Envelope.Ciphertext,
		&createdAt,
		&deletedAt,
		&destroyedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}

	if record.CreatedAt, err = parseTime(createdAt); err != nil {
		return Record{}, err
	}
	if record.DeletedAt, err = parseNullTime(deletedAt); err != nil {
		return Record{}, err
	}
	if record.DestroyedAt, err = parseNullTime(destroyedAt); err != nil {
		return Record{}, err
	}

	switch {
	case destroyedAt.Valid:
		return Record{}, ErrDestroyed
	case deletedAt.Valid:
		return Record{}, ErrDeleted
	}
	return record, nil
}

func (s *Store) Metadata(ctx context.Context, tenant, path string) (Metadata, error) {
	if err := validateLocation(tenant, path); err != nil {
		return Metadata{}, err
	}

	metadata := Metadata{Tenant: tenant, Path: path}
	var createdAt, updatedAt string

	err := s.db.QueryRowContext(ctx,
		`SELECT current_version, max_versions, created_at, updated_at
		 FROM secret_metadata WHERE tenant = ? AND path = ?`,
		tenant, path,
	).Scan(&metadata.CurrentVersion, &metadata.MaxVersions, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Metadata{}, ErrNotFound
	}
	if err != nil {
		return Metadata{}, err
	}

	if metadata.CreatedAt, err = parseTime(createdAt); err != nil {
		return Metadata{}, err
	}
	if metadata.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func (s *Store) Delete(ctx context.Context, tenant, path string, versions ...int) error {
	return s.mark(ctx, tenant, path, versions, func(ctx context.Context, tx *sql.Tx, version int, now string) error {
		state, err := readVersionState(ctx, tx, tenant, path, version)
		switch {
		case err != nil:
			return err
		case !state.exists:
			return ErrNotFound
		case state.destroyed:
			return ErrDestroyed
		case state.deleted:
			return nil
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE secret_versions SET deleted_at = ? WHERE tenant = ? AND path = ? AND version = ?`,
			now, tenant, path, version)
		return err
	})
}

func (s *Store) Undelete(ctx context.Context, tenant, path string, versions ...int) error {
	return s.mark(ctx, tenant, path, versions, func(ctx context.Context, tx *sql.Tx, version int, now string) error {
		state, err := readVersionState(ctx, tx, tenant, path, version)
		switch {
		case err != nil:
			return err
		case !state.exists:
			return ErrNotFound
		case state.destroyed:
			return ErrDestroyed
		case !state.deleted:
			return nil
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE secret_versions SET deleted_at = NULL WHERE tenant = ? AND path = ? AND version = ?`,
			tenant, path, version)
		return err
	})
}

func (s *Store) Destroy(ctx context.Context, tenant, path string, versions ...int) error {
	return s.mark(ctx, tenant, path, versions, func(ctx context.Context, tx *sql.Tx, version int, now string) error {
		state, err := readVersionState(ctx, tx, tenant, path, version)
		switch {
		case err != nil:
			return err
		case !state.exists:
			return ErrNotFound
		case state.destroyed:
			return nil
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE secret_versions SET destroyed_at = ?, wrapped_dek = x'', ciphertext = x''
			 WHERE tenant = ? AND path = ? AND version = ?`,
			now, tenant, path, version)
		return err
	})
}

type versionAction func(ctx context.Context, tx *sql.Tx, version int, now string) error

func (s *Store) mark(ctx context.Context, tenant, path string, versions []int, action versionAction) error {
	if err := validateLocation(tenant, path); err != nil {
		return err
	}
	for _, version := range versions {
		if version < 1 {
			return ErrInvalidVersion
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if len(versions) == 0 {
		resolved, known, err := readCurrentVersion(ctx, tx, tenant, path)
		if err != nil {
			return err
		}
		if !known {
			return ErrNotFound
		}
		versions = []int{resolved}
	}

	now := s.timestamp()
	for _, version := range versions {
		if err := action(ctx, tx, version, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) timestamp() string {
	return formatTime(s.now())
}
