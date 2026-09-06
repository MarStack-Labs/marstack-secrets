package param

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

const storedVersion = 1

type Cipher interface {
	Seal(ctx context.Context, tenant string, plaintext []byte, aad crypto.AAD) (crypto.Envelope, error)
	Open(ctx context.Context, tenant string, envelope crypto.Envelope, aad crypto.AAD) (crypto.Sensitive, error)
	Rewrap(ctx context.Context, tenant string, envelope crypto.Envelope, aad crypto.AAD) (crypto.Envelope, bool, error)
}

type Parameter struct {
	Tenant       string
	Path         string
	ResolvedFrom string
	Kind         Kind
	Value        string
	UpdatedAt    time.Time
	UpdatedBy    string
}

func (p Parameter) Inherited() bool {
	return p.ResolvedFrom != p.Path
}

type Options struct {
	Now func() time.Time
}

type Store struct {
	db     *sql.DB
	cipher Cipher
	now    func() time.Time
}

func NewStore(db *sql.DB, cipher Cipher, opts Options) (*Store, error) {
	if db == nil {
		return nil, ErrNoDatabase
	}
	if cipher == nil {
		return nil, ErrNoCipher
	}
	store := &Store{db: db, cipher: cipher, now: opts.Now}
	if store.now == nil {
		store.now = time.Now
	}
	return store, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	return sqlite.Migrate(ctx, s.db, moduleName, migrations)
}

func (s *Store) Put(ctx context.Context, tenant, path string, kind Kind, raw, actor string) error {
	if err := validate(tenant, path, kind, raw); err != nil {
		return err
	}

	envelope, err := s.cipher.Seal(ctx, tenant, []byte(raw), locate(tenant, path))
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO param_values (tenant, path, kind, kek_version, wrapped_dek, ciphertext, updated_at, updated_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (tenant, path) DO UPDATE SET
			kind = excluded.kind,
			kek_version = excluded.kek_version,
			wrapped_dek = excluded.wrapped_dek,
			ciphertext = excluded.ciphertext,
			updated_at = excluded.updated_at,
			updated_by = excluded.updated_by`,
		tenant, path, string(kind), envelope.KEKVersion, envelope.WrappedDEK, envelope.Ciphertext,
		sqlite.FormatTime(s.now()), actor)
	return err
}

func (s *Store) Get(ctx context.Context, tenant, path string) (Parameter, error) {
	if err := validateLocation(tenant, path); err != nil {
		return Parameter{}, err
	}
	return s.read(ctx, tenant, path, path)
}

func (s *Store) Resolve(ctx context.Context, tenant, path string) (Parameter, error) {
	if err := validateLocation(tenant, path); err != nil {
		return Parameter{}, err
	}

	for _, candidate := range inheritanceChain(path) {
		found, err := s.read(ctx, tenant, candidate, path)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return Parameter{}, err
		}
		return found, nil
	}
	return Parameter{}, ErrNotFound
}

func (s *Store) List(ctx context.Context, tenant, prefix string) ([]Parameter, error) {
	if err := validateTenant(tenant); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT path, kind, updated_at, updated_by FROM param_values
		 WHERE tenant = ? AND path >= ? AND path < ?
		 ORDER BY path`,
		tenant, prefix, ceiling(prefix))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var found []Parameter
	for rows.Next() {
		entry := Parameter{Tenant: tenant}
		var kind, updatedAt string
		if err := rows.Scan(&entry.Path, &kind, &updatedAt, &entry.UpdatedBy); err != nil {
			return nil, err
		}
		entry.Kind = Kind(kind)
		entry.ResolvedFrom = entry.Path
		if entry.UpdatedAt, err = sqlite.ParseTime(updatedAt); err != nil {
			return nil, err
		}
		found = append(found, entry)
	}
	return found, rows.Err()
}

func (s *Store) Delete(ctx context.Context, tenant, path string) error {
	if err := validateLocation(tenant, path); err != nil {
		return err
	}

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM param_values WHERE tenant = ? AND path = ?`, tenant, path)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) read(ctx context.Context, tenant, stored, requested string) (Parameter, error) {
	entry := Parameter{Tenant: tenant, Path: requested, ResolvedFrom: stored}

	var kind, updatedAt string
	var envelope crypto.Envelope

	err := s.db.QueryRowContext(ctx,
		`SELECT kind, kek_version, wrapped_dek, ciphertext, updated_at, updated_by
		 FROM param_values WHERE tenant = ? AND path = ?`,
		tenant, stored,
	).Scan(&kind, &envelope.KEKVersion, &envelope.WrappedDEK, &envelope.Ciphertext,
		&updatedAt, &entry.UpdatedBy)

	if errors.Is(err, sql.ErrNoRows) {
		return Parameter{}, ErrNotFound
	}
	if err != nil {
		return Parameter{}, err
	}

	plaintext, err := s.cipher.Open(ctx, tenant, envelope, locate(tenant, stored))
	if err != nil {
		return Parameter{}, err
	}
	defer plaintext.Zero()

	entry.Kind = Kind(kind)
	entry.Value = string(plaintext)
	if entry.UpdatedAt, err = sqlite.ParseTime(updatedAt); err != nil {
		return Parameter{}, err
	}
	return entry, nil
}

func locate(tenant, path string) crypto.AAD {
	return crypto.AAD{Tenant: tenant, Path: PolicyPath(tenant, path), Version: storedVersion}
}

func ceiling(prefix string) string {
	return prefix + "￿"
}

func validateLocation(tenant, path string) error {
	if err := validateTenant(tenant); err != nil {
		return err
	}
	if !safePath(path) {
		return ErrInvalidPath
	}
	return nil
}

func validateTenant(tenant string) error {
	if tenant == "" || len(tenant) > maxTenantLen {
		return ErrInvalidTenant
	}
	return nil
}
