package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

type Options struct {
	Now func() time.Time
}

type Manager struct {
	db  *sql.DB
	now func() time.Time
}

func NewManager(db *sql.DB, opts Options) (*Manager, error) {
	if db == nil {
		return nil, ErrNoDatabase
	}
	manager := &Manager{db: db, now: opts.Now}
	if manager.now == nil {
		manager.now = time.Now
	}
	return manager, nil
}

func (m *Manager) Migrate(ctx context.Context) error {
	return sqlite.Migrate(ctx, m.db, moduleName, migrations)
}

func (m *Manager) RegisterIdentity(ctx context.Context, id string, kind Kind, tenant string) (Identity, error) {
	if err := validateIdentity(id, kind, tenant); err != nil {
		return Identity{}, err
	}

	now := m.now().UTC()
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO auth_identities (id, kind, tenant, created_at) VALUES (?, ?, ?, ?)`,
		id, string(kind), tenant, sqlite.FormatTime(now))
	if err != nil {
		if existing, lookupErr := m.Identity(ctx, id); lookupErr == nil {
			_ = existing
			return Identity{}, ErrIdentityExists
		}
		return Identity{}, err
	}

	return Identity{ID: id, Kind: kind, Tenant: tenant, CreatedAt: now}, nil
}

func (m *Manager) Identity(ctx context.Context, id string) (Identity, error) {
	identity := Identity{ID: id}
	var kind, createdAt string
	var disabledAt sql.NullString

	err := m.db.QueryRowContext(ctx,
		`SELECT kind, tenant, created_at, disabled_at FROM auth_identities WHERE id = ?`, id,
	).Scan(&kind, &identity.Tenant, &createdAt, &disabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, ErrUnknownIdentity
	}
	if err != nil {
		return Identity{}, err
	}

	identity.Kind = Kind(kind)
	identity.Disabled = disabledAt.Valid
	if identity.CreatedAt, err = sqlite.ParseTime(createdAt); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func (m *Manager) DisableIdentity(ctx context.Context, id string) error {
	result, err := m.db.ExecContext(ctx,
		`UPDATE auth_identities SET disabled_at = ? WHERE id = ? AND disabled_at IS NULL`,
		sqlite.FormatTime(m.now()), id)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		if _, lookupErr := m.Identity(ctx, id); lookupErr != nil {
			return lookupErr
		}
	}
	return nil
}

func (m *Manager) Issue(ctx context.Context, identityID, binding string, ttl time.Duration) (Token, error) {
	if ttl <= 0 || ttl > MaximumTTL {
		return Token{}, ErrInvalidTTL
	}

	identity, err := m.Identity(ctx, identityID)
	if err != nil {
		return Token{}, err
	}
	if identity.Disabled {
		return Token{}, ErrIdentityDisabled
	}

	value, err := newTokenValue()
	if err != nil {
		return Token{}, err
	}

	issuedAt := m.now().UTC()
	expiresAt := issuedAt.Add(ttl)

	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO auth_tokens (id_hash, identity_id, binding, issued_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		fingerprint(value), identityID, binding,
		sqlite.FormatTime(issuedAt), sqlite.FormatTime(expiresAt),
	); err != nil {
		value.Zero()
		return Token{}, err
	}

	return Token{Value: value, Identity: identity, ExpiresAt: expiresAt}, nil
}

func (m *Manager) Authenticate(ctx context.Context, presented crypto.Sensitive, binding string) (Identity, error) {
	if !looksLikeToken(presented) {
		return Identity{}, ErrUnauthenticated
	}

	var identityID, storedBinding, expiresAt string
	var revokedAt, disabledAt sql.NullString
	var kind, tenant, createdAt string

	err := m.db.QueryRowContext(ctx,
		`SELECT t.identity_id, t.binding, t.expires_at, t.revoked_at,
		        i.kind, i.tenant, i.created_at, i.disabled_at
		 FROM auth_tokens t
		 JOIN auth_identities i ON i.id = t.identity_id
		 WHERE t.id_hash = ?`,
		fingerprint(presented),
	).Scan(&identityID, &storedBinding, &expiresAt, &revokedAt,
		&kind, &tenant, &createdAt, &disabledAt)

	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, ErrUnauthenticated
	}
	if err != nil {
		return Identity{}, err
	}

	expiry, err := sqlite.ParseTime(expiresAt)
	if err != nil {
		return Identity{}, err
	}
	created, err := sqlite.ParseTime(createdAt)
	if err != nil {
		return Identity{}, err
	}

	switch {
	case revokedAt.Valid:
		return Identity{}, ErrUnauthenticated
	case disabledAt.Valid:
		return Identity{}, ErrUnauthenticated
	case !m.now().UTC().Before(expiry):
		return Identity{}, ErrUnauthenticated
	case storedBinding != binding:
		return Identity{}, ErrUnauthenticated
	}

	return Identity{
		ID:        identityID,
		Kind:      Kind(kind),
		Tenant:    tenant,
		CreatedAt: created,
	}, nil
}

func (m *Manager) Revoke(ctx context.Context, presented crypto.Sensitive) error {
	if !looksLikeToken(presented) {
		return ErrUnauthenticated
	}
	_, err := m.db.ExecContext(ctx,
		`UPDATE auth_tokens SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL`,
		sqlite.FormatTime(m.now()), fingerprint(presented))
	return err
}

func (m *Manager) RevokeIdentity(ctx context.Context, identityID string) (int, error) {
	result, err := m.db.ExecContext(ctx,
		`UPDATE auth_tokens SET revoked_at = ? WHERE identity_id = ? AND revoked_at IS NULL`,
		sqlite.FormatTime(m.now()), identityID)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}

func (m *Manager) PurgeExpired(ctx context.Context) (int, error) {
	result, err := m.db.ExecContext(ctx,
		`DELETE FROM auth_tokens WHERE expires_at <= ?`, sqlite.FormatTime(m.now()))
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}
