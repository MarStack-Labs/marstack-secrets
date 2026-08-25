package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

const BootstrapTTL = 5 * time.Minute

func (m *Manager) IssueBootstrap(ctx context.Context, identityID string, ttl time.Duration) (Token, error) {
	return m.issue(ctx, m.db, identityID, NoBinding, ttl, singleUse)
}

func (m *Manager) Exchange(ctx context.Context, presented crypto.Sensitive, binding string, ttl time.Duration) (Token, error) {
	if ttl <= 0 || ttl > MaximumTTL {
		return Token{}, ErrInvalidTTL
	}
	if !looksLikeToken(presented) {
		return Token{}, ErrUnauthenticated
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return Token{}, err
	}
	defer func() { _ = tx.Rollback() }()

	identityID, err := m.consume(ctx, tx, presented)
	if err != nil {
		return Token{}, err
	}

	token, err := m.issue(ctx, tx, identityID, binding, ttl, reusable)
	if err != nil {
		return Token{}, err
	}
	if err := tx.Commit(); err != nil {
		token.Value.Zero()
		return Token{}, err
	}
	return token, nil
}

func (m *Manager) consume(ctx context.Context, tx *sql.Tx, presented crypto.Sensitive) (string, error) {
	var identityID, expiresAt string
	var single int
	var revokedAt, consumedAt, disabledAt sql.NullString

	err := tx.QueryRowContext(ctx,
		`SELECT t.identity_id, t.expires_at, t.single_use, t.revoked_at, t.consumed_at, i.disabled_at
		 FROM auth_tokens t
		 JOIN auth_identities i ON i.id = t.identity_id
		 WHERE t.id_hash = ?`,
		fingerprint(presented),
	).Scan(&identityID, &expiresAt, &single, &revokedAt, &consumedAt, &disabledAt)

	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUnauthenticated
	}
	if err != nil {
		return "", err
	}

	expiry, err := sqlite.ParseTime(expiresAt)
	if err != nil {
		return "", err
	}

	switch {
	case single != singleUse:
		return "", ErrUnauthenticated
	case revokedAt.Valid, consumedAt.Valid, disabledAt.Valid:
		return "", ErrUnauthenticated
	case !m.now().UTC().Before(expiry):
		return "", ErrUnauthenticated
	}

	result, err := tx.ExecContext(ctx,
		`UPDATE auth_tokens SET consumed_at = ? WHERE id_hash = ? AND consumed_at IS NULL`,
		sqlite.FormatTime(m.now()), fingerprint(presented))
	if err != nil {
		return "", err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if affected != 1 {
		return "", ErrUnauthenticated
	}
	return identityID, nil
}
