package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/jwt"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

const InstanceTTL = time.Hour

type Assertions interface {
	Verify(ctx context.Context, token []byte) (jwt.Claims, error)
}

func (m *Manager) LoginInstance(ctx context.Context, verifier Assertions, assertion []byte) (Token, error) {
	claims, err := verifier.Verify(ctx, assertion)
	if err != nil {
		return Token{}, errors.Join(ErrUnauthenticated, err)
	}
	if err := validateIdentity(claims.Subject, authn.KindInstance, claims.Tenant); err != nil {
		return Token{}, errors.Join(ErrUnauthenticated, err)
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return Token{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := m.spend(ctx, tx, claims); err != nil {
		return Token{}, err
	}
	if err := m.enrol(ctx, tx, claims); err != nil {
		return Token{}, err
	}

	token, err := m.issue(ctx, tx, claims.Subject, NoBinding, InstanceTTL, reusable)
	if err != nil {
		if errors.Is(err, ErrIdentityDisabled) {
			return Token{}, ErrUnauthenticated
		}
		return Token{}, err
	}
	if err := tx.Commit(); err != nil {
		token.Value.Zero()
		return Token{}, err
	}
	return token, nil
}

func (m *Manager) spend(ctx context.Context, tx *sql.Tx, claims jwt.Claims) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO auth_spent_assertions (id, identity, spent_at, expires_at) VALUES (?, ?, ?, ?)`,
		claims.ID, claims.Subject,
		sqlite.FormatTime(m.now()),
		sqlite.FormatTime(time.Unix(claims.ExpiresAt, 0)))
	if err == nil {
		return nil
	}

	var spent int
	if lookupErr := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM auth_spent_assertions WHERE id = ?`, claims.ID).Scan(&spent); lookupErr != nil {
		return err
	}
	if spent > 0 {
		return ErrReplayed
	}
	return err
}

func (m *Manager) enrol(ctx context.Context, tx *sql.Tx, claims jwt.Claims) error {
	existing, err := m.identityOn(ctx, tx, claims.Subject)
	switch {
	case errors.Is(err, ErrUnknownIdentity):
		_, err = tx.ExecContext(ctx,
			`INSERT INTO auth_identities (id, kind, tenant, created_at) VALUES (?, ?, ?, ?)`,
			claims.Subject, string(authn.KindInstance), claims.Tenant, sqlite.FormatTime(m.now()))
		return err
	case err != nil:
		return err
	case existing.Tenant != claims.Tenant:
		return ErrTenantMismatch
	case existing.Kind != authn.KindInstance:
		return ErrKindMismatch
	default:
		return nil
	}
}

func (m *Manager) PurgeSpentAssertions(ctx context.Context) (int, error) {
	result, err := m.db.ExecContext(ctx,
		`DELETE FROM auth_spent_assertions WHERE expires_at <= ?`, sqlite.FormatTime(m.now()))
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}
