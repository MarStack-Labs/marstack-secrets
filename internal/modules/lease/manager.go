package lease

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

const (
	DefaultTTL   = 30 * time.Minute
	MaximumTTL   = 24 * time.Hour
	Retention    = 24 * time.Hour
	maxTenantLen = 64
	maxPathLen   = 512
	suffixLength = 12
)

var (
	ErrNoDatabase    = errors.New("lease: a database is required")
	ErrNoRevoker     = errors.New("lease: a token revoker is required")
	ErrNotFound      = errors.New("lease: no such lease")
	ErrNotHolder     = errors.New("lease: the lease belongs to another identity")
	ErrGone          = errors.New("lease: the lease has expired or been revoked")
	ErrInvalidTenant = errors.New("lease: tenant is empty or too long")
	ErrInvalidPath   = errors.New("lease: path is empty or too long")
	ErrInvalidTTL    = errors.New("lease: time to live must be positive and within the maximum")
	ErrInvalidBatch  = errors.New("lease: batch size must be at least one")
)

type Revoker interface {
	RevokeIdentity(ctx context.Context, identityID string) (int, error)
}

type Lease struct {
	ID         string
	Tenant     string
	IdentityID string
	Path       string
	Version    int
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

func (l Lease) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", l.ID),
		slog.String("identity", l.IdentityID),
		slog.String("path", l.Path),
		slog.Int("version", l.Version),
	)
}

type Revocation struct {
	Leases     int
	Identities []string
	Tokens     int
}

type Options struct {
	Now func() time.Time
}

type Manager struct {
	db      *sql.DB
	revoker Revoker
	now     func() time.Time
}

func NewManager(db *sql.DB, revoker Revoker, opts Options) (*Manager, error) {
	if db == nil {
		return nil, ErrNoDatabase
	}
	if revoker == nil {
		return nil, ErrNoRevoker
	}
	manager := &Manager{db: db, revoker: revoker, now: opts.Now}
	if manager.now == nil {
		manager.now = time.Now
	}
	return manager, nil
}

func (m *Manager) Migrate(ctx context.Context) error {
	return sqlite.Migrate(ctx, m.db, moduleName, migrations)
}

func (m *Manager) Issue(ctx context.Context, tenant, identityID, path string, version int, ttl time.Duration) (Lease, error) {
	if err := validate(tenant, path, ttl); err != nil {
		return Lease{}, err
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return Lease{}, err
	}
	defer func() { _ = tx.Rollback() }()

	now := m.now().UTC()
	expiry := now.Add(ttl)

	existing, found, err := m.activeHolding(ctx, tx, tenant, identityID, path, version, now)
	if err != nil {
		return Lease{}, err
	}

	if found {
		if expiry.After(existing.ExpiresAt) {
			if _, err := tx.ExecContext(ctx,
				`UPDATE lease_records SET expires_at = ? WHERE id = ?`,
				sqlite.FormatTime(expiry), existing.ID); err != nil {
				return Lease{}, err
			}
			existing.ExpiresAt = expiry
		}
		if err := tx.Commit(); err != nil {
			return Lease{}, err
		}
		return existing, nil
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE lease_records SET revoked_at = ?
		 WHERE tenant = ? AND identity_id = ? AND path = ? AND version = ? AND revoked_at IS NULL`,
		sqlite.FormatTime(now), tenant, identityID, path, version); err != nil {
		return Lease{}, err
	}

	issued := Lease{
		ID:         newID(path),
		Tenant:     tenant,
		IdentityID: identityID,
		Path:       path,
		Version:    version,
		IssuedAt:   now,
		ExpiresAt:  expiry,
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO lease_records (id, tenant, identity_id, path, version, issued_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		issued.ID, tenant, identityID, path, version,
		sqlite.FormatTime(now), sqlite.FormatTime(expiry)); err != nil {
		return Lease{}, err
	}
	if err := tx.Commit(); err != nil {
		return Lease{}, err
	}
	return issued, nil
}

func (m *Manager) Renew(ctx context.Context, id, identityID string, ttl time.Duration) (Lease, error) {
	if ttl <= 0 || ttl > MaximumTTL {
		return Lease{}, ErrInvalidTTL
	}

	held, err := m.read(ctx, m.db, id)
	if err != nil {
		return Lease{}, err
	}
	if held.IdentityID != identityID {
		return Lease{}, ErrNotHolder
	}

	now := m.now().UTC()
	if !now.Before(held.ExpiresAt) {
		return Lease{}, ErrGone
	}

	expiry := now.Add(ttl)
	if _, err := m.db.ExecContext(ctx,
		`UPDATE lease_records SET expires_at = ? WHERE id = ? AND revoked_at IS NULL`,
		sqlite.FormatTime(expiry), id); err != nil {
		return Lease{}, err
	}
	held.ExpiresAt = expiry
	return held, nil
}

func (m *Manager) Revoke(ctx context.Context, id string) error {
	result, err := m.db.ExecContext(ctx,
		`UPDATE lease_records SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		sqlite.FormatTime(m.now()), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		var present int
		if err := m.db.QueryRowContext(ctx,
			`SELECT count(*) FROM lease_records WHERE id = ?`, id).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			return ErrNotFound
		}
	}
	return nil
}

func (m *Manager) RevokePrefix(ctx context.Context, tenant, prefix string) (Revocation, error) {
	if err := validateTenant(tenant); err != nil {
		return Revocation{}, err
	}
	if prefix == "" || len(prefix) > maxPathLen {
		return Revocation{}, ErrInvalidPath
	}

	holders, leases, err := m.holdersUnder(ctx, tenant, prefix)
	if err != nil {
		return Revocation{}, err
	}
	if _, err := m.db.ExecContext(ctx,
		`UPDATE lease_records SET revoked_at = ?
		 WHERE tenant = ? AND path >= ? AND path < ? AND revoked_at IS NULL`,
		sqlite.FormatTime(m.now()), tenant, prefix, prefixCeiling(prefix)); err != nil {
		return Revocation{}, err
	}

	return m.revokeHolders(ctx, leases, holders)
}

func (m *Manager) RevokeIdentity(ctx context.Context, tenant, identityID string) (Revocation, error) {
	if err := validateTenant(tenant); err != nil {
		return Revocation{}, err
	}

	var leases int
	if err := m.db.QueryRowContext(ctx,
		`SELECT count(*) FROM lease_records
		 WHERE tenant = ? AND identity_id = ? AND revoked_at IS NULL`,
		tenant, identityID).Scan(&leases); err != nil {
		return Revocation{}, err
	}
	if _, err := m.db.ExecContext(ctx,
		`UPDATE lease_records SET revoked_at = ?
		 WHERE tenant = ? AND identity_id = ? AND revoked_at IS NULL`,
		sqlite.FormatTime(m.now()), tenant, identityID); err != nil {
		return Revocation{}, err
	}

	return m.revokeHolders(ctx, leases, []string{identityID})
}

func (m *Manager) Active(ctx context.Context, tenant, identityID string) ([]Lease, error) {
	if err := validateTenant(tenant); err != nil {
		return nil, err
	}

	query := `SELECT id, tenant, identity_id, path, version, issued_at, expires_at
	          FROM lease_records
	          WHERE tenant = ? AND revoked_at IS NULL AND expires_at > ?`
	args := []any{tenant, sqlite.FormatTime(m.now())}
	if identityID != "" {
		query += ` AND identity_id = ?`
		args = append(args, identityID)
	}
	query += ` ORDER BY path, identity_id`

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var active []Lease
	for rows.Next() {
		held, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		active = append(active, held)
	}
	return active, rows.Err()
}

func (m *Manager) CountActive(ctx context.Context) (int, error) {
	var held int
	err := m.db.QueryRowContext(ctx,
		`SELECT count(*) FROM lease_records WHERE revoked_at IS NULL AND expires_at > ?`,
		sqlite.FormatTime(m.now())).Scan(&held)
	return held, err
}

func (m *Manager) Sweep(ctx context.Context, batch int) (int, error) {
	if batch < 1 {
		return 0, ErrInvalidBatch
	}

	cutoff := sqlite.FormatTime(m.now().Add(-Retention))
	result, err := m.db.ExecContext(ctx,
		`DELETE FROM lease_records WHERE id IN (
			SELECT id FROM lease_records WHERE expires_at <= ? LIMIT ?
		 )`, cutoff, batch)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}

func (m *Manager) revokeHolders(ctx context.Context, leases int, holders []string) (Revocation, error) {
	revocation := Revocation{Leases: leases, Identities: holders}
	if revocation.Identities == nil {
		revocation.Identities = []string{}
	}

	for _, holder := range holders {
		tokens, err := m.revoker.RevokeIdentity(ctx, holder)
		if err != nil {
			return Revocation{}, err
		}
		revocation.Tokens += tokens
	}
	return revocation, nil
}

func (m *Manager) holdersUnder(ctx context.Context, tenant, prefix string) ([]string, int, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT identity_id, count(*) FROM lease_records
		 WHERE tenant = ? AND path >= ? AND path < ? AND revoked_at IS NULL
		 GROUP BY identity_id ORDER BY identity_id`,
		tenant, prefix, prefixCeiling(prefix))
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	var holders []string
	var leases int
	for rows.Next() {
		var holder string
		var held int
		if err := rows.Scan(&holder, &held); err != nil {
			return nil, 0, err
		}
		holders = append(holders, holder)
		leases += held
	}
	return holders, leases, rows.Err()
}

func (m *Manager) activeHolding(ctx context.Context, tx *sql.Tx, tenant, identityID, path string, version int, now time.Time) (Lease, bool, error) {
	row := tx.QueryRowContext(ctx,
		`SELECT id, tenant, identity_id, path, version, issued_at, expires_at
		 FROM lease_records
		 WHERE tenant = ? AND identity_id = ? AND path = ? AND version = ?
		   AND revoked_at IS NULL AND expires_at > ?`,
		tenant, identityID, path, version, sqlite.FormatTime(now))

	held, err := scanLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, false, nil
	}
	if err != nil {
		return Lease{}, false, err
	}
	return held, true, nil
}

func (m *Manager) read(ctx context.Context, q querier, id string) (Lease, error) {
	row := q.QueryRowContext(ctx,
		`SELECT id, tenant, identity_id, path, version, issued_at, expires_at
		 FROM lease_records WHERE id = ? AND revoked_at IS NULL`, id)

	held, err := scanLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, ErrGone
	}
	if err != nil {
		return Lease{}, err
	}
	return held, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface {
	Scan(dest ...any) error
}

func scanLease(row scanner) (Lease, error) {
	var held Lease
	var issuedAt, expiresAt string

	if err := row.Scan(&held.ID, &held.Tenant, &held.IdentityID, &held.Path,
		&held.Version, &issuedAt, &expiresAt); err != nil {
		return Lease{}, err
	}

	var err error
	if held.IssuedAt, err = sqlite.ParseTime(issuedAt); err != nil {
		return Lease{}, err
	}
	if held.ExpiresAt, err = sqlite.ParseTime(expiresAt); err != nil {
		return Lease{}, err
	}
	return held, nil
}

func newID(path string) string {
	return path + "/" + rand.Text()[:suffixLength]
}

func prefixCeiling(prefix string) string {
	return prefix + "￿"
}

func validate(tenant, path string, ttl time.Duration) error {
	if err := validateTenant(tenant); err != nil {
		return err
	}
	if path == "" || len(path) > maxPathLen || strings.Contains(path, "￿") {
		return ErrInvalidPath
	}
	if ttl <= 0 || ttl > MaximumTTL {
		return ErrInvalidTTL
	}
	return nil
}

func validateTenant(tenant string) error {
	if tenant == "" || len(tenant) > maxTenantLen {
		return ErrInvalidTenant
	}
	return nil
}
