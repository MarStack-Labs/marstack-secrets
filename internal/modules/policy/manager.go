package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

const maxBoundPolicies = 64

var (
	ErrNoDatabase     = errors.New("policy: a database is required")
	ErrNotFound       = errors.New("policy: no such policy")
	ErrInvalidTenant  = errors.New("policy: tenant is empty or too long")
	ErrTooManyBound   = errors.New("policy: too many policies bound to one identity")
	ErrStoredCorrupt  = errors.New("policy: a stored policy no longer validates")
	ErrCrossTenant    = errors.New("policy: the path belongs to another tenant")
	ErrEmptyIdentity  = errors.New("policy: identity must not be empty")
	maxTenantLenBytes = 64
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

func (m *Manager) Put(ctx context.Context, tenant string, policy Policy) error {
	if err := validateTenant(tenant); err != nil {
		return err
	}
	if _, err := New(policy.Name, policy.Rules); err != nil {
		return err
	}

	encoded, err := json.Marshal(policy.Rules)
	if err != nil {
		return err
	}

	now := sqlite.FormatTime(m.now())
	_, err = m.db.ExecContext(ctx,
		`INSERT INTO policy_definitions (tenant, name, rules, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (tenant, name) DO UPDATE SET rules = excluded.rules, updated_at = excluded.updated_at`,
		tenant, policy.Name, string(encoded), now, now)
	return err
}

func (m *Manager) Get(ctx context.Context, tenant, name string) (Policy, error) {
	if err := validateTenant(tenant); err != nil {
		return Policy{}, err
	}

	var encoded string
	err := m.db.QueryRowContext(ctx,
		`SELECT rules FROM policy_definitions WHERE tenant = ? AND name = ?`,
		tenant, name).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, err
	}
	return decodePolicy(name, encoded)
}

func (m *Manager) List(ctx context.Context, tenant string) ([]string, error) {
	if err := validateTenant(tenant); err != nil {
		return nil, err
	}

	rows, err := m.db.QueryContext(ctx,
		`SELECT name FROM policy_definitions WHERE tenant = ? ORDER BY name`, tenant)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func (m *Manager) Delete(ctx context.Context, tenant, name string) error {
	if err := validateTenant(tenant); err != nil {
		return err
	}

	result, err := m.db.ExecContext(ctx,
		`DELETE FROM policy_definitions WHERE tenant = ? AND name = ?`, tenant, name)
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

func (m *Manager) Bind(ctx context.Context, tenant, identityID, name string) error {
	if err := validateTenant(tenant); err != nil {
		return err
	}
	if identityID == "" {
		return ErrEmptyIdentity
	}
	if _, err := m.Get(ctx, tenant, name); err != nil {
		return err
	}

	bound, err := m.BindingsFor(ctx, tenant, identityID)
	if err != nil {
		return err
	}
	if len(bound) >= maxBoundPolicies {
		return ErrTooManyBound
	}

	_, err = m.db.ExecContext(ctx,
		`INSERT INTO policy_bindings (tenant, identity_id, policy_name, created_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (tenant, identity_id, policy_name) DO NOTHING`,
		tenant, identityID, name, sqlite.FormatTime(m.now()))
	return err
}

func (m *Manager) Unbind(ctx context.Context, tenant, identityID, name string) error {
	if err := validateTenant(tenant); err != nil {
		return err
	}
	_, err := m.db.ExecContext(ctx,
		`DELETE FROM policy_bindings WHERE tenant = ? AND identity_id = ? AND policy_name = ?`,
		tenant, identityID, name)
	return err
}

func (m *Manager) BindingsFor(ctx context.Context, tenant, identityID string) ([]string, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT policy_name FROM policy_bindings
		 WHERE tenant = ? AND identity_id = ? ORDER BY policy_name`,
		tenant, identityID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func (m *Manager) SetFor(ctx context.Context, identity authn.Identity) (Set, error) {
	if err := validateTenant(identity.Tenant); err != nil {
		return nil, err
	}

	rows, err := m.db.QueryContext(ctx,
		`SELECT d.name, d.rules
		 FROM policy_bindings b
		 JOIN policy_definitions d ON d.tenant = b.tenant AND d.name = b.policy_name
		 WHERE b.tenant = ? AND b.identity_id = ?
		 ORDER BY d.name`,
		identity.Tenant, identity.ID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var set Set
	for rows.Next() {
		var name, encoded string
		if err := rows.Scan(&name, &encoded); err != nil {
			return nil, err
		}
		policy, err := decodePolicy(name, encoded)
		if err != nil {
			return nil, err
		}
		set = append(set, policy)
	}
	return set, rows.Err()
}

func (m *Manager) Authorize(ctx context.Context, identity authn.Identity, tenant, path string, capability authz.Capability) (authz.Decision, error) {
	if identity.Tenant == "" || tenant == "" || identity.Tenant != tenant {
		return authz.Decision{Reason: "the path belongs to another tenant"}, nil
	}

	set, err := m.SetFor(ctx, identity)
	if err != nil {
		return authz.Decision{}, err
	}
	return set.Evaluate(path, capability), nil
}

func decodePolicy(name, encoded string) (Policy, error) {
	var rules []Rule
	if err := json.Unmarshal([]byte(encoded), &rules); err != nil {
		return Policy{}, errors.Join(ErrStoredCorrupt, err)
	}

	policy, err := New(name, rules)
	if err != nil {
		return Policy{}, errors.Join(ErrStoredCorrupt, err)
	}
	return policy, nil
}

func validateTenant(tenant string) error {
	if tenant == "" || len(tenant) > maxTenantLenBytes {
		return ErrInvalidTenant
	}
	return nil
}
