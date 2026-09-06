package seal

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

const initialKEKVersion = 1

type State string

const (
	StateUninitialized State = "uninitialized"
	StateSealed        State = "sealed"
	StateUnsealed      State = "unsealed"
)

type Status struct {
	State      State
	Shares     int
	Threshold  int
	Progress   int
	KEKVersion int
}

type Rotation struct {
	From int
	To   int
}

type Options struct {
	Now func() time.Time
}

type config struct {
	initialized bool
	shares      int
	threshold   int
	keyCheck    []byte
	kekVersion  int
}

type Manager struct {
	db  *sql.DB
	now func() time.Time

	mu         sync.RWMutex
	root       crypto.Key
	kekVersion int
	collected  []crypto.Sensitive
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

func (m *Manager) Initialize(ctx context.Context, shares, threshold int) ([]crypto.Sensitive, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored, err := m.readConfig(ctx)
	if err != nil {
		return nil, err
	}
	if stored.initialized {
		return nil, ErrAlreadyInitialized
	}

	root, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}

	split, err := crypto.Split(crypto.Sensitive(root), shares, threshold)
	if err != nil {
		root.Zero()
		return nil, err
	}
	keyCheck, err := crypto.KeyCheckValue(root)
	if err != nil {
		root.Zero()
		return nil, err
	}

	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO seal_config (id, shamir_shares, shamir_threshold, key_check, kek_version, created_at)
		 VALUES (1, ?, ?, ?, ?, ?)`,
		shares, threshold, keyCheck, initialKEKVersion, m.now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		root.Zero()
		return nil, err
	}

	m.root = root
	m.kekVersion = initialKEKVersion
	return split, nil
}

func (m *Manager) Unseal(ctx context.Context, share crypto.Sensitive) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(share) < 2 {
		return Status{}, ErrInvalidShare
	}

	stored, err := m.readConfig(ctx)
	if err != nil {
		return Status{}, err
	}
	if !stored.initialized {
		return Status{}, ErrNotInitialized
	}
	if m.root != nil {
		return m.statusLocked(stored), nil
	}
	if m.alreadyCollected(share) {
		return m.statusLocked(stored), nil
	}

	m.collected = append(m.collected, bytes.Clone(share))
	if len(m.collected) < stored.threshold {
		return m.statusLocked(stored), nil
	}

	combined, combineErr := crypto.Combine(m.collected)
	m.discardCollected()
	if combineErr != nil {
		return Status{}, errors.Join(ErrUnsealFailed, combineErr)
	}

	root := crypto.Key(combined)
	if err := root.Validate(); err != nil {
		root.Zero()
		return Status{}, ErrUnsealFailed
	}
	if err := crypto.VerifyKeyCheckValue(root, stored.keyCheck); err != nil {
		root.Zero()
		return Status{}, ErrUnsealFailed
	}

	m.root = root
	m.kekVersion = stored.kekVersion
	return m.statusLocked(stored), nil
}

func (m *Manager) Seal() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.root != nil {
		m.root.Zero()
		m.root = nil
	}
	m.kekVersion = 0
	m.discardCollected()
}

func (m *Manager) Rotate(ctx context.Context) (Rotation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored, err := m.readConfig(ctx)
	if err != nil {
		return Rotation{}, err
	}
	if !stored.initialized {
		return Rotation{}, ErrNotInitialized
	}
	if m.root == nil {
		return Rotation{}, ErrSealed
	}

	next := stored.kekVersion + 1
	result, err := m.db.ExecContext(ctx,
		`UPDATE seal_config SET kek_version = ? WHERE id = 1 AND kek_version = ?`,
		next, stored.kekVersion)
	if err != nil {
		return Rotation{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Rotation{}, err
	}
	if affected != 1 {
		return Rotation{}, ErrRotationRaced
	}

	m.kekVersion = next
	return Rotation{From: stored.kekVersion, To: next}, nil
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stored, err := m.readConfig(ctx)
	if err != nil {
		return Status{}, err
	}
	return m.statusLocked(stored), nil
}

func (m *Manager) Cipher() *Cipher {
	return &Cipher{manager: m}
}

func (m *Manager) IsUnsealed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.root != nil
}

func (m *Manager) deriveKEK(tenant string, version int) (crypto.Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.deriveKEKLocked(tenant, version)
}

func (m *Manager) sealingKEK(tenant string) (crypto.Key, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	version := m.kekVersion
	kek, err := m.deriveKEKLocked(tenant, version)
	if err != nil {
		return nil, 0, err
	}
	return kek, version, nil
}

func (m *Manager) rewrap(tenant string, envelope crypto.Envelope, aad crypto.AAD) (crypto.Envelope, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.root == nil {
		return crypto.Envelope{}, false, ErrSealed
	}
	if envelope.KEKVersion > m.kekVersion {
		return crypto.Envelope{}, false, ErrKEKVersion
	}
	if envelope.KEKVersion == m.kekVersion {
		return envelope, false, nil
	}

	current, err := m.deriveKEKLocked(tenant, envelope.KEKVersion)
	if err != nil {
		return crypto.Envelope{}, false, err
	}
	defer current.Zero()

	next, err := m.deriveKEKLocked(tenant, m.kekVersion)
	if err != nil {
		return crypto.Envelope{}, false, err
	}
	defer next.Zero()

	rewrapped, err := crypto.Rewrap(current, next, m.kekVersion, envelope, aad)
	if err != nil {
		return crypto.Envelope{}, false, err
	}
	return rewrapped, true, nil
}

func (m *Manager) deriveKEKLocked(tenant string, version int) (crypto.Key, error) {
	if m.root == nil {
		return nil, ErrSealed
	}
	if version < initialKEKVersion {
		return nil, ErrKEKVersion
	}
	label, err := crypto.Label("kek", tenant, crypto.LabelInt(version))
	if err != nil {
		return nil, err
	}
	return crypto.DeriveKey(m.root, label)
}

func (m *Manager) statusLocked(stored config) Status {
	status := Status{
		State:      StateUninitialized,
		Shares:     stored.shares,
		Threshold:  stored.threshold,
		Progress:   len(m.collected),
		KEKVersion: stored.kekVersion,
	}
	switch {
	case !stored.initialized:
		status.State = StateUninitialized
	case m.root != nil:
		status.State = StateUnsealed
	default:
		status.State = StateSealed
	}
	return status
}

func (m *Manager) alreadyCollected(share crypto.Sensitive) bool {
	index := share[len(share)-1]
	for _, existing := range m.collected {
		if existing[len(existing)-1] == index {
			return true
		}
	}
	return false
}

func (m *Manager) discardCollected() {
	for _, share := range m.collected {
		share.Zero()
	}
	m.collected = nil
}

func (m *Manager) readConfig(ctx context.Context) (config, error) {
	var stored config
	err := m.db.QueryRowContext(ctx,
		`SELECT shamir_shares, shamir_threshold, key_check, kek_version FROM seal_config WHERE id = 1`,
	).Scan(&stored.shares, &stored.threshold, &stored.keyCheck, &stored.kekVersion)

	if errors.Is(err, sql.ErrNoRows) {
		return config{}, nil
	}
	if err != nil {
		return config{}, err
	}
	stored.initialized = true
	return stored, nil
}
