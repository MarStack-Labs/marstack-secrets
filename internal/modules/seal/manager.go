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

const currentKEKVersion = 1

type State string

const (
	StateUninitialized State = "uninitialized"
	StateSealed        State = "sealed"
	StateUnsealed      State = "unsealed"
)

type Status struct {
	State     State
	Shares    int
	Threshold int
	Progress  int
}

type Options struct {
	Now func() time.Time
}

type config struct {
	initialized bool
	shares      int
	threshold   int
	keyCheck    []byte
}

type Manager struct {
	db  *sql.DB
	now func() time.Time

	mu        sync.RWMutex
	root      crypto.Key
	collected []crypto.Sensitive
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
		`INSERT INTO seal_config (id, shamir_shares, shamir_threshold, key_check, created_at)
		 VALUES (1, ?, ?, ?, ?)`,
		shares, threshold, keyCheck, m.now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		root.Zero()
		return nil, err
	}

	m.root = root
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
	return m.statusLocked(stored), nil
}

func (m *Manager) Seal() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.root != nil {
		m.root.Zero()
		m.root = nil
	}
	m.discardCollected()
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

	if m.root == nil {
		return nil, ErrSealed
	}
	return crypto.DeriveKey(m.root, crypto.Label("kek", tenant, crypto.LabelInt(version)))
}

func (m *Manager) statusLocked(stored config) Status {
	status := Status{
		State:     StateUninitialized,
		Shares:    stored.shares,
		Threshold: stored.threshold,
		Progress:  len(m.collected),
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
		`SELECT shamir_shares, shamir_threshold, key_check FROM seal_config WHERE id = 1`,
	).Scan(&stored.shares, &stored.threshold, &stored.keyCheck)

	if errors.Is(err, sql.ErrNoRows) {
		return config{}, nil
	}
	if err != nil {
		return config{}, err
	}
	stored.initialized = true
	return stored, nil
}
