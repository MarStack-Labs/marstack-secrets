package seal

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

func newManagerAt(t *testing.T, path string) (*Manager, *sql.DB) {
	t.Helper()

	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager, err := NewManager(db, Options{})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if err := manager.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	return manager, db
}

func newManager(t *testing.T) (*Manager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "marsec.db")
	manager, _ := newManagerAt(t, path)
	return manager, path
}

func initialized(t *testing.T) (*Manager, []crypto.Sensitive, string) {
	t.Helper()
	manager, path := newManager(t)
	shares, err := manager.Initialize(t.Context(), 5, 3)
	if err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}
	return manager, shares, path
}

func statusOf(t *testing.T, manager *Manager) Status {
	t.Helper()
	status, err := manager.Status(t.Context())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	return status
}

func TestAFreshStoreIsUninitialized(t *testing.T) {
	manager, _ := newManager(t)

	if got := statusOf(t, manager).State; got != StateUninitialized {
		t.Errorf("State = %q, want %q", got, StateUninitialized)
	}
	if _, err := manager.Unseal(t.Context(), crypto.Sensitive("share")); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Unseal before initialize = %v, want ErrNotInitialized", err)
	}
}

func TestInitializeReturnsSharesAndLeavesTheStoreOpen(t *testing.T) {
	manager, shares, _ := initialized(t)

	if len(shares) != 5 {
		t.Fatalf("Initialize returned %d shares, want 5", len(shares))
	}
	status := statusOf(t, manager)
	if status.State != StateUnsealed {
		t.Errorf("State = %q, want %q", status.State, StateUnsealed)
	}
	if status.Shares != 5 || status.Threshold != 3 {
		t.Errorf("Status = %+v, want 5 shares and a threshold of 3", status)
	}
}

func TestInitializeHappensOnlyOnce(t *testing.T) {
	manager, _, _ := initialized(t)

	if _, err := manager.Initialize(t.Context(), 5, 3); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second Initialize = %v, want ErrAlreadyInitialized", err)
	}
}

func TestInitializeRejectsImpossibleParameters(t *testing.T) {
	manager, _ := newManager(t)

	if _, err := manager.Initialize(t.Context(), 3, 5); !errors.Is(err, crypto.ErrThreshold) {
		t.Fatalf("Initialize with a threshold above the share count = %v, want ErrThreshold", err)
	}
	if got := statusOf(t, manager).State; got != StateUninitialized {
		t.Errorf("a rejected Initialize left the store %q", got)
	}
}

func TestTheRootKeyDoesNotSurviveARestart(t *testing.T) {
	manager, _, path := initialized(t)
	if got := statusOf(t, manager).State; got != StateUnsealed {
		t.Fatalf("State = %q, want %q", got, StateUnsealed)
	}

	restarted, _ := newManagerAt(t, path)
	status := statusOf(t, restarted)
	if status.State != StateSealed {
		t.Errorf("State after a restart = %q, want %q", status.State, StateSealed)
	}
	if status.Threshold != 3 || status.Shares != 5 {
		t.Errorf("Status after a restart = %+v, want the persisted parameters", status)
	}
}

func TestUnsealNeedsTheThresholdNumberOfShares(t *testing.T) {
	_, shares, path := initialized(t)
	restarted, _ := newManagerAt(t, path)
	ctx := t.Context()

	for offered, share := range shares[:2] {
		status, err := restarted.Unseal(ctx, share)
		if err != nil {
			t.Fatalf("Unseal returned error: %v", err)
		}
		if status.State != StateSealed {
			t.Fatalf("State after %d shares = %q, want %q", offered+1, status.State, StateSealed)
		}
		if status.Progress != offered+1 {
			t.Errorf("Progress = %d, want %d", status.Progress, offered+1)
		}
	}

	status, err := restarted.Unseal(ctx, shares[2])
	if err != nil {
		t.Fatalf("Unseal returned error: %v", err)
	}
	if status.State != StateUnsealed {
		t.Fatalf("State after the third share = %q, want %q", status.State, StateUnsealed)
	}
	if status.Progress != 0 {
		t.Errorf("Progress after unsealing = %d, want 0", status.Progress)
	}
}

func TestTheSameShareTwiceDoesNotCount(t *testing.T) {
	_, shares, path := initialized(t)
	restarted, _ := newManagerAt(t, path)
	ctx := t.Context()

	for range 3 {
		status, err := restarted.Unseal(ctx, shares[0])
		if err != nil {
			t.Fatalf("Unseal returned error: %v", err)
		}
		if status.Progress != 1 {
			t.Fatalf("Progress = %d, want 1 after repeating one share", status.Progress)
		}
		if status.State != StateSealed {
			t.Fatalf("State = %q, want %q", status.State, StateSealed)
		}
	}
}

func TestUnsealingWithForeignSharesFails(t *testing.T) {
	_, _, path := initialized(t)
	restarted, _ := newManagerAt(t, path)

	_, foreign, _ := initialized(t)
	ctx := t.Context()

	for _, share := range foreign[:2] {
		if _, err := restarted.Unseal(ctx, share); err != nil {
			t.Fatalf("Unseal returned error: %v", err)
		}
	}
	if _, err := restarted.Unseal(ctx, foreign[2]); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("Unseal with foreign shares = %v, want ErrUnsealFailed", err)
	}

	status := statusOf(t, restarted)
	if status.State != StateSealed {
		t.Errorf("State = %q, want %q", status.State, StateSealed)
	}
	if status.Progress != 0 {
		t.Errorf("Progress after a failed attempt = %d, want it reset to 0", status.Progress)
	}
}

func TestUnsealRejectsMalformedShares(t *testing.T) {
	_, _, path := initialized(t)
	restarted, _ := newManagerAt(t, path)

	for name, share := range map[string]crypto.Sensitive{
		"empty":     {},
		"one byte":  {0x01},
		"nil share": nil,
	} {
		if _, err := restarted.Unseal(t.Context(), share); !errors.Is(err, ErrInvalidShare) {
			t.Errorf("Unseal with a %s share = %v, want ErrInvalidShare", name, err)
		}
	}
}

func TestUnsealValidatesTheShareWhateverTheState(t *testing.T) {
	manager, _ := newManager(t)

	if _, err := manager.Unseal(t.Context(), crypto.Sensitive{0x01}); !errors.Is(err, ErrInvalidShare) {
		t.Errorf("Unseal on an uninitialized store = %v, want ErrInvalidShare", err)
	}

	open, _, _ := initialized(t)
	if _, err := open.Unseal(t.Context(), crypto.Sensitive{0x01}); !errors.Is(err, ErrInvalidShare) {
		t.Errorf("Unseal on an open store = %v, want ErrInvalidShare", err)
	}
}

func TestUnsealIsIdempotentOnceOpen(t *testing.T) {
	manager, shares, _ := initialized(t)

	status, err := manager.Unseal(t.Context(), shares[0])
	if err != nil {
		t.Fatalf("Unseal returned error: %v", err)
	}
	if status.State != StateUnsealed {
		t.Errorf("State = %q, want %q", status.State, StateUnsealed)
	}
	if status.Progress != 0 {
		t.Errorf("Progress = %d, want 0 when already open", status.Progress)
	}
}

func TestSealClosesTheStoreAndDiscardsProgress(t *testing.T) {
	manager, shares, path := initialized(t)

	manager.Seal()
	if got := statusOf(t, manager).State; got != StateSealed {
		t.Fatalf("State after Seal = %q, want %q", got, StateSealed)
	}
	manager.Seal()
	if got := statusOf(t, manager).State; got != StateSealed {
		t.Errorf("a repeated Seal changed the state to %q", got)
	}

	restarted, _ := newManagerAt(t, path)
	ctx := t.Context()
	if _, err := restarted.Unseal(ctx, shares[0]); err != nil {
		t.Fatalf("Unseal returned error: %v", err)
	}
	restarted.Seal()
	if got := statusOf(t, restarted).Progress; got != 0 {
		t.Errorf("Progress after Seal = %d, want 0", got)
	}
}

func TestNewManagerRequiresADatabase(t *testing.T) {
	if _, err := NewManager(nil, Options{}); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("NewManager = %v, want ErrNoDatabase", err)
	}
}

func TestSharesAreIndependentOfTheStoreThatMadeThem(t *testing.T) {
	_, shares, path := initialized(t)

	first, _ := newManagerAt(t, path)
	ctx := t.Context()
	for _, share := range []crypto.Sensitive{shares[4], shares[2], shares[0]} {
		if _, err := first.Unseal(ctx, share); err != nil {
			t.Fatalf("Unseal returned error: %v", err)
		}
	}
	if got := statusOf(t, first).State; got != StateUnsealed {
		t.Fatalf("State = %q, want %q with an out of order quorum", got, StateUnsealed)
	}
}

func TestInitializeStoresNoKeyMaterial(t *testing.T) {
	manager, shares, path := initialized(t)
	ctx := context.Background()

	kek, err := manager.deriveKEK("prod", currentKEKVersion)
	if err != nil {
		t.Fatalf("deriveKEK returned error: %v", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("opening the database directly: %v", err)
	}
	defer func() { _ = db.Close() }()

	var keyCheck []byte
	if err := db.QueryRowContext(ctx, `SELECT key_check FROM seal_config WHERE id = 1`).Scan(&keyCheck); err != nil {
		t.Fatalf("reading the stored configuration: %v", err)
	}

	if bytes.Contains(keyCheck, kek) {
		t.Error("the stored key check value contains a key encryption key")
	}
	for index, share := range shares {
		if bytes.Contains(keyCheck, share[:len(share)-1]) {
			t.Errorf("the stored key check value contains share %d", index+1)
		}
	}
}
