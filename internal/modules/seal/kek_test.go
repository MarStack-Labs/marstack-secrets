package seal

import (
	"database/sql"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

func reopened(t *testing.T, path string, shares []crypto.Sensitive, quorum int) *Manager {
	t.Helper()

	manager, _ := newManagerAt(t, path)
	for _, share := range shares[:quorum] {
		if _, err := manager.Unseal(t.Context(), share); err != nil {
			t.Fatalf("Unseal returned error: %v", err)
		}
	}
	if !manager.IsUnsealed() {
		t.Fatal("the store did not open with a quorum of shares")
	}
	return manager
}

func setStoredKEKVersion(t *testing.T, path string, version int) {
	t.Helper()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("opening the database directly: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(t.Context(),
		`UPDATE seal_config SET kek_version = ? WHERE id = 1`, version); err != nil {
		t.Fatalf("writing the key encryption key version: %v", err)
	}
}

func TestANewStoreStartsAtTheFirstKEKVersion(t *testing.T) {
	manager, _, _ := initialized(t)

	if got := statusOf(t, manager).KEKVersion; got != initialKEKVersion {
		t.Errorf("KEKVersion = %d, want %d", got, initialKEKVersion)
	}
}

func TestAnUninitializedStoreReportsNoKEKVersion(t *testing.T) {
	manager, _ := newManager(t)

	if got := statusOf(t, manager).KEKVersion; got != 0 {
		t.Errorf("KEKVersion = %d, want 0 before the store is initialized", got)
	}
}

func TestSealingFollowsThePersistedKEKVersion(t *testing.T) {
	_, shares, path := initialized(t)
	setStoredKEKVersion(t, path, 7)

	manager := reopened(t, path, shares, 3)
	envelope, err := manager.Cipher().Seal(t.Context(), "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	if envelope.KEKVersion != 7 {
		t.Errorf("KEKVersion = %d, want the persisted 7 rather than a compiled in constant", envelope.KEKVersion)
	}
	if got := statusOf(t, manager).KEKVersion; got != 7 {
		t.Errorf("Status reported KEKVersion = %d, want 7", got)
	}
}

func TestAValueSurvivesAKEKVersionItWasNotSealedUnder(t *testing.T) {
	_, shares, path := initialized(t)
	plaintext := []byte("db_password=s3cr3t")

	first := reopened(t, path, shares, 3)
	envelope, err := first.Cipher().Seal(t.Context(), "prod", plaintext, location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	setStoredKEKVersion(t, path, 9)
	second := reopened(t, path, shares, 3)

	opened, err := second.Cipher().Open(t.Context(), "prod", envelope, location("prod"))
	if err != nil {
		t.Fatalf("Open under a later key encryption key version returned error: %v", err)
	}
	if string(opened) != string(plaintext) {
		t.Errorf("Open() = %q, want %q", string(opened), plaintext)
	}
}
