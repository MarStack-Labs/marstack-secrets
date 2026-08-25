package app

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/modules/seal"
	"github.com/marstack-labs/marstack-secrets/internal/modules/secret"
	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

var _ secret.Cipher = (*seal.Cipher)(nil)

func TestSealAndSecretComposeIntoAWorkingStore(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "marsec.db")

	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager, err := seal.NewManager(db, seal.Options{})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if err := manager.Migrate(ctx); err != nil {
		t.Fatalf("seal Migrate returned error: %v", err)
	}

	store, err := secret.NewStore(db, secret.Options{})
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	service, err := secret.NewService(store, manager.Cipher())
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if err := service.Migrate(ctx); err != nil {
		t.Fatalf("secret Migrate returned error: %v", err)
	}

	plaintext := []byte("db_password=s3cr3t")

	if _, err := service.Put(ctx, "prod", "payment-api", plaintext, secret.Absent()); !errors.Is(err, seal.ErrSealed) {
		t.Fatalf("writing before the store is initialized = %v, want ErrSealed", err)
	}

	shares, err := manager.Initialize(ctx, 5, 3)
	if err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}

	if _, err := service.Put(ctx, "prod", "payment-api", plaintext, secret.Absent()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}

	value, err := service.Get(ctx, "prod", "payment-api", 0)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !bytes.Equal(value.Data, plaintext) {
		t.Fatalf("Get() = %q, want %q", string(value.Data), plaintext)
	}

	manager.Seal()

	if _, err := service.Get(ctx, "prod", "payment-api", 0); !errors.Is(err, seal.ErrSealed) {
		t.Fatalf("reading a sealed store = %v, want ErrSealed", err)
	}
	if _, err := service.Metadata(ctx, "prod", "payment-api"); err != nil {
		t.Errorf("metadata should stay readable while sealed, got %v", err)
	}

	for _, share := range []crypto.Sensitive{shares[3], shares[0], shares[4]} {
		if _, err := manager.Unseal(ctx, share); err != nil {
			t.Fatalf("Unseal returned error: %v", err)
		}
	}

	reopened, err := service.Get(ctx, "prod", "payment-api", 0)
	if err != nil {
		t.Fatalf("Get after unsealing returned error: %v", err)
	}
	if !bytes.Equal(reopened.Data, plaintext) {
		t.Errorf("Get() after unsealing = %q, want %q", string(reopened.Data), plaintext)
	}
}
