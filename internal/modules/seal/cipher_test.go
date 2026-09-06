package seal

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

func location(tenant string) crypto.AAD {
	return crypto.AAD{Tenant: tenant, Path: "payment-api", Version: 1}
}

func TestCipherRoundTrips(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()
	ctx := t.Context()
	plaintext := []byte("db_password=s3cr3t")

	envelope, err := cipher.Seal(ctx, "prod", plaintext, location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	if envelope.KEKVersion != initialKEKVersion {
		t.Errorf("KEKVersion = %d, want %d", envelope.KEKVersion, initialKEKVersion)
	}
	if bytes.Contains(envelope.Ciphertext, plaintext) {
		t.Fatal("the plaintext appears in the ciphertext")
	}

	opened, err := cipher.Open(ctx, "prod", envelope, location("prod"))
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("Open() = %q, want %q", string(opened), plaintext)
	}
}

func TestASealedStoreCannotEncryptOrDecrypt(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()
	ctx := t.Context()

	envelope, err := cipher.Seal(ctx, "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	manager.Seal()

	if _, err := cipher.Seal(ctx, "prod", []byte("value"), location("prod")); !errors.Is(err, ErrSealed) {
		t.Errorf("Seal while sealed = %v, want ErrSealed", err)
	}
	if _, err := cipher.Open(ctx, "prod", envelope, location("prod")); !errors.Is(err, ErrSealed) {
		t.Errorf("Open while sealed = %v, want ErrSealed", err)
	}
}

func TestValuesSurviveASealAndUnsealCycle(t *testing.T) {
	manager, shares, path := initialized(t)
	ctx := t.Context()
	plaintext := []byte("db_password=s3cr3t")

	envelope, err := manager.Cipher().Seal(ctx, "prod", plaintext, location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	restarted, _ := newManagerAt(t, path)
	for _, share := range shares[:3] {
		if _, err := restarted.Unseal(ctx, share); err != nil {
			t.Fatalf("Unseal returned error: %v", err)
		}
	}

	opened, err := restarted.Cipher().Open(ctx, "prod", envelope, location("prod"))
	if err != nil {
		t.Fatalf("Open after a restart returned error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("Open() = %q, want %q", string(opened), plaintext)
	}
}

func TestTenantsGetDifferentKeys(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()
	ctx := t.Context()

	envelope, err := cipher.Seal(ctx, "prod", []byte("prod value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	if _, err := cipher.Open(ctx, "staging", envelope, location("prod")); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("opening a prod value as staging = %v, want ErrDecrypt", err)
	}
}

func TestOpenRejectsAnUnknownKeyVersion(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()
	ctx := t.Context()

	envelope, err := cipher.Seal(ctx, "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	envelope.KEKVersion = 2
	if _, err := cipher.Open(ctx, "prod", envelope, location("prod")); !errors.Is(err, crypto.ErrDecrypt) {
		t.Errorf("Open with a rotated key version = %v, want ErrDecrypt", err)
	}

	envelope.KEKVersion = 0
	if _, err := cipher.Open(ctx, "prod", envelope, location("prod")); !errors.Is(err, crypto.ErrDecrypt) {
		t.Errorf("Open with a zero key version = %v, want ErrDecrypt", err)
	}
}

func TestCipherIsSafeUnderConcurrentUse(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()
	ctx := t.Context()
	plaintext := []byte("db_password=s3cr3t")

	var group sync.WaitGroup
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 16 {
				envelope, err := cipher.Seal(ctx, "prod", plaintext, location("prod"))
				if err != nil {
					t.Errorf("worker %d: Seal returned error: %v", worker, err)
					return
				}
				opened, err := cipher.Open(ctx, "prod", envelope, location("prod"))
				if err != nil {
					t.Errorf("worker %d: Open returned error: %v", worker, err)
					return
				}
				if !bytes.Equal(opened, plaintext) {
					t.Errorf("worker %d: round trip lost the value", worker)
					return
				}
			}
		}()
	}
	group.Wait()
}
