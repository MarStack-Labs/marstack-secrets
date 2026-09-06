package secret

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

type staticCipher struct {
	kek        crypto.Key
	kekVersion int
	sealErr    error
	openErr    error
	rewrapErr  error
}

func (c *staticCipher) Seal(_ context.Context, _ string, plaintext []byte, aad crypto.AAD) (crypto.Envelope, error) {
	if c.sealErr != nil {
		return crypto.Envelope{}, c.sealErr
	}
	return crypto.Seal(c.kek, c.kekVersion, plaintext, aad)
}

func (c *staticCipher) Open(_ context.Context, _ string, envelope crypto.Envelope, aad crypto.AAD) (crypto.Sensitive, error) {
	if c.openErr != nil {
		return nil, c.openErr
	}
	plaintext, err := crypto.Open(c.kek, envelope, aad)
	if err != nil {
		return nil, err
	}
	return crypto.Sensitive(plaintext), nil
}

func (c *staticCipher) Rewrap(_ context.Context, _ string, envelope crypto.Envelope, aad crypto.AAD) (crypto.Envelope, bool, error) {
	if c.rewrapErr != nil {
		return crypto.Envelope{}, false, c.rewrapErr
	}
	if envelope.KEKVersion == c.kekVersion {
		return envelope, false, nil
	}
	rewrapped, err := crypto.Rewrap(c.kek, c.kek, c.kekVersion, envelope, aad)
	if err != nil {
		return crypto.Envelope{}, false, err
	}
	return rewrapped, true, nil
}

func newTestService(t *testing.T) (*Service, *staticCipher, *sql.DB) {
	t.Helper()

	store, db := newTestStore(t, Options{})
	kek, err := crypto.NewKey()
	if err != nil {
		t.Fatalf("NewKey returned error: %v", err)
	}
	cipher := &staticCipher{kek: kek, kekVersion: 1}

	service, err := NewService(store, cipher)
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	return service, cipher, db
}

func TestServiceRoundTripsAPlaintext(t *testing.T) {
	service, _, _ := newTestService(t)
	ctx := t.Context()
	plaintext := []byte("db_password=s3cr3t")

	version, err := service.Put(ctx, "prod", "payment-api", plaintext, Absent())
	if err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if version != 1 {
		t.Errorf("Put returned version %d, want 1", version)
	}

	value, err := service.Get(ctx, "prod", "payment-api", currentVersion)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !bytes.Equal(value.Data, plaintext) {
		t.Errorf("Data = %q, want %q", string(value.Data), plaintext)
	}
	if value.Tenant != "prod" || value.Path != "payment-api" || value.Version != 1 {
		t.Errorf("Value = %+v, want the location it was written to", value)
	}
	if value.CreatedAt.IsZero() {
		t.Error("CreatedAt was not populated")
	}
}

func TestServiceKeepsEveryVersionReadable(t *testing.T) {
	service, _, _ := newTestService(t)
	ctx := t.Context()

	for _, plaintext := range []string{"first", "second", "third"} {
		if _, err := service.Put(ctx, "prod", "payment-api", []byte(plaintext), Any()); err != nil {
			t.Fatalf("Put returned error: %v", err)
		}
	}

	for version, want := range map[int]string{1: "first", 2: "second", 3: "third"} {
		value, err := service.Get(ctx, "prod", "payment-api", version)
		if err != nil {
			t.Fatalf("Get on version %d returned error: %v", version, err)
		}
		if string(value.Data) != want {
			t.Errorf("version %d = %q, want %q", version, string(value.Data), want)
		}
	}
}

func TestServiceNeverWritesAPlaintext(t *testing.T) {
	service, _, db := newTestService(t)
	ctx := t.Context()
	plaintext := []byte("db_password=s3cr3t")

	if _, err := service.Put(ctx, "prod", "payment-api", plaintext, Absent()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}

	rows, err := db.QueryContext(ctx, `SELECT wrapped_dek, ciphertext FROM secret_versions`)
	if err != nil {
		t.Fatalf("reading stored rows: %v", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var wrappedDEK, ciphertext []byte
		if err := rows.Scan(&wrappedDEK, &ciphertext); err != nil {
			t.Fatalf("scanning a row: %v", err)
		}
		if bytes.Contains(ciphertext, plaintext) || bytes.Contains(wrappedDEK, plaintext) {
			t.Fatal("the plaintext reached the database")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating rows: %v", err)
	}
}

func TestAValueMovedToAnotherPathDoesNotOpen(t *testing.T) {
	service, _, db := newTestService(t)
	ctx := t.Context()

	if _, err := service.Put(ctx, "prod", "payment-api", []byte("payment secret"), Absent()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if _, err := service.Put(ctx, "prod", "billing-api", []byte("billing secret"), Absent()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		UPDATE secret_versions SET
			wrapped_dek = (SELECT wrapped_dek FROM secret_versions WHERE path = 'billing-api' AND version = 1),
			ciphertext  = (SELECT ciphertext  FROM secret_versions WHERE path = 'billing-api' AND version = 1)
		WHERE path = 'payment-api' AND version = 1`); err != nil {
		t.Fatalf("swapping the stored rows: %v", err)
	}

	if _, err := service.Get(ctx, "prod", "payment-api", 1); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("Get on a moved value = %v, want ErrDecrypt", err)
	}
}

func TestAValueRolledBackToAnOlderVersionDoesNotOpen(t *testing.T) {
	service, _, db := newTestService(t)
	ctx := t.Context()

	for _, plaintext := range []string{"old value", "new value"} {
		if _, err := service.Put(ctx, "prod", "payment-api", []byte(plaintext), Any()); err != nil {
			t.Fatalf("Put returned error: %v", err)
		}
	}

	if _, err := db.ExecContext(ctx, `
		UPDATE secret_versions SET
			wrapped_dek = (SELECT wrapped_dek FROM secret_versions WHERE version = 1),
			ciphertext  = (SELECT ciphertext  FROM secret_versions WHERE version = 1)
		WHERE version = 2`); err != nil {
		t.Fatalf("rolling the stored row back: %v", err)
	}

	if _, err := service.Get(ctx, "prod", "payment-api", 2); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("Get on a rolled back value = %v, want ErrDecrypt", err)
	}
}

func TestServiceReportsCipherFailures(t *testing.T) {
	service, cipher, _ := newTestService(t)
	ctx := t.Context()

	sealFailed := errors.New("the key is unavailable")
	cipher.sealErr = sealFailed
	if _, err := service.Put(ctx, "prod", "payment-api", []byte("value"), Absent()); !errors.Is(err, sealFailed) {
		t.Fatalf("Put = %v, want the seal error", err)
	}
	if _, err := service.Metadata(ctx, "prod", "payment-api"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a failed seal left something behind: %v", err)
	}

	cipher.sealErr = nil
	if _, err := service.Put(ctx, "prod", "payment-api", []byte("value"), Absent()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}

	openFailed := errors.New("the store is sealed")
	cipher.openErr = openFailed
	if _, err := service.Get(ctx, "prod", "payment-api", currentVersion); !errors.Is(err, openFailed) {
		t.Fatalf("Get = %v, want the open error", err)
	}
}

func TestServiceDelegatesTheLifecycle(t *testing.T) {
	service, _, _ := newTestService(t)
	ctx := t.Context()

	if _, err := service.Put(ctx, "prod", "payment-api", []byte("value"), Absent()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}

	if err := service.Delete(ctx, "prod", "payment-api"); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if _, err := service.Get(ctx, "prod", "payment-api", currentVersion); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Get after Delete = %v, want ErrDeleted", err)
	}

	if err := service.Undelete(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Undelete returned error: %v", err)
	}
	if _, err := service.Get(ctx, "prod", "payment-api", currentVersion); err != nil {
		t.Fatalf("Get after Undelete returned error: %v", err)
	}

	metadata, err := service.Metadata(ctx, "prod", "payment-api")
	if err != nil {
		t.Fatalf("Metadata returned error: %v", err)
	}
	if metadata.CurrentVersion != 1 {
		t.Errorf("CurrentVersion = %d, want 1", metadata.CurrentVersion)
	}

	if err := service.Destroy(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Destroy returned error: %v", err)
	}
	if _, err := service.Get(ctx, "prod", "payment-api", 1); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("Get after Destroy = %v, want ErrDestroyed", err)
	}
}

func TestServiceValidatesItsLocation(t *testing.T) {
	service, _, _ := newTestService(t)
	ctx := t.Context()

	if _, err := service.Put(ctx, "", "payment-api", []byte("value"), Any()); !errors.Is(err, ErrInvalidTenant) {
		t.Errorf("Put with an empty tenant = %v, want ErrInvalidTenant", err)
	}
	if _, err := service.Get(ctx, "prod", "", currentVersion); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("Get with an empty path = %v, want ErrInvalidPath", err)
	}
}

func TestNewServiceRequiresItsCollaborators(t *testing.T) {
	store, _ := newTestStore(t, Options{})

	if _, err := NewService(nil, &staticCipher{}); !errors.Is(err, ErrNoStore) {
		t.Errorf("NewService without a store = %v, want ErrNoStore", err)
	}
	if _, err := NewService(store, nil); !errors.Is(err, ErrNoCipher) {
		t.Errorf("NewService without a cipher = %v, want ErrNoCipher", err)
	}
}

func TestAValueDoesNotPrintItsPlaintext(t *testing.T) {
	service, _, _ := newTestService(t)
	ctx := t.Context()
	plaintext := "db_password=s3cr3t"

	if _, err := service.Put(ctx, "prod", "payment-api", []byte(plaintext), Absent()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	value, err := service.Get(ctx, "prod", "payment-api", currentVersion)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}

	for name, rendering := range map[string]string{
		"%v":  fmt.Sprintf("%v", value),
		"%+v": fmt.Sprintf("%+v", value),
		"%#v": fmt.Sprintf("%#v", value),
	} {
		if bytes.Contains([]byte(rendering), []byte(plaintext)) {
			t.Errorf("%s leaked the plaintext: %s", name, rendering)
		}
	}
}
