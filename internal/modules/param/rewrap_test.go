package param

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

func testCipher(t *testing.T, store *Store) *staticCipher {
	t.Helper()

	cipher, ok := store.cipher.(*staticCipher)
	if !ok {
		t.Fatalf("the store holds a %T rather than the test cipher", store.cipher)
	}
	return cipher
}

func storedRow(t *testing.T, store *Store, tenant, path string) (crypto.Envelope, string, string) {
	t.Helper()

	var envelope crypto.Envelope
	var updatedAt, updatedBy string
	if err := store.db.QueryRowContext(t.Context(),
		`SELECT kek_version, wrapped_dek, ciphertext, updated_at, updated_by
		 FROM param_values WHERE tenant = ? AND path = ?`,
		tenant, path,
	).Scan(&envelope.KEKVersion, &envelope.WrappedDEK, &envelope.Ciphertext, &updatedAt, &updatedBy); err != nil {
		t.Fatalf("reading the stored parameter: %v", err)
	}
	return envelope, updatedAt, updatedBy
}

func TestRewrapMovesEveryParameterForward(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "app/log_level", KindString, "info")
	put(t, store, "app/replicas", KindInt, "3")
	if err := store.Put(t.Context(), "staging", "app/log_level", KindString, "debug", "ci"); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}

	testCipher(t, store).kekVersion = 2

	progress, err := store.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	if progress.Examined != 3 || progress.Rewrapped != 3 {
		t.Errorf("Rewrap() = %+v, want three examined and three rewrapped", progress)
	}

	for _, location := range [][2]string{
		{"prod", "app/log_level"},
		{"prod", "app/replicas"},
		{"staging", "app/log_level"},
	} {
		envelope, _, _ := storedRow(t, store, location[0], location[1])
		if envelope.KEKVersion != 2 {
			t.Errorf("%s/%s is still at version %d", location[0], location[1], envelope.KEKVersion)
		}
	}
}

func newTestStoreOnAMovingClock(t *testing.T) *Store {
	t.Helper()

	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "marsec.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	kek, err := crypto.NewKey()
	if err != nil {
		t.Fatalf("NewKey returned error: %v", err)
	}

	at := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ticking := func() time.Time {
		at = at.Add(time.Minute)
		return at
	}

	store, err := NewStore(db, &staticCipher{kek: kek, kekVersion: 1}, Options{Now: ticking})
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	return store
}

func TestRewrapIsNotAnEdit(t *testing.T) {
	store := newTestStoreOnAMovingClock(t)
	put(t, store, "app/log_level", KindString, "info")

	before, updatedAt, updatedBy := storedRow(t, store, "prod", "app/log_level")

	testCipher(t, store).kekVersion = 2
	if _, err := store.Rewrap(t.Context()); err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	after, laterAt, laterBy := storedRow(t, store, "prod", "app/log_level")

	if laterAt != updatedAt {
		t.Errorf("updated_at moved from %q to %q; rotating a key is not a change of value", updatedAt, laterAt)
	}
	if laterBy != updatedBy {
		t.Errorf("updated_by moved from %q to %q; the rotation took the author's name", updatedBy, laterBy)
	}
	if !bytes.Equal(after.Ciphertext, before.Ciphertext) {
		t.Error("the stored ciphertext changed, so the value was re-encrypted rather than rewrapped")
	}
	if bytes.Equal(after.WrappedDEK, before.WrappedDEK) {
		t.Error("the stored wrapped data key did not change")
	}
}

func TestRewrapLeavesParametersReadable(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "app/log_level", KindString, "info")
	put(t, store, "app/replicas", KindInt, "3")

	testCipher(t, store).kekVersion = 2
	if _, err := store.Rewrap(t.Context()); err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}

	for path, want := range map[string]string{"app/log_level": "info", "app/replicas": "3"} {
		found, err := store.Get(t.Context(), "prod", path)
		if err != nil {
			t.Fatalf("Get(%q) returned error: %v", path, err)
		}
		if found.Value != want {
			t.Errorf("Get(%q) = %q, want %q", path, found.Value, want)
		}
	}
}

func TestRewrapOfParametersIsIdempotent(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "app/log_level", KindString, "info")
	testCipher(t, store).kekVersion = 2

	first, err := store.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("first Rewrap returned error: %v", err)
	}
	second, err := store.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("second Rewrap returned error: %v", err)
	}

	if first.Rewrapped != 1 {
		t.Errorf("first Rewrap moved %d parameters, want 1", first.Rewrapped)
	}
	if second.Rewrapped != 0 || second.Examined != 1 {
		t.Errorf("second Rewrap = %+v, want one examined and none moved", second)
	}
}

func TestRewrapOfParametersWalksPastABatchBoundary(t *testing.T) {
	store := newTestStore(t)
	total := rewrapBatch + 7
	for index := range total {
		put(t, store, fmt.Sprintf("app/setting-%03d", index), KindString, "value")
	}

	testCipher(t, store).kekVersion = 2
	progress, err := store.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	if progress.Examined != total || progress.Rewrapped != total {
		t.Fatalf("Rewrap() = %+v, want %d examined and rewrapped", progress, total)
	}

	envelope, _, _ := storedRow(t, store, "prod", fmt.Sprintf("app/setting-%03d", total-1))
	if envelope.KEKVersion != 2 {
		t.Errorf("the last parameter stopped at version %d, so the cursor did not advance", envelope.KEKVersion)
	}
}

func TestRewrapOfParametersStopsAtTheFirstFailure(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "app/log_level", KindString, "info")

	failure := errors.New("the cipher is unavailable")
	cipher := testCipher(t, store)
	cipher.kekVersion = 2
	cipher.rewrapErr = failure

	if _, err := store.Rewrap(t.Context()); !errors.Is(err, failure) {
		t.Fatalf("Rewrap = %v, want the cipher failure", err)
	}

	cipher.rewrapErr = nil
	resumed, err := store.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("Rewrap after the failure returned error: %v", err)
	}
	if resumed.Rewrapped != 1 {
		t.Errorf("the resumed Rewrap moved %d parameters, want 1", resumed.Rewrapped)
	}
}

func TestRewrapOfParametersStopsWhenTheContextIsCancelled(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "app/log_level", KindString, "info")
	testCipher(t, store).kekVersion = 2

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := store.Rewrap(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Rewrap with a cancelled context = %v, want context.Canceled", err)
	}
}
