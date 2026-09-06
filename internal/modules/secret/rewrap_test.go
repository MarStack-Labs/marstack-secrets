package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

func writeVersions(t *testing.T, service *Service, tenant, path string, count int) {
	t.Helper()

	for index := range count {
		if _, err := service.Put(t.Context(), tenant, path,
			[]byte(fmt.Sprintf("value-%d", index)), Any()); err != nil {
			t.Fatalf("Put returned error: %v", err)
		}
	}
}

func storedKEKVersions(t *testing.T, service *Service) map[string]int {
	t.Helper()

	rows, err := service.store.db.QueryContext(t.Context(),
		`SELECT tenant, path, version, kek_version FROM secret_versions ORDER BY tenant, path, version`)
	if err != nil {
		t.Fatalf("reading the stored key encryption key versions: %v", err)
	}
	defer func() { _ = rows.Close() }()

	found := map[string]int{}
	for rows.Next() {
		var tenant, path string
		var version, kekVersion int
		if err := rows.Scan(&tenant, &path, &version, &kekVersion); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		found[fmt.Sprintf("%s/%s@%d", tenant, path, version)] = kekVersion
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating: %v", err)
	}
	return found
}

func TestRewrapMovesEveryReadableVersionForward(t *testing.T) {
	service, cipher, _ := newTestService(t)
	writeVersions(t, service, "prod", "payment-api", 3)
	writeVersions(t, service, "prod", "billing-api", 2)
	writeVersions(t, service, "staging", "payment-api", 1)

	cipher.kekVersion = 2

	progress, err := service.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	if progress.Examined != 6 || progress.Rewrapped != 6 {
		t.Errorf("Rewrap() = %+v, want six examined and six rewrapped", progress)
	}

	for location, version := range storedKEKVersions(t, service) {
		if version != 2 {
			t.Errorf("%s is still at key encryption key version %d", location, version)
		}
	}
}

func storedEnvelope(t *testing.T, service *Service, tenant, path string, version int) crypto.Envelope {
	t.Helper()

	var envelope crypto.Envelope
	if err := service.store.db.QueryRowContext(t.Context(),
		`SELECT kek_version, wrapped_dek, ciphertext FROM secret_versions
		 WHERE tenant = ? AND path = ? AND version = ?`,
		tenant, path, version,
	).Scan(&envelope.KEKVersion, &envelope.WrappedDEK, &envelope.Ciphertext); err != nil {
		t.Fatalf("reading the stored envelope: %v", err)
	}
	return envelope
}

func TestRewrapReplacesTheWrappedKeyAndNothingElse(t *testing.T) {
	service, cipher, _ := newTestService(t)
	ctx := t.Context()
	plaintext := []byte("db_password=s3cr3t")

	if _, err := service.Put(ctx, "prod", "payment-api", plaintext, Any()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	before := storedEnvelope(t, service, "prod", "payment-api", 1)

	cipher.kekVersion = 2
	if _, err := service.Rewrap(ctx); err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	after := storedEnvelope(t, service, "prod", "payment-api", 1)

	if !bytes.Equal(after.Ciphertext, before.Ciphertext) {
		t.Error("the stored ciphertext changed, so the payload was re-encrypted rather than rewrapped")
	}
	if bytes.Equal(after.WrappedDEK, before.WrappedDEK) {
		t.Error("the stored wrapped data key did not change")
	}

	value, err := service.Get(ctx, "prod", "payment-api", 0)
	if err != nil {
		t.Fatalf("Get after Rewrap returned error: %v", err)
	}
	if !bytes.Equal(value.Data, plaintext) {
		t.Errorf("Get() = %q, want %q", string(value.Data), plaintext)
	}
}

func TestRewrapIsIdempotent(t *testing.T) {
	service, cipher, _ := newTestService(t)
	writeVersions(t, service, "prod", "payment-api", 2)
	cipher.kekVersion = 2

	first, err := service.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("first Rewrap returned error: %v", err)
	}
	second, err := service.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("second Rewrap returned error: %v", err)
	}

	if first.Rewrapped != 2 {
		t.Errorf("first Rewrap rewrapped %d, want 2", first.Rewrapped)
	}
	if second.Rewrapped != 0 {
		t.Errorf("second Rewrap rewrapped %d, want 0 with nothing left behind", second.Rewrapped)
	}
	if second.Examined != 2 {
		t.Errorf("second Rewrap examined %d, want 2", second.Examined)
	}
}

func TestRewrapSkipsDestroyedVersions(t *testing.T) {
	service, cipher, _ := newTestService(t)
	ctx := t.Context()
	writeVersions(t, service, "prod", "payment-api", 3)

	if err := service.Destroy(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Destroy returned error: %v", err)
	}

	cipher.kekVersion = 2
	progress, err := service.Rewrap(ctx)
	if err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	if progress.Examined != 2 {
		t.Errorf("Rewrap examined %d versions, want 2 with one destroyed", progress.Examined)
	}

	stored := storedKEKVersions(t, service)
	if got := stored["prod/payment-api@1"]; got != 1 {
		t.Errorf("a destroyed version moved to key encryption key version %d", got)
	}
}

func TestRewrapCoversASoftDeletedVersion(t *testing.T) {
	service, cipher, _ := newTestService(t)
	ctx := t.Context()
	writeVersions(t, service, "prod", "payment-api", 2)

	if err := service.Delete(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}

	cipher.kekVersion = 2
	if _, err := service.Rewrap(ctx); err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	if got := storedKEKVersions(t, service)["prod/payment-api@1"]; got != 2 {
		t.Errorf("a deleted version stayed at key encryption key version %d; undelete would leave it behind", got)
	}

	if err := service.Undelete(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Undelete returned error: %v", err)
	}
	if _, err := service.Get(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Get after Undelete returned error: %v", err)
	}
}

func TestRewrapWalksPastABatchBoundary(t *testing.T) {
	service, cipher, _ := newTestService(t)
	total := rewrapBatch + 7

	store, err := NewStore(service.store.db, Options{MaxVersions: total, Now: service.store.now})
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	roomy, err := NewService(store, cipher)
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	writeVersions(t, roomy, "prod", "payment-api", total)

	cipher.kekVersion = 2
	progress, err := roomy.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	if progress.Examined != total || progress.Rewrapped != total {
		t.Fatalf("Rewrap() = %+v, want %d examined and rewrapped", progress, total)
	}

	for location, version := range storedKEKVersions(t, roomy) {
		if version != 2 {
			t.Errorf("%s stopped at key encryption key version %d, so the cursor did not advance", location, version)
		}
	}
}

func TestRewrapStopsAtTheFirstFailureWithoutLosingWhatItDid(t *testing.T) {
	service, cipher, _ := newTestService(t)
	writeVersions(t, service, "prod", "payment-api", 3)

	failure := errors.New("the cipher is unavailable")
	cipher.kekVersion = 2
	cipher.rewrapErr = failure

	progress, err := service.Rewrap(t.Context())
	if !errors.Is(err, failure) {
		t.Fatalf("Rewrap = %v, want the cipher failure", err)
	}
	if progress.Rewrapped != 0 {
		t.Errorf("Rewrap reported %d rewrapped despite failing on the first one", progress.Rewrapped)
	}

	cipher.rewrapErr = nil
	resumed, err := service.Rewrap(t.Context())
	if err != nil {
		t.Fatalf("Rewrap after the failure returned error: %v", err)
	}
	if resumed.Rewrapped != 3 {
		t.Errorf("the resumed Rewrap moved %d versions, want all 3", resumed.Rewrapped)
	}
}

func TestRewrapRequiresARewrapper(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	if _, err := store.Rewrap(t.Context(), nil); !errors.Is(err, ErrNoRewrapper) {
		t.Fatalf("Rewrap without a rewrapper = %v, want ErrNoRewrapper", err)
	}
}

func TestRewrapStopsWhenTheContextIsCancelled(t *testing.T) {
	service, cipher, _ := newTestService(t)
	writeVersions(t, service, "prod", "payment-api", 3)
	cipher.kekVersion = 2

	ctx, cancel := context.WithCancel(t.Context())
	_, err := service.store.Rewrap(ctx, func(tenant, path string, version int, envelope crypto.Envelope) (crypto.Envelope, bool, error) {
		cancel()
		return envelope, false, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Rewrap after cancellation = %v, want context.Canceled", err)
	}
}
