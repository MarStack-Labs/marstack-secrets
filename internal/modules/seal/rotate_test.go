package seal

import (
	"bytes"
	"errors"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

func rotateOnce(t *testing.T, manager *Manager) Rotation {
	t.Helper()

	rotation, err := manager.Rotate(t.Context())
	if err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}
	return rotation
}

func TestRotateAdvancesTheVersionAndNewWritesFollowIt(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()

	before, err := cipher.Seal(t.Context(), "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	rotation := rotateOnce(t, manager)
	if rotation.From != 1 || rotation.To != 2 {
		t.Errorf("Rotate() = %+v, want a move from 1 to 2", rotation)
	}

	after, err := cipher.Seal(t.Context(), "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal after rotation returned error: %v", err)
	}
	if before.KEKVersion != 1 {
		t.Errorf("the earlier envelope moved to version %d on its own", before.KEKVersion)
	}
	if after.KEKVersion != 2 {
		t.Errorf("KEKVersion after rotation = %d, want 2", after.KEKVersion)
	}
	if got := statusOf(t, manager).KEKVersion; got != 2 {
		t.Errorf("Status reported KEKVersion = %d, want 2", got)
	}
}

func TestRotateCanBeRepeated(t *testing.T) {
	manager, _, _ := initialized(t)

	for want := 2; want <= 4; want++ {
		if got := rotateOnce(t, manager).To; got != want {
			t.Fatalf("Rotate() moved to %d, want %d", got, want)
		}
	}
}

func TestRotationSurvivesARestart(t *testing.T) {
	manager, shares, path := initialized(t)
	rotateOnce(t, manager)
	rotateOnce(t, manager)

	restarted := reopened(t, path, shares, 3)
	if got := statusOf(t, restarted).KEKVersion; got != 3 {
		t.Fatalf("KEKVersion after a restart = %d, want 3", got)
	}

	envelope, err := restarted.Cipher().Seal(t.Context(), "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	if envelope.KEKVersion != 3 {
		t.Errorf("a write after a restart used version %d, want 3", envelope.KEKVersion)
	}
}

func TestRotateRefusesWhenTheStoreCannotReachTheRootKey(t *testing.T) {
	sealed, _, _ := initialized(t)
	sealed.Seal()
	if _, err := sealed.Rotate(t.Context()); !errors.Is(err, ErrSealed) {
		t.Errorf("Rotate on a sealed store = %v, want ErrSealed", err)
	}

	fresh, _ := newManager(t)
	if _, err := fresh.Rotate(t.Context()); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Rotate on an uninitialized store = %v, want ErrNotInitialized", err)
	}
}

func TestARotationThatCannotBeRecordedIsNotAppliedInMemory(t *testing.T) {
	manager, _, path := initialized(t)
	setStoredKEKVersion(t, path, 5)

	if _, err := manager.Rotate(t.Context()); err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}
	if got := statusOf(t, manager).KEKVersion; got != 6 {
		t.Fatalf("KEKVersion = %d, want 6 read back from the row rather than from memory", got)
	}

	envelope, err := manager.Cipher().Seal(t.Context(), "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	if envelope.KEKVersion != 6 {
		t.Errorf("a write after rotation used version %d, want 6", envelope.KEKVersion)
	}
}

func TestRewrapMovesAValueToTheCurrentVersionWithoutReEncrypting(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()
	ctx := t.Context()
	plaintext := []byte("db_password=s3cr3t")

	envelope, err := cipher.Seal(ctx, "prod", plaintext, location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	ciphertext := bytes.Clone(envelope.Ciphertext)
	wrapped := bytes.Clone(envelope.WrappedDEK)

	rotateOnce(t, manager)

	rewrapped, changed, err := cipher.Rewrap(ctx, "prod", envelope, location("prod"))
	if err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	if !changed {
		t.Fatal("Rewrap reported no change after a rotation")
	}
	if rewrapped.KEKVersion != 2 {
		t.Errorf("KEKVersion = %d, want 2", rewrapped.KEKVersion)
	}
	if !bytes.Equal(rewrapped.Ciphertext, ciphertext) {
		t.Error("Rewrap re-encrypted the payload instead of only rewrapping the data key")
	}
	if bytes.Equal(rewrapped.WrappedDEK, wrapped) {
		t.Error("Rewrap left the wrapped data key untouched")
	}

	opened, err := cipher.Open(ctx, "prod", rewrapped, location("prod"))
	if err != nil {
		t.Fatalf("Open after Rewrap returned error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("Open() = %q, want %q", string(opened), plaintext)
	}
}

func TestRewrapIsAnIdentityAtTheCurrentVersion(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()
	ctx := t.Context()

	envelope, err := cipher.Seal(ctx, "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	rewrapped, changed, err := cipher.Rewrap(ctx, "prod", envelope, location("prod"))
	if err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}
	if changed {
		t.Error("Rewrap reported a change for a value already at the current version")
	}
	if !bytes.Equal(rewrapped.WrappedDEK, envelope.WrappedDEK) {
		t.Error("Rewrap rewrapped a value that did not need it")
	}
}

func TestRewrapRefusesWhatItCannotOrShouldNotTouch(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()
	ctx := t.Context()

	envelope, err := cipher.Seal(ctx, "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	ahead := envelope
	ahead.KEKVersion = 9
	if _, _, err := cipher.Rewrap(ctx, "prod", ahead, location("prod")); !errors.Is(err, ErrKEKVersion) {
		t.Errorf("Rewrap of an envelope ahead of the store = %v, want ErrKEKVersion", err)
	}

	unversioned := envelope
	unversioned.KEKVersion = 0
	if _, _, err := cipher.Rewrap(ctx, "prod", unversioned, location("prod")); !errors.Is(err, crypto.ErrDecrypt) {
		t.Errorf("Rewrap of an unversioned envelope = %v, want ErrDecrypt", err)
	}

	manager.Seal()
	if _, _, err := cipher.Rewrap(ctx, "prod", envelope, location("prod")); !errors.Is(err, ErrSealed) {
		t.Errorf("Rewrap on a sealed store = %v, want ErrSealed", err)
	}
}

func TestRewrapRejectsAValueMovedToAnotherLocation(t *testing.T) {
	manager, _, _ := initialized(t)
	cipher := manager.Cipher()
	ctx := t.Context()

	envelope, err := cipher.Seal(ctx, "prod", []byte("value"), location("prod"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	rotateOnce(t, manager)

	elsewhere := location("prod")
	elsewhere.Path = "other-api"
	if _, _, err := cipher.Rewrap(ctx, "prod", envelope, elsewhere); !errors.Is(err, crypto.ErrDecrypt) {
		t.Errorf("Rewrap with the wrong associated data = %v, want ErrDecrypt", err)
	}
}
