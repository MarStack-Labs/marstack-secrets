package secret

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

type clock struct {
	at time.Time
}

func (c *clock) now() time.Time {
	c.at = c.at.Add(time.Second)
	return c.at
}

func newTestStore(t *testing.T, opts Options) (*Store, *sql.DB) {
	t.Helper()

	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "marsec.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if opts.Now == nil {
		opts.Now = (&clock{at: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)}).now
	}
	store, err := NewStore(db, opts)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	return store, db
}

func envelopeFor(marker byte) crypto.Envelope {
	return crypto.Envelope{
		KEKVersion: 1,
		WrappedDEK: []byte{marker, marker},
		Ciphertext: []byte{marker, marker, marker},
	}
}

func put(t *testing.T, store *Store, tenant, path string, marker byte) int {
	t.Helper()
	version, err := store.Put(t.Context(), tenant, path, envelopeFor(marker), Any())
	if err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	return version
}

func TestPutCreatesConsecutiveVersions(t *testing.T) {
	store, _ := newTestStore(t, Options{})

	for want := 1; want <= 3; want++ {
		if got := put(t, store, "prod", "payment-api", byte(want)); got != want {
			t.Fatalf("Put returned version %d, want %d", got, want)
		}
	}
}

func TestGetReturnsTheCurrentVersionByDefault(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	put(t, store, "prod", "payment-api", 1)
	put(t, store, "prod", "payment-api", 2)

	record, err := store.Get(t.Context(), "prod", "payment-api", currentVersion)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if record.Version != 2 {
		t.Errorf("Version = %d, want 2", record.Version)
	}
	if !bytes.Equal(record.Envelope.Ciphertext, envelopeFor(2).Ciphertext) {
		t.Errorf("Ciphertext = %v, want the second write", record.Envelope.Ciphertext)
	}
	if record.CreatedAt.IsZero() {
		t.Error("CreatedAt was not populated")
	}
}

func TestGetReturnsAnOlderVersion(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	put(t, store, "prod", "payment-api", 1)
	put(t, store, "prod", "payment-api", 2)

	record, err := store.Get(t.Context(), "prod", "payment-api", 1)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !bytes.Equal(record.Envelope.Ciphertext, envelopeFor(1).Ciphertext) {
		t.Errorf("Ciphertext = %v, want the first write", record.Envelope.Ciphertext)
	}
}

func TestGetReportsMissingPathsAndVersions(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	put(t, store, "prod", "payment-api", 1)

	if _, err := store.Get(t.Context(), "prod", "unknown", currentVersion); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get on an unknown path = %v, want ErrNotFound", err)
	}
	if _, err := store.Get(t.Context(), "prod", "payment-api", 99); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get on an unknown version = %v, want ErrNotFound", err)
	}
}

func TestTenantsAreIsolated(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	put(t, store, "prod", "payment-api", 1)
	put(t, store, "staging", "payment-api", 9)

	prod, err := store.Get(t.Context(), "prod", "payment-api", currentVersion)
	if err != nil {
		t.Fatalf("Get for prod returned error: %v", err)
	}
	staging, err := store.Get(t.Context(), "staging", "payment-api", currentVersion)
	if err != nil {
		t.Fatalf("Get for staging returned error: %v", err)
	}

	if prod.Version != 1 || staging.Version != 1 {
		t.Errorf("versions = %d and %d, want each tenant to start at 1", prod.Version, staging.Version)
	}
	if bytes.Equal(prod.Envelope.Ciphertext, staging.Envelope.Ciphertext) {
		t.Fatal("tenants share the same stored value")
	}
}

func TestPutHonoursCheckAndSet(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	ctx := t.Context()

	if _, err := store.Put(ctx, "prod", "payment-api", envelopeFor(1), Absent()); err != nil {
		t.Fatalf("Put with Absent on a new path returned error: %v", err)
	}
	if _, err := store.Put(ctx, "prod", "payment-api", envelopeFor(2), Absent()); !errors.Is(err, ErrConflict) {
		t.Errorf("Put with Absent on an existing path = %v, want ErrConflict", err)
	}
	if _, err := store.Put(ctx, "prod", "payment-api", envelopeFor(2), AtVersion(1)); err != nil {
		t.Fatalf("Put with AtVersion(1) returned error: %v", err)
	}
	if _, err := store.Put(ctx, "prod", "payment-api", envelopeFor(3), AtVersion(1)); !errors.Is(err, ErrConflict) {
		t.Errorf("Put with a stale expectation = %v, want ErrConflict", err)
	}
}

func TestAConflictingPutChangesNothing(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	ctx := t.Context()
	put(t, store, "prod", "payment-api", 1)

	if _, err := store.Put(ctx, "prod", "payment-api", envelopeFor(9), AtVersion(7)); !errors.Is(err, ErrConflict) {
		t.Fatalf("Put = %v, want ErrConflict", err)
	}

	record, err := store.Get(ctx, "prod", "payment-api", currentVersion)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if record.Version != 1 {
		t.Errorf("current version = %d, want it unchanged at 1", record.Version)
	}
	if !bytes.Equal(record.Envelope.Ciphertext, envelopeFor(1).Ciphertext) {
		t.Error("the rejected write reached the database")
	}
}

func TestDeleteAndUndelete(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	ctx := t.Context()
	put(t, store, "prod", "payment-api", 1)

	if err := store.Delete(ctx, "prod", "payment-api"); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if _, err := store.Get(ctx, "prod", "payment-api", currentVersion); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Get after Delete = %v, want ErrDeleted", err)
	}

	if err := store.Undelete(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Undelete returned error: %v", err)
	}
	record, err := store.Get(ctx, "prod", "payment-api", currentVersion)
	if err != nil {
		t.Fatalf("Get after Undelete returned error: %v", err)
	}
	if !bytes.Equal(record.Envelope.Ciphertext, envelopeFor(1).Ciphertext) {
		t.Error("the value did not survive delete and undelete")
	}
}

func TestDeleteAndDestroyAreIdempotent(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	ctx := t.Context()
	put(t, store, "prod", "payment-api", 1)

	for range 2 {
		if err := store.Delete(ctx, "prod", "payment-api", 1); err != nil {
			t.Fatalf("Delete returned error: %v", err)
		}
	}
	if err := store.Undelete(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Undelete returned error: %v", err)
	}
	if err := store.Undelete(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("second Undelete returned error: %v", err)
	}
	for range 2 {
		if err := store.Destroy(ctx, "prod", "payment-api", 1); err != nil {
			t.Fatalf("Destroy returned error: %v", err)
		}
	}
}

func TestDestroyErasesKeyMaterial(t *testing.T) {
	store, db := newTestStore(t, Options{})
	ctx := t.Context()
	put(t, store, "prod", "payment-api", 1)

	if err := store.Destroy(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Destroy returned error: %v", err)
	}

	var wrappedDEK, ciphertext []byte
	err := db.QueryRowContext(ctx,
		`SELECT wrapped_dek, ciphertext FROM secret_versions WHERE tenant = ? AND path = ? AND version = ?`,
		"prod", "payment-api", 1).Scan(&wrappedDEK, &ciphertext)
	if err != nil {
		t.Fatalf("reading the destroyed row: %v", err)
	}
	if len(wrappedDEK) != 0 || len(ciphertext) != 0 {
		t.Errorf("destroyed row still holds material: dek=%v ciphertext=%v", wrappedDEK, ciphertext)
	}

	if _, err := store.Get(ctx, "prod", "payment-api", 1); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Get on a destroyed version = %v, want ErrDestroyed", err)
	}
}

func TestDestroyedMaterialDoesNotLingerInTheDatabaseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marsec.db")
	ctx := context.Background()

	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	store, err := NewStore(db, Options{})
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}

	marker := bytes.Repeat([]byte{0x5A, 0xA5}, 512)
	if _, err := store.Put(ctx, "prod", "payment-api", crypto.Envelope{
		KEKVersion: 1,
		WrappedDEK: marker,
		Ciphertext: marker,
	}, Absent()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if err := store.Destroy(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Destroy returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpointing the write ahead log: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	for _, suffix := range []string{"", "-wal"} {
		contents, err := os.ReadFile(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("reading %s: %v", path+suffix, err)
		}
		if bytes.Contains(contents, marker) {
			t.Errorf("destroyed material is still present in %s", filepath.Base(path+suffix))
		}
	}
}

func TestADestroyedVersionCannotComeBack(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	ctx := t.Context()
	put(t, store, "prod", "payment-api", 1)

	if err := store.Destroy(ctx, "prod", "payment-api", 1); err != nil {
		t.Fatalf("Destroy returned error: %v", err)
	}
	if err := store.Undelete(ctx, "prod", "payment-api", 1); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Undelete on a destroyed version = %v, want ErrDestroyed", err)
	}
	if err := store.Delete(ctx, "prod", "payment-api", 1); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Delete on a destroyed version = %v, want ErrDestroyed", err)
	}
}

func TestMarkingReportsMissingVersions(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	ctx := t.Context()
	put(t, store, "prod", "payment-api", 1)

	for name, err := range map[string]error{
		"delete":   store.Delete(ctx, "prod", "payment-api", 42),
		"undelete": store.Undelete(ctx, "prod", "payment-api", 42),
		"destroy":  store.Destroy(ctx, "prod", "payment-api", 42),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s on a missing version = %v, want ErrNotFound", name, err)
		}
	}
	if err := store.Delete(ctx, "prod", "unknown"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete on an unknown path = %v, want ErrNotFound", err)
	}
}

func TestOldVersionsAreDestroyedOnceTheLimitIsPassed(t *testing.T) {
	store, _ := newTestStore(t, Options{MaxVersions: 3})
	ctx := t.Context()

	for marker := byte(1); marker <= 5; marker++ {
		put(t, store, "prod", "payment-api", marker)
	}

	for _, version := range []int{1, 2} {
		if _, err := store.Get(ctx, "prod", "payment-api", version); !errors.Is(err, ErrDestroyed) {
			t.Errorf("version %d = %v, want ErrDestroyed", version, err)
		}
	}
	for _, version := range []int{3, 4, 5} {
		if _, err := store.Get(ctx, "prod", "payment-api", version); err != nil {
			t.Errorf("version %d returned error: %v", version, err)
		}
	}
}

func TestMetadataTracksTheLifecycle(t *testing.T) {
	store, _ := newTestStore(t, Options{MaxVersions: 4})
	ctx := t.Context()
	put(t, store, "prod", "payment-api", 1)

	first, err := store.Metadata(ctx, "prod", "payment-api")
	if err != nil {
		t.Fatalf("Metadata returned error: %v", err)
	}
	if first.CurrentVersion != 1 || first.MaxVersions != 4 {
		t.Errorf("Metadata = %+v, want current version 1 and max versions 4", first)
	}
	if !first.CreatedAt.Equal(first.UpdatedAt) {
		t.Error("a freshly created path should have equal created and updated timestamps")
	}

	put(t, store, "prod", "payment-api", 2)
	second, err := store.Metadata(ctx, "prod", "payment-api")
	if err != nil {
		t.Fatalf("Metadata returned error: %v", err)
	}
	if second.CurrentVersion != 2 {
		t.Errorf("CurrentVersion = %d, want 2", second.CurrentVersion)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Error("CreatedAt moved on a later write")
	}
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Error("UpdatedAt did not move on a later write")
	}

	if _, err := store.Metadata(ctx, "prod", "unknown"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Metadata on an unknown path = %v, want ErrNotFound", err)
	}
}

func TestStoreRejectsInvalidLocations(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	ctx := t.Context()
	long := string(bytes.Repeat([]byte("a"), maxPathLen+1))

	cases := map[string]struct {
		tenant string
		path   string
		want   error
	}{
		"empty tenant": {tenant: "", path: "payment-api", want: ErrInvalidTenant},
		"long tenant":  {tenant: long, path: "payment-api", want: ErrInvalidTenant},
		"empty path":   {tenant: "prod", path: "", want: ErrInvalidPath},
		"long path":    {tenant: "prod", path: long, want: ErrInvalidPath},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Put(ctx, tc.tenant, tc.path, envelopeFor(1), Any()); !errors.Is(err, tc.want) {
				t.Errorf("Put = %v, want %v", err, tc.want)
			}
			if _, err := store.Get(ctx, tc.tenant, tc.path, currentVersion); !errors.Is(err, tc.want) {
				t.Errorf("Get = %v, want %v", err, tc.want)
			}
			if err := store.Delete(ctx, tc.tenant, tc.path); !errors.Is(err, tc.want) {
				t.Errorf("Delete = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestStoreRejectsNegativeAndZeroVersions(t *testing.T) {
	store, _ := newTestStore(t, Options{})
	ctx := t.Context()
	put(t, store, "prod", "payment-api", 1)

	if _, err := store.Get(ctx, "prod", "payment-api", -1); !errors.Is(err, ErrInvalidVersion) {
		t.Errorf("Get with a negative version = %v, want ErrInvalidVersion", err)
	}
	if err := store.Delete(ctx, "prod", "payment-api", 0); !errors.Is(err, ErrInvalidVersion) {
		t.Errorf("Delete with version zero = %v, want ErrInvalidVersion", err)
	}
}

func TestNewStoreRejectsNegativeMaxVersions(t *testing.T) {
	if _, err := NewStore(nil, Options{MaxVersions: -1}); !errors.Is(err, ErrMaxVersions) {
		t.Fatalf("NewStore = %v, want ErrMaxVersions", err)
	}
}

func TestStoreCarriesSealedValuesEndToEnd(t *testing.T) {
	store, db := newTestStore(t, Options{})
	ctx := t.Context()

	kek, err := crypto.NewKey()
	if err != nil {
		t.Fatalf("NewKey returned error: %v", err)
	}
	plaintext := []byte("db_password=s3cr3t")
	aad := crypto.AAD{Tenant: "prod", Path: "payment-api", Version: 1}

	sealed, err := crypto.Seal(kek, 1, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	if _, err := store.Put(ctx, "prod", "payment-api", sealed, Absent()); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}

	var stored []byte
	if err := db.QueryRowContext(ctx,
		`SELECT ciphertext FROM secret_versions WHERE tenant = ? AND path = ? AND version = 1`,
		"prod", "payment-api").Scan(&stored); err != nil {
		t.Fatalf("reading the stored row: %v", err)
	}
	if bytes.Contains(stored, plaintext) {
		t.Fatal("the plaintext reached the database")
	}

	record, err := store.Get(ctx, "prod", "payment-api", currentVersion)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	opened, err := crypto.Open(kek, record.Envelope, aad)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("Open() = %q, want %q", opened, plaintext)
	}
}

func TestStoreSurvivesReopening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marsec.db")
	ctx := context.Background()

	first, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	store, err := NewStore(first, Options{})
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	put(t, store, "prod", "payment-api", 7)
	if err := first.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	second, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopening the database: %v", err)
	}
	defer func() { _ = second.Close() }()

	reopened, err := NewStore(second, Options{})
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := reopened.Migrate(ctx); err != nil {
		t.Fatalf("Migrate after reopening returned error: %v", err)
	}

	record, err := reopened.Get(ctx, "prod", "payment-api", currentVersion)
	if err != nil {
		t.Fatalf("Get after reopening returned error: %v", err)
	}
	if !bytes.Equal(record.Envelope.Ciphertext, envelopeFor(7).Ciphertext) {
		t.Error("the stored value did not survive reopening")
	}
}
