package param

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

type staticCipher struct {
	kek        crypto.Key
	kekVersion int
	rewrapErr  error
}

func (c *staticCipher) Seal(_ context.Context, _ string, plaintext []byte, aad crypto.AAD) (crypto.Envelope, error) {
	return crypto.Seal(c.kek, c.kekVersion, plaintext, aad)
}

func (c *staticCipher) Open(_ context.Context, _ string, envelope crypto.Envelope, aad crypto.AAD) (crypto.Sensitive, error) {
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

func newTestStore(t *testing.T) *Store {
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
	store, err := NewStore(db, &staticCipher{kek: kek, kekVersion: 1}, Options{Now: func() time.Time { return at }})
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	return store
}

func put(t *testing.T, store *Store, path string, kind Kind, raw string) {
	t.Helper()
	if err := store.Put(t.Context(), "prod", path, kind, raw, "service/ci"); err != nil {
		t.Fatalf("Put(%q) returned error: %v", path, err)
	}
}

func TestAParameterRoundTrips(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "app/log_level", KindString, "info")

	found, err := store.Get(t.Context(), "prod", "app/log_level")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if found.Value != "info" || found.Kind != KindString {
		t.Errorf("Get() = %+v", found)
	}
	if found.UpdatedBy != "service/ci" || found.UpdatedAt.IsZero() {
		t.Errorf("the parameter records no author or time: %+v", found)
	}
	if found.Inherited() {
		t.Error("an exact match should not report itself inherited")
	}
}

func TestPutOverwritesInPlace(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "app/replicas", KindInt, "3")
	put(t, store, "app/replicas", KindInt, "5")

	found, err := store.Get(t.Context(), "prod", "app/replicas")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if found.Value != "5" {
		t.Errorf("Value = %q, want the later write", found.Value)
	}
}

func TestKindsAreValidatedOnWrite(t *testing.T) {
	store := newTestStore(t)

	accepted := map[Kind][]string{
		KindString:     {"info", "", "anything at all"},
		KindInt:        {"3", "-7", " 42 "},
		KindBool:       {"true", "false", "1", "0", "TRUE"},
		KindStringList: {"a", "a,b,c", "a, b , c"},
	}
	for kind, values := range accepted {
		for _, raw := range values {
			if err := store.Put(t.Context(), "prod", "app/ok", kind, raw, "ci"); err != nil {
				t.Errorf("%s rejected %q: %v", kind, raw, err)
			}
		}
	}

	refused := map[Kind][]string{
		KindInt:        {"three", "3.5", "", "3 apples"},
		KindBool:       {"yes", "maybe", ""},
		KindStringList: {"", "a,,b", "a, ,b"},
	}
	for kind, values := range refused {
		for _, raw := range values {
			if err := store.Put(t.Context(), "prod", "app/bad", kind, raw, "ci"); !errors.Is(err, ErrInvalidValue) {
				t.Errorf("%s accepted %q: %v", kind, raw, err)
			}
		}
	}

	if err := store.Put(t.Context(), "prod", "app/bad", Kind("duration"), "5s", "ci"); !errors.Is(err, ErrInvalidKind) {
		t.Errorf("an unknown kind = %v, want ErrInvalidKind", err)
	}
}

func TestInheritanceWalksUpTowardsTheTenantRoot(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "log_level", KindString, "warn")
	put(t, store, "apps/payment/log_level", KindString, "debug")

	cases := map[string]struct {
		requested string
		value     string
		from      string
	}{
		"exact match":        {requested: "apps/payment/log_level", value: "debug", from: "apps/payment/log_level"},
		"one level up":       {requested: "apps/billing/log_level", value: "warn", from: "log_level"},
		"straight to root":   {requested: "log_level", value: "warn", from: "log_level"},
		"deeply nested miss": {requested: "apps/a/b/c/log_level", value: "warn", from: "log_level"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			found, err := store.Resolve(t.Context(), "prod", tc.requested)
			if err != nil {
				t.Fatalf("Resolve returned error: %v", err)
			}
			if found.Value != tc.value {
				t.Errorf("Value = %q, want %q", found.Value, tc.value)
			}
			if found.ResolvedFrom != tc.from {
				t.Errorf("ResolvedFrom = %q, want %q", found.ResolvedFrom, tc.from)
			}
			if found.Path != tc.requested {
				t.Errorf("Path = %q, want the requested path", found.Path)
			}
		})
	}
}

func TestTheNearestDefinitionWins(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "log_level", KindString, "root")
	put(t, store, "apps/log_level", KindString, "apps")
	put(t, store, "apps/payment/log_level", KindString, "payment")

	found, err := store.Resolve(t.Context(), "prod", "apps/payment/log_level")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if found.Value != "payment" {
		t.Errorf("Value = %q, want the nearest definition", found.Value)
	}

	found, err = store.Resolve(t.Context(), "prod", "apps/billing/log_level")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if found.Value != "apps" {
		t.Errorf("Value = %q, want the middle definition", found.Value)
	}
}

func TestInheritanceNeverLeavesTheTenant(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "log_level", KindString, "prod default")

	if err := store.Put(t.Context(), "staging", "log_level", KindString, "staging default", "ci"); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}

	found, err := store.Resolve(t.Context(), "staging", "apps/payment/log_level")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if found.Value != "staging default" {
		t.Errorf("Value = %q, want the tenant's own default", found.Value)
	}

	if _, err := store.Resolve(t.Context(), "other", "apps/payment/log_level"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a tenant with nothing defined resolved to %v", err)
	}
}

func TestResolveReportsNothingWhenNothingMatches(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "apps/payment/log_level", KindString, "debug")

	if _, err := store.Resolve(t.Context(), "prod", "apps/payment/replicas"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Resolve = %v, want ErrNotFound", err)
	}
	if _, err := store.Get(t.Context(), "prod", "apps/billing/log_level"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get followed the inheritance chain: %v", err)
	}
}

func TestListReportsWhatIsStoredUnderAPrefix(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "apps/payment/log_level", KindString, "debug")
	put(t, store, "apps/payment/replicas", KindInt, "3")
	put(t, store, "apps/billing/log_level", KindString, "info")
	put(t, store, "log_level", KindString, "warn")

	found, err := store.List(t.Context(), "prod", "apps/payment/")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("List() returned %d entries, want 2: %+v", len(found), found)
	}
	for _, entry := range found {
		if entry.Value != "" {
			t.Errorf("List returned a value for %q; listing should not decrypt", entry.Path)
		}
	}

	all, err := store.List(t.Context(), "prod", "")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(all) != 4 {
		t.Errorf("List() with no prefix returned %d entries, want 4", len(all))
	}
}

func TestDeleteRemovesOneParameter(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "log_level", KindString, "warn")
	put(t, store, "apps/payment/log_level", KindString, "debug")

	if err := store.Delete(t.Context(), "prod", "apps/payment/log_level"); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if err := store.Delete(t.Context(), "prod", "apps/payment/log_level"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a repeated Delete = %v, want ErrNotFound", err)
	}

	found, err := store.Resolve(t.Context(), "prod", "apps/payment/log_level")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if found.Value != "warn" {
		t.Errorf("after deleting the override, Value = %q, want the inherited default", found.Value)
	}
}

func TestAValueIsEncryptedAtRest(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "app/log_level", KindString, "a recognisable parameter value")

	var ciphertext []byte
	if err := store.db.QueryRowContext(t.Context(),
		`SELECT ciphertext FROM param_values WHERE tenant = 'prod' AND path = 'app/log_level'`).
		Scan(&ciphertext); err != nil {
		t.Fatalf("reading the stored row: %v", err)
	}
	if strings.Contains(string(ciphertext), "recognisable") {
		t.Fatal("the parameter is stored in the clear")
	}
}

func TestAValueMovedToAnotherPathDoesNotOpen(t *testing.T) {
	store := newTestStore(t)
	put(t, store, "apps/payment/log_level", KindString, "debug")
	put(t, store, "apps/billing/log_level", KindString, "info")

	if _, err := store.db.ExecContext(t.Context(), `
		UPDATE param_values SET
			wrapped_dek = (SELECT wrapped_dek FROM param_values WHERE path = 'apps/billing/log_level'),
			ciphertext  = (SELECT ciphertext  FROM param_values WHERE path = 'apps/billing/log_level')
		WHERE path = 'apps/payment/log_level'`); err != nil {
		t.Fatalf("swapping the rows: %v", err)
	}

	if _, err := store.Get(t.Context(), "prod", "apps/payment/log_level"); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("Get on a moved value = %v, want ErrDecrypt", err)
	}
}

func TestPathsAreValidated(t *testing.T) {
	store := newTestStore(t)

	for name, path := range map[string]string{
		"empty":        "",
		"absolute":     "/app/log_level",
		"traversal":    "app/../../etc/passwd",
		"double slash": "app//log_level",
		"dot":          "app/./log_level",
		"padded":       "app/ log_level",
		"too long":     strings.Repeat("a", maxPathLen+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.Put(t.Context(), "prod", path, KindString, "x", "ci"); !errors.Is(err, ErrInvalidPath) {
				t.Errorf("Put = %v, want ErrInvalidPath", err)
			}
			if _, err := store.Resolve(t.Context(), "prod", path); !errors.Is(err, ErrInvalidPath) {
				t.Errorf("Resolve = %v, want ErrInvalidPath", err)
			}
		})
	}

	if err := store.Put(t.Context(), "", "app/log_level", KindString, "x", "ci"); !errors.Is(err, ErrInvalidTenant) {
		t.Errorf("Put without a tenant = %v, want ErrInvalidTenant", err)
	}
	if err := store.Put(t.Context(), "prod", "app/big", KindString, strings.Repeat("x", maxValueBytes+1), "ci"); !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("Put with an oversized value = %v, want ErrValueTooLarge", err)
	}
}

func TestNewStoreRequiresItsCollaborators(t *testing.T) {
	if _, err := NewStore(nil, &staticCipher{}, Options{}); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("NewStore without a database = %v, want ErrNoDatabase", err)
	}

	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "marsec.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := NewStore(db, nil, Options{}); !errors.Is(err, ErrNoCipher) {
		t.Errorf("NewStore without a cipher = %v, want ErrNoCipher", err)
	}
}

func TestTheInheritanceChainIsWhatItLooksLike(t *testing.T) {
	cases := map[string][]string{
		"apps/payment/log_level": {"apps/payment/log_level", "apps/log_level", "log_level"},
		"apps/log_level":         {"apps/log_level", "log_level"},
		"log_level":              {"log_level"},
		"a/b/c/d/key":            {"a/b/c/d/key", "a/b/c/key", "a/b/key", "a/key", "key"},
	}
	for path, want := range cases {
		t.Run(path, func(t *testing.T) {
			got := inheritanceChain(path)
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("inheritanceChain(%q) = %v, want %v", path, got, want)
			}
		})
	}
}
