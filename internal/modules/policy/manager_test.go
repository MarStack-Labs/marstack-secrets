package policy

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

func newTestManager(t *testing.T) (*Manager, *sql.DB) {
	t.Helper()

	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "marsec.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	at := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	manager, err := NewManager(db, Options{Now: func() time.Time { return at }})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if err := manager.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	return manager, db
}

func identityOf(id, tenant string) authn.Identity {
	return authn.Identity{ID: id, Kind: authn.KindInstance, Tenant: tenant}
}

func stored(t *testing.T, manager *Manager, tenant string, policy Policy) {
	t.Helper()
	if err := manager.Put(t.Context(), tenant, policy); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	manager, _ := newTestManager(t)
	original := must(t, "reader", rule("secret/prod/*", authz.Read, authz.List))

	stored(t, manager, "prod", original)

	read, err := manager.Get(t.Context(), "prod", "reader")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if read.Name != "reader" || len(read.Rules) != 1 {
		t.Fatalf("Get() = %+v", read)
	}
	if read.Rules[0].Path != "secret/prod/*" || len(read.Rules[0].Capabilities) != 2 {
		t.Errorf("rules = %+v", read.Rules)
	}
}

func TestPutOverwritesAndListReports(t *testing.T) {
	manager, _ := newTestManager(t)

	stored(t, manager, "prod", must(t, "reader", rule("secret/prod/*", authz.Read)))
	stored(t, manager, "prod", must(t, "reader", rule("secret/prod/*", authz.Read, authz.Write)))
	stored(t, manager, "prod", must(t, "writer", rule("secret/prod/x", authz.Write)))
	stored(t, manager, "staging", must(t, "reader", rule("secret/staging/*", authz.Read)))

	names, err := manager.List(t.Context(), "prod")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if strings.Join(names, ",") != "reader,writer" {
		t.Errorf("List() = %v, want reader and writer", names)
	}

	updated, err := manager.Get(t.Context(), "prod", "reader")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if len(updated.Rules[0].Capabilities) != 2 {
		t.Error("the overwrite did not take effect")
	}
}

func TestTenantsDoNotSeeEachOthersPolicies(t *testing.T) {
	manager, _ := newTestManager(t)
	stored(t, manager, "prod", must(t, "reader", rule("secret/prod/*", authz.Read)))

	if _, err := manager.Get(t.Context(), "staging", "reader"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get across tenants = %v, want ErrNotFound", err)
	}
	names, err := manager.List(t.Context(), "staging")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("List() = %v, want nothing", names)
	}
}

func TestDeleteRemovesThePolicyAndItsBindings(t *testing.T) {
	manager, _ := newTestManager(t)
	stored(t, manager, "prod", must(t, "reader", rule("secret/prod/*", authz.Read)))

	if err := manager.Bind(t.Context(), "prod", "instance/web-01", "reader"); err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}
	if err := manager.Delete(t.Context(), "prod", "reader"); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}

	bound, err := manager.BindingsFor(t.Context(), "prod", "instance/web-01")
	if err != nil {
		t.Fatalf("BindingsFor returned error: %v", err)
	}
	if len(bound) != 0 {
		t.Errorf("BindingsFor() = %v, want the binding to have gone with the policy", bound)
	}
	if err := manager.Delete(t.Context(), "prod", "reader"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a repeated Delete = %v, want ErrNotFound", err)
	}
}

func TestBindRequiresAnExistingPolicy(t *testing.T) {
	manager, _ := newTestManager(t)

	if err := manager.Bind(t.Context(), "prod", "instance/web-01", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Bind = %v, want ErrNotFound", err)
	}
	if err := manager.Bind(t.Context(), "prod", "", "ghost"); !errors.Is(err, ErrEmptyIdentity) {
		t.Errorf("Bind without an identity = %v, want ErrEmptyIdentity", err)
	}
}

func TestBindIsIdempotentAndUnbindReverses(t *testing.T) {
	manager, _ := newTestManager(t)
	stored(t, manager, "prod", must(t, "reader", rule("secret/prod/*", authz.Read)))

	for range 3 {
		if err := manager.Bind(t.Context(), "prod", "instance/web-01", "reader"); err != nil {
			t.Fatalf("Bind returned error: %v", err)
		}
	}
	bound, err := manager.BindingsFor(t.Context(), "prod", "instance/web-01")
	if err != nil {
		t.Fatalf("BindingsFor returned error: %v", err)
	}
	if len(bound) != 1 {
		t.Fatalf("BindingsFor() = %v, want one binding", bound)
	}

	if err := manager.Unbind(t.Context(), "prod", "instance/web-01", "reader"); err != nil {
		t.Fatalf("Unbind returned error: %v", err)
	}
	if err := manager.Unbind(t.Context(), "prod", "instance/web-01", "reader"); err != nil {
		t.Fatalf("a repeated Unbind returned error: %v", err)
	}
	bound, err = manager.BindingsFor(t.Context(), "prod", "instance/web-01")
	if err != nil {
		t.Fatalf("BindingsFor returned error: %v", err)
	}
	if len(bound) != 0 {
		t.Errorf("BindingsFor() = %v, want nothing", bound)
	}
}

func TestAuthorizeUsesTheBoundPolicies(t *testing.T) {
	manager, _ := newTestManager(t)
	identity := identityOf("instance/web-01", "prod")

	stored(t, manager, "prod", must(t, "reader", rule("secret/prod/*", authz.Read)))

	decision, err := manager.Authorize(t.Context(), identity, "prod", "secret/prod/db", authz.Read)
	if err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
	if decision.Allowed {
		t.Fatal("an unbound policy was applied")
	}

	if err := manager.Bind(t.Context(), "prod", identity.ID, "reader"); err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}

	decision, err = manager.Authorize(t.Context(), identity, "prod", "secret/prod/db", authz.Read)
	if err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("read was denied after binding: %s", decision.Reason)
	}
	if decision.Policy != "reader" {
		t.Errorf("policy = %q, want reader", decision.Policy)
	}
}

func TestTenantIsolationCannotBeGrantedByPolicy(t *testing.T) {
	manager, _ := newTestManager(t)
	identity := identityOf("instance/web-01", "prod")

	stored(t, manager, "prod", must(t, "overreach", rule("*", authz.Read, authz.Write)))
	if err := manager.Bind(t.Context(), "prod", identity.ID, "overreach"); err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}

	decision, err := manager.Authorize(t.Context(), identity, "staging", "secret/staging/db", authz.Read)
	if err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
	if decision.Allowed {
		t.Fatal("a store-wide policy reached into another tenant")
	}
	if !strings.Contains(decision.Reason, "another tenant") {
		t.Errorf("reason = %q", decision.Reason)
	}
}

func TestAnIdentityWithoutATenantIsRefused(t *testing.T) {
	manager, _ := newTestManager(t)

	decision, err := manager.Authorize(t.Context(), authn.Identity{ID: "ghost"}, "prod", "secret/prod/db", authz.Read)
	if err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
	if decision.Allowed {
		t.Fatal("an identity with no tenant was authorized")
	}
}

func TestBindingsAreScopedToTheirTenant(t *testing.T) {
	manager, _ := newTestManager(t)

	stored(t, manager, "prod", must(t, "reader", rule("secret/prod/*", authz.Read)))
	stored(t, manager, "staging", must(t, "reader", rule("secret/staging/*", authz.Read, authz.Write)))

	if err := manager.Bind(t.Context(), "staging", "instance/web-01", "reader"); err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}

	decision, err := manager.Authorize(t.Context(), identityOf("instance/web-01", "prod"), "prod", "secret/prod/db", authz.Read)
	if err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
	if decision.Allowed {
		t.Fatal("a binding made in another tenant took effect here")
	}
}

func TestTooManyBindingsIsRefused(t *testing.T) {
	manager, _ := newTestManager(t)

	for index := range maxBoundPolicies + 1 {
		name := "policy-" + strings.Repeat("x", index%3) + string(rune('a'+index%26)) + string(rune('a'+index/26))
		stored(t, manager, "prod", must(t, name, rule("secret/prod/*", authz.Read)))
		err := manager.Bind(t.Context(), "prod", "instance/web-01", name)
		if index < maxBoundPolicies {
			if err != nil {
				t.Fatalf("Bind %d returned error: %v", index, err)
			}
			continue
		}
		if !errors.Is(err, ErrTooManyBound) {
			t.Fatalf("Bind past the limit = %v, want ErrTooManyBound", err)
		}
	}
}

func TestACorruptStoredPolicyIsRefusedRatherThanTrusted(t *testing.T) {
	manager, db := newTestManager(t)
	stored(t, manager, "prod", must(t, "reader", rule("secret/prod/*", authz.Read)))

	if _, err := db.ExecContext(t.Context(),
		`UPDATE policy_definitions SET rules = ? WHERE tenant = 'prod' AND name = 'reader'`,
		`[{"Path":"secret/../etc/*","Capabilities":["read"]}]`); err != nil {
		t.Fatalf("editing the stored policy: %v", err)
	}

	if _, err := manager.Get(t.Context(), "prod", "reader"); !errors.Is(err, ErrStoredCorrupt) {
		t.Fatalf("Get = %v, want ErrStoredCorrupt", err)
	}

	if err := manager.Bind(t.Context(), "prod", "instance/web-01", "reader"); !errors.Is(err, ErrStoredCorrupt) {
		t.Errorf("Bind on a corrupt policy = %v, want ErrStoredCorrupt", err)
	}
}

func TestPutRejectsUnusableInput(t *testing.T) {
	manager, _ := newTestManager(t)

	if err := manager.Put(t.Context(), "", must(t, "reader", rule("secret/prod/*", authz.Read))); !errors.Is(err, ErrInvalidTenant) {
		t.Errorf("Put without a tenant = %v, want ErrInvalidTenant", err)
	}
	if err := manager.Put(t.Context(), "prod", Policy{Name: "broken"}); !errors.Is(err, ErrNoRules) {
		t.Errorf("Put with no rules = %v, want ErrNoRules", err)
	}
	if err := manager.Put(t.Context(), "prod", Policy{
		Name:  "traversal",
		Rules: []Rule{rule("secret/../etc/*", authz.Read)},
	}); !errors.Is(err, ErrTraversal) {
		t.Errorf("Put with a traversal = %v, want ErrTraversal", err)
	}
}

func TestNewManagerRequiresADatabase(t *testing.T) {
	if _, err := NewManager(nil, Options{}); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("NewManager = %v, want ErrNoDatabase", err)
	}
}
