package auth

import (
	"bytes"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

type clock struct {
	at time.Time
}

func (c *clock) now() time.Time {
	return c.at
}

func (c *clock) advance(by time.Duration) {
	c.at = c.at.Add(by)
}

func newTestManager(t *testing.T) (*Manager, *clock, *sql.DB) {
	t.Helper()

	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "marsec.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	tick := &clock{at: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	manager, err := NewManager(db, Options{Now: tick.now})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if err := manager.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	return manager, tick, db
}

func registered(t *testing.T, manager *Manager, id string, kind Kind) Identity {
	t.Helper()
	identity, err := manager.RegisterIdentity(t.Context(), id, kind, "prod")
	if err != nil {
		t.Fatalf("RegisterIdentity returned error: %v", err)
	}
	return identity
}

func issued(t *testing.T, manager *Manager, identityID, binding string) Token {
	t.Helper()
	token, err := manager.Issue(t.Context(), identityID, binding, DefaultTTL)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	return token
}

func TestRegisterAndReadAnIdentity(t *testing.T) {
	manager, _, _ := newTestManager(t)

	created := registered(t, manager, "instance/web-01", KindInstance)
	if created.Kind != KindInstance || created.Tenant != "prod" || created.Disabled {
		t.Fatalf("RegisterIdentity returned %+v", created)
	}

	read, err := manager.Identity(t.Context(), "instance/web-01")
	if err != nil {
		t.Fatalf("Identity returned error: %v", err)
	}
	if read.ID != created.ID || read.Kind != created.Kind || !read.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("Identity() = %+v, want %+v", read, created)
	}

	if _, err := manager.Identity(t.Context(), "instance/unknown"); !errors.Is(err, ErrUnknownIdentity) {
		t.Errorf("Identity for an unknown id = %v, want ErrUnknownIdentity", err)
	}
}

func TestRegisterRejectsDuplicatesAndBadInput(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)

	if _, err := manager.RegisterIdentity(t.Context(), "instance/web-01", KindInstance, "prod"); !errors.Is(err, ErrIdentityExists) {
		t.Errorf("a duplicate registration = %v, want ErrIdentityExists", err)
	}

	cases := map[string]struct {
		id     string
		kind   Kind
		tenant string
		want   error
	}{
		"empty id":     {id: "", kind: KindInstance, tenant: "prod", want: ErrInvalidIdentity},
		"long id":      {id: strings.Repeat("a", maxIdentityLen+1), kind: KindInstance, tenant: "prod", want: ErrInvalidIdentity},
		"unknown kind": {id: "instance/web-02", kind: Kind("robot"), tenant: "prod", want: ErrInvalidKind},
		"empty kind":   {id: "instance/web-02", kind: Kind(""), tenant: "prod", want: ErrInvalidKind},
		"empty tenant": {id: "instance/web-02", kind: KindInstance, tenant: "", want: ErrInvalidTenant},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := manager.RegisterIdentity(t.Context(), tc.id, tc.kind, tc.tenant); !errors.Is(err, tc.want) {
				t.Fatalf("RegisterIdentity = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIssueAndAuthenticate(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)

	token := issued(t, manager, "instance/web-01", NoBinding)
	if !strings.HasPrefix(string(token.Value), tokenPrefix) {
		t.Errorf("token %q does not carry the prefix", string(token.Value))
	}
	if len(token.Value) < minTokenLength {
		t.Errorf("token is %d bytes, want at least %d", len(token.Value), minTokenLength)
	}

	identity, err := manager.Authenticate(t.Context(), token.Value, NoBinding)
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if identity.ID != "instance/web-01" || identity.Tenant != "prod" || identity.Kind != KindInstance {
		t.Errorf("Authenticate() = %+v", identity)
	}
}

func TestTokensAreStoredOnlyAsAFingerprint(t *testing.T) {
	manager, _, db := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)
	token := issued(t, manager, "instance/web-01", NoBinding)

	var stored []byte
	if err := db.QueryRowContext(t.Context(), `SELECT id_hash FROM auth_tokens`).Scan(&stored); err != nil {
		t.Fatalf("reading the stored token: %v", err)
	}

	if bytes.Contains(stored, token.Value) {
		t.Fatal("the token itself is in the database")
	}
	if !bytes.Equal(stored, fingerprint(token.Value)) {
		t.Error("the stored value is not the fingerprint of the token")
	}
	if len(stored) != 32 {
		t.Errorf("fingerprint is %d bytes, want 32", len(stored))
	}
}

func TestEveryFailureLooksTheSame(t *testing.T) {
	manager, tick, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)
	registered(t, manager, "instance/web-02", KindInstance)

	expired := issued(t, manager, "instance/web-01", NoBinding)
	revoked := issued(t, manager, "instance/web-01", NoBinding)
	bound := issued(t, manager, "instance/web-01", "web-01")
	disabled := issued(t, manager, "instance/web-02", NoBinding)

	if err := manager.Revoke(t.Context(), revoked.Value); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if err := manager.DisableIdentity(t.Context(), "instance/web-02"); err != nil {
		t.Fatalf("DisableIdentity returned error: %v", err)
	}
	tick.advance(2 * DefaultTTL)

	cases := map[string]struct {
		token   crypto.Sensitive
		binding string
	}{
		"expired":             {token: expired.Value, binding: NoBinding},
		"revoked":             {token: revoked.Value, binding: NoBinding},
		"wrong binding":       {token: bound.Value, binding: "web-99"},
		"missing binding":     {token: bound.Value, binding: NoBinding},
		"disabled identity":   {token: disabled.Value, binding: NoBinding},
		"never issued":        {token: crypto.Sensitive(tokenPrefix + strings.Repeat("A", 43)), binding: NoBinding},
		"wrong prefix":        {token: crypto.Sensitive("ghp_" + strings.Repeat("A", 43)), binding: NoBinding},
		"far too short":       {token: crypto.Sensitive("mss_short"), binding: NoBinding},
		"empty":               {token: nil, binding: NoBinding},
		"looks like a bearer": {token: crypto.Sensitive("Bearer mss_aaaa"), binding: NoBinding},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			identity, err := manager.Authenticate(t.Context(), tc.token, tc.binding)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Authenticate = %v, want ErrUnauthenticated", err)
			}
			if identity != (Identity{}) {
				t.Errorf("Authenticate returned %+v alongside the error", identity)
			}
		})
	}
}

func TestABoundTokenOnlyWorksAtItsBinding(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)
	token := issued(t, manager, "instance/web-01", "web-01")

	if _, err := manager.Authenticate(t.Context(), token.Value, "web-01"); err != nil {
		t.Fatalf("Authenticate at the right binding returned error: %v", err)
	}
	if _, err := manager.Authenticate(t.Context(), token.Value, "web-02"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Authenticate at another binding = %v, want ErrUnauthenticated", err)
	}
}

func TestATokenExpiresExactlyAtItsDeadline(t *testing.T) {
	manager, tick, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)
	token := issued(t, manager, "instance/web-01", NoBinding)

	tick.advance(DefaultTTL - time.Nanosecond)
	if _, err := manager.Authenticate(t.Context(), token.Value, NoBinding); err != nil {
		t.Fatalf("Authenticate just before expiry returned error: %v", err)
	}

	tick.advance(time.Nanosecond)
	if _, err := manager.Authenticate(t.Context(), token.Value, NoBinding); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Authenticate at the deadline = %v, want ErrUnauthenticated", err)
	}
}

func TestRevokeIdentityKillsEveryToken(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)
	registered(t, manager, "instance/web-02", KindInstance)

	first := issued(t, manager, "instance/web-01", NoBinding)
	second := issued(t, manager, "instance/web-01", NoBinding)
	other := issued(t, manager, "instance/web-02", NoBinding)

	count, err := manager.RevokeIdentity(t.Context(), "instance/web-01")
	if err != nil {
		t.Fatalf("RevokeIdentity returned error: %v", err)
	}
	if count != 2 {
		t.Errorf("RevokeIdentity revoked %d tokens, want 2", count)
	}

	for name, token := range map[string]Token{"first": first, "second": second} {
		if _, err := manager.Authenticate(t.Context(), token.Value, NoBinding); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("the %s token still authenticates: %v", name, err)
		}
	}
	if _, err := manager.Authenticate(t.Context(), other.Value, NoBinding); err != nil {
		t.Errorf("another identity's token was revoked too: %v", err)
	}
}

func TestIssueRejectsBadInput(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)

	if _, err := manager.Issue(t.Context(), "instance/unknown", NoBinding, DefaultTTL); !errors.Is(err, ErrUnknownIdentity) {
		t.Errorf("Issue for an unknown identity = %v, want ErrUnknownIdentity", err)
	}
	for name, ttl := range map[string]time.Duration{
		"zero":         0,
		"negative":     -time.Hour,
		"beyond limit": MaximumTTL + time.Second,
	} {
		if _, err := manager.Issue(t.Context(), "instance/web-01", NoBinding, ttl); !errors.Is(err, ErrInvalidTTL) {
			t.Errorf("Issue with a %s ttl = %v, want ErrInvalidTTL", name, err)
		}
	}

	if err := manager.DisableIdentity(t.Context(), "instance/web-01"); err != nil {
		t.Fatalf("DisableIdentity returned error: %v", err)
	}
	if _, err := manager.Issue(t.Context(), "instance/web-01", NoBinding, DefaultTTL); !errors.Is(err, ErrIdentityDisabled) {
		t.Errorf("Issue for a disabled identity = %v, want ErrIdentityDisabled", err)
	}
}

func TestDisableIdentityReportsUnknownIdentities(t *testing.T) {
	manager, _, _ := newTestManager(t)

	if err := manager.DisableIdentity(t.Context(), "instance/unknown"); !errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("DisableIdentity = %v, want ErrUnknownIdentity", err)
	}

	registered(t, manager, "instance/web-01", KindInstance)
	for range 2 {
		if err := manager.DisableIdentity(t.Context(), "instance/web-01"); err != nil {
			t.Fatalf("DisableIdentity returned error: %v", err)
		}
	}
}

func TestIssuedTokensAreUnique(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)

	seen := make(map[string]struct{})
	for range 64 {
		token := issued(t, manager, "instance/web-01", NoBinding)
		seen[string(token.Value)] = struct{}{}
	}
	if len(seen) != 64 {
		t.Fatalf("got %d distinct tokens out of 64", len(seen))
	}
}

func TestPurgeExpiredRemovesOnlyExpiredTokens(t *testing.T) {
	manager, tick, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)

	short := issued(t, manager, "instance/web-01", NoBinding)
	long, err := manager.Issue(t.Context(), "instance/web-01", NoBinding, 10*DefaultTTL)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	tick.advance(2 * DefaultTTL)
	removed, err := manager.PurgeExpired(t.Context())
	if err != nil {
		t.Fatalf("PurgeExpired returned error: %v", err)
	}
	if removed != 1 {
		t.Errorf("PurgeExpired removed %d tokens, want 1", removed)
	}

	if _, err := manager.Authenticate(t.Context(), short.Value, NoBinding); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the purged token still authenticates: %v", err)
	}
	if _, err := manager.Authenticate(t.Context(), long.Value, NoBinding); err != nil {
		t.Errorf("the surviving token no longer authenticates: %v", err)
	}
}

func TestNewManagerRequiresADatabase(t *testing.T) {
	if _, err := NewManager(nil, Options{}); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("NewManager = %v, want ErrNoDatabase", err)
	}
}

func TestTokenValueIsRedacted(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindInstance)
	token := issued(t, manager, "instance/web-01", NoBinding)

	if rendered := token.Value.String(); strings.Contains(rendered, tokenPrefix) {
		t.Errorf("the token renders as %q", rendered)
	}
}
