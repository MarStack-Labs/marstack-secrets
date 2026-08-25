package lease

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"
)

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(by)
}

type revoker struct {
	mu      sync.Mutex
	calls   []string
	tokens  int
	failing error
}

func (r *revoker) RevokeIdentity(_ context.Context, identityID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failing != nil {
		return 0, r.failing
	}
	r.calls = append(r.calls, identityID)
	return r.tokens, nil
}

func (r *revoker) called() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.calls...)
}

func newTestManager(t *testing.T) (*Manager, *clock, *revoker) {
	t.Helper()

	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "marsec.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	tick := &clock{at: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	tokens := &revoker{tokens: 2}

	manager, err := NewManager(db, tokens, Options{Now: tick.now})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if err := manager.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
	return manager, tick, tokens
}

func issue(t *testing.T, manager *Manager, identityID, path string, version int) Lease {
	t.Helper()
	held, err := manager.Issue(t.Context(), "prod", identityID, path, version, DefaultTTL)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	return held
}

func TestAnIssuedLeaseRecordsTheHolding(t *testing.T) {
	manager, tick, _ := newTestManager(t)

	held := issue(t, manager, "instance/web-01", "secret/prod/payment-api", 3)
	if !strings.HasPrefix(held.ID, "secret/prod/payment-api/") {
		t.Errorf("id = %q, want it to name the path", held.ID)
	}
	if held.IdentityID != "instance/web-01" || held.Version != 3 {
		t.Errorf("lease = %+v", held)
	}
	if !held.ExpiresAt.Equal(tick.at.Add(DefaultTTL)) {
		t.Errorf("ExpiresAt = %v, want %v", held.ExpiresAt, tick.at.Add(DefaultTTL))
	}
}

func TestReadingTwiceReusesOneLease(t *testing.T) {
	manager, _, _ := newTestManager(t)

	first := issue(t, manager, "instance/web-01", "secret/prod/db", 1)
	for range 50 {
		issue(t, manager, "instance/web-01", "secret/prod/db", 1)
	}

	active, err := manager.Active(t.Context(), "prod", "instance/web-01")
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("fifty reads produced %d leases, want 1", len(active))
	}
	if active[0].ID != first.ID {
		t.Errorf("the lease identifier changed between reads")
	}
}

func TestANewVersionGetsItsOwnLease(t *testing.T) {
	manager, _, _ := newTestManager(t)

	issue(t, manager, "instance/web-01", "secret/prod/db", 1)
	issue(t, manager, "instance/web-01", "secret/prod/db", 2)

	active, err := manager.Active(t.Context(), "prod", "instance/web-01")
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("Active() = %d leases, want one per version", len(active))
	}
}

func TestReissuingExtendsButNeverShortens(t *testing.T) {
	manager, tick, _ := newTestManager(t)

	long, err := manager.Issue(t.Context(), "prod", "instance/web-01", "secret/prod/db", 1, time.Hour)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	short, err := manager.Issue(t.Context(), "prod", "instance/web-01", "secret/prod/db", 1, time.Minute)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if !short.ExpiresAt.Equal(long.ExpiresAt) {
		t.Errorf("a shorter reissue moved the expiry to %v", short.ExpiresAt)
	}

	tick.advance(30 * time.Minute)
	longer, err := manager.Issue(t.Context(), "prod", "instance/web-01", "secret/prod/db", 1, time.Hour)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if !longer.ExpiresAt.After(long.ExpiresAt) {
		t.Errorf("a longer reissue did not extend the expiry")
	}
}

func TestAnExpiredLeaseIsReplacedNotReused(t *testing.T) {
	manager, tick, _ := newTestManager(t)

	first := issue(t, manager, "instance/web-01", "secret/prod/db", 1)
	tick.advance(2 * DefaultTTL)
	second := issue(t, manager, "instance/web-01", "secret/prod/db", 1)

	if second.ID == first.ID {
		t.Fatal("an expired lease was reused")
	}

	active, err := manager.Active(t.Context(), "prod", "instance/web-01")
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if len(active) != 1 || active[0].ID != second.ID {
		t.Errorf("Active() = %+v, want only the replacement", active)
	}
}

func TestRenewOnlyByTheHolder(t *testing.T) {
	manager, tick, _ := newTestManager(t)
	held := issue(t, manager, "instance/web-01", "secret/prod/db", 1)

	renewed, err := manager.Renew(t.Context(), held.ID, "instance/web-01", time.Hour)
	if err != nil {
		t.Fatalf("Renew returned error: %v", err)
	}
	if !renewed.ExpiresAt.Equal(tick.at.Add(time.Hour)) {
		t.Errorf("ExpiresAt = %v", renewed.ExpiresAt)
	}

	if _, err := manager.Renew(t.Context(), held.ID, "instance/web-02", time.Hour); !errors.Is(err, ErrNotHolder) {
		t.Errorf("Renew by another identity = %v, want ErrNotHolder", err)
	}
	if _, err := manager.Renew(t.Context(), "secret/prod/db/nonexistent", "instance/web-01", time.Hour); !errors.Is(err, ErrGone) {
		t.Errorf("Renew of an unknown lease = %v, want ErrGone", err)
	}
	if _, err := manager.Renew(t.Context(), held.ID, "instance/web-01", MaximumTTL+time.Second); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("Renew with an oversized ttl = %v, want ErrInvalidTTL", err)
	}
}

func TestAnExpiredLeaseCannotBeRenewed(t *testing.T) {
	manager, tick, _ := newTestManager(t)
	held := issue(t, manager, "instance/web-01", "secret/prod/db", 1)

	tick.advance(2 * DefaultTTL)
	if _, err := manager.Renew(t.Context(), held.ID, "instance/web-01", time.Hour); !errors.Is(err, ErrGone) {
		t.Fatalf("Renew = %v, want ErrGone", err)
	}
}

func TestRevokeRemovesOneLease(t *testing.T) {
	manager, _, _ := newTestManager(t)
	held := issue(t, manager, "instance/web-01", "secret/prod/db", 1)
	issue(t, manager, "instance/web-01", "secret/prod/other", 1)

	if err := manager.Revoke(t.Context(), held.ID); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if err := manager.Revoke(t.Context(), held.ID); err != nil {
		t.Fatalf("a repeated Revoke returned error: %v", err)
	}
	if err := manager.Revoke(t.Context(), "secret/prod/db/nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Revoke of an unknown lease = %v, want ErrNotFound", err)
	}

	active, err := manager.Active(t.Context(), "prod", "instance/web-01")
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if len(active) != 1 || active[0].Path != "secret/prod/other" {
		t.Errorf("Active() = %+v", active)
	}
}

func TestRevokePrefixRevokesTheHoldersTokens(t *testing.T) {
	manager, _, tokens := newTestManager(t)

	issue(t, manager, "instance/web-01", "secret/prod/payment/db", 1)
	issue(t, manager, "instance/web-01", "secret/prod/payment/key", 1)
	issue(t, manager, "instance/web-02", "secret/prod/payment/db", 1)
	issue(t, manager, "instance/web-03", "secret/prod/billing/db", 1)

	revocation, err := manager.RevokePrefix(t.Context(), "prod", "secret/prod/payment/")
	if err != nil {
		t.Fatalf("RevokePrefix returned error: %v", err)
	}
	if revocation.Leases != 3 {
		t.Errorf("Leases = %d, want 3", revocation.Leases)
	}
	if strings.Join(revocation.Identities, ",") != "instance/web-01,instance/web-02" {
		t.Errorf("Identities = %v", revocation.Identities)
	}
	if revocation.Tokens != 4 {
		t.Errorf("Tokens = %d, want two identities at two tokens each", revocation.Tokens)
	}
	if strings.Join(tokens.called(), ",") != "instance/web-01,instance/web-02" {
		t.Errorf("the revoker saw %v", tokens.called())
	}

	remaining, err := manager.Active(t.Context(), "prod", "")
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if len(remaining) != 1 || remaining[0].IdentityID != "instance/web-03" {
		t.Errorf("Active() = %+v, want only the billing holder", remaining)
	}
}

func TestRevokePrefixDoesNotOverreachTheBoundary(t *testing.T) {
	manager, _, _ := newTestManager(t)

	issue(t, manager, "instance/web-01", "secret/prod/payment", 1)
	issue(t, manager, "instance/web-02", "secret/prod/payment-api", 1)

	revocation, err := manager.RevokePrefix(t.Context(), "prod", "secret/prod/payment/")
	if err != nil {
		t.Fatalf("RevokePrefix returned error: %v", err)
	}
	if revocation.Leases != 0 {
		t.Fatalf("Leases = %d, want 0: neither path is under that prefix", revocation.Leases)
	}

	wider, err := manager.RevokePrefix(t.Context(), "prod", "secret/prod/payment")
	if err != nil {
		t.Fatalf("RevokePrefix returned error: %v", err)
	}
	if wider.Leases != 2 {
		t.Errorf("Leases = %d, want both paths under the shorter prefix", wider.Leases)
	}
}

func TestRevokePrefixIsScopedToItsTenant(t *testing.T) {
	manager, _, _ := newTestManager(t)

	issue(t, manager, "instance/web-01", "secret/prod/db", 1)
	if _, err := manager.Issue(t.Context(), "staging", "instance/web-02", "secret/staging/db", 1, DefaultTTL); err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if _, err := manager.RevokePrefix(t.Context(), "prod", "secret/"); err != nil {
		t.Fatalf("RevokePrefix returned error: %v", err)
	}

	staging, err := manager.Active(t.Context(), "staging", "")
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if len(staging) != 1 {
		t.Errorf("a revocation in prod removed %d staging leases", 1-len(staging))
	}
}

func TestRevokeIdentityClearsEverythingItHolds(t *testing.T) {
	manager, _, tokens := newTestManager(t)

	issue(t, manager, "instance/web-01", "secret/prod/a", 1)
	issue(t, manager, "instance/web-01", "secret/prod/b", 1)
	issue(t, manager, "instance/web-02", "secret/prod/a", 1)

	revocation, err := manager.RevokeIdentity(t.Context(), "prod", "instance/web-01")
	if err != nil {
		t.Fatalf("RevokeIdentity returned error: %v", err)
	}
	if revocation.Leases != 2 || revocation.Tokens != 2 {
		t.Errorf("revocation = %+v", revocation)
	}
	if strings.Join(tokens.called(), ",") != "instance/web-01" {
		t.Errorf("the revoker saw %v", tokens.called())
	}

	remaining, err := manager.Active(t.Context(), "prod", "")
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if len(remaining) != 1 || remaining[0].IdentityID != "instance/web-02" {
		t.Errorf("Active() = %+v", remaining)
	}
}

func TestAFailingRevokerStopsTheRevocation(t *testing.T) {
	manager, _, tokens := newTestManager(t)
	issue(t, manager, "instance/web-01", "secret/prod/db", 1)

	tokens.failing = errors.New("the auth store is unavailable")
	if _, err := manager.RevokeIdentity(t.Context(), "prod", "instance/web-01"); err == nil {
		t.Fatal("RevokeIdentity reported success while the token revocation failed")
	}
}

func TestSweepForgetsOnlyWhatIsPastRetention(t *testing.T) {
	manager, tick, _ := newTestManager(t)

	issue(t, manager, "instance/web-01", "secret/prod/old", 1)
	tick.advance(DefaultTTL + Retention + time.Minute)
	issue(t, manager, "instance/web-01", "secret/prod/new", 1)

	removed, err := manager.Sweep(t.Context(), 100)
	if err != nil {
		t.Fatalf("Sweep returned error: %v", err)
	}
	if removed != 1 {
		t.Errorf("Sweep removed %d rows, want 1", removed)
	}

	active, err := manager.Active(t.Context(), "prod", "")
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if len(active) != 1 || active[0].Path != "secret/prod/new" {
		t.Errorf("Active() = %+v", active)
	}
}

func TestSweepRespectsItsBatchSize(t *testing.T) {
	manager, tick, _ := newTestManager(t)

	for index := range 10 {
		issue(t, manager, "instance/web-01", "secret/prod/"+string(rune('a'+index)), 1)
	}
	tick.advance(DefaultTTL + Retention + time.Minute)

	removed, err := manager.Sweep(t.Context(), 4)
	if err != nil {
		t.Fatalf("Sweep returned error: %v", err)
	}
	if removed != 4 {
		t.Errorf("Sweep removed %d rows, want 4", removed)
	}
	if _, err := manager.Sweep(t.Context(), 0); !errors.Is(err, ErrInvalidBatch) {
		t.Errorf("Sweep with a zero batch = %v, want ErrInvalidBatch", err)
	}
}

func TestIssueRejectsUnusableInput(t *testing.T) {
	manager, _, _ := newTestManager(t)

	cases := map[string]struct {
		tenant string
		path   string
		ttl    time.Duration
		want   error
	}{
		"no tenant": {tenant: "", path: "secret/prod/db", ttl: DefaultTTL, want: ErrInvalidTenant},
		"no path":   {tenant: "prod", path: "", ttl: DefaultTTL, want: ErrInvalidPath},
		"zero ttl":  {tenant: "prod", path: "secret/prod/db", ttl: 0, want: ErrInvalidTTL},
		"huge ttl":  {tenant: "prod", path: "secret/prod/db", ttl: MaximumTTL + time.Second, want: ErrInvalidTTL},
		"sentinel":  {tenant: "prod", path: "secret/prod/￿", ttl: DefaultTTL, want: ErrInvalidPath},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := manager.Issue(t.Context(), tc.tenant, "instance/web-01", tc.path, 1, tc.ttl); !errors.Is(err, tc.want) {
				t.Fatalf("Issue = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewManagerRequiresItsCollaborators(t *testing.T) {
	if _, err := NewManager(nil, &revoker{}, Options{}); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("NewManager without a database = %v, want ErrNoDatabase", err)
	}

	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "marsec.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := NewManager(db, nil, Options{}); !errors.Is(err, ErrNoRevoker) {
		t.Errorf("NewManager without a revoker = %v, want ErrNoRevoker", err)
	}
}
