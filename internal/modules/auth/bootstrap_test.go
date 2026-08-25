package auth

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

func TestABootstrapTokenBuysASessionToken(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindBootstrap)

	bootstrap, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}

	session, err := manager.Exchange(t.Context(), bootstrap.Value, "web-01", DefaultTTL)
	if err != nil {
		t.Fatalf("Exchange returned error: %v", err)
	}
	if strings.EqualFold(string(session.Value), string(bootstrap.Value)) {
		t.Fatal("Exchange handed back the same token")
	}

	identity, err := manager.Authenticate(t.Context(), session.Value, "web-01")
	if err != nil {
		t.Fatalf("the session token does not authenticate: %v", err)
	}
	if identity.ID != "instance/web-01" {
		t.Errorf("Authenticate() = %+v", identity)
	}
}

func TestABootstrapTokenIsNotASessionToken(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindBootstrap)

	bootstrap, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}

	if _, err := manager.Authenticate(t.Context(), bootstrap.Value, NoBinding); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a bootstrap token authenticated directly: %v", err)
	}
}

func TestASessionTokenCannotBeExchanged(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindBootstrap)
	session := issued(t, manager, "instance/web-01", NoBinding)

	if _, err := manager.Exchange(t.Context(), session.Value, "web-01", DefaultTTL); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Exchange accepted a reusable token: %v", err)
	}
}

func TestABootstrapTokenWorksExactlyOnce(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindBootstrap)

	bootstrap, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}

	if _, err := manager.Exchange(t.Context(), bootstrap.Value, "web-01", DefaultTTL); err != nil {
		t.Fatalf("the first Exchange returned error: %v", err)
	}
	if _, err := manager.Exchange(t.Context(), bootstrap.Value, "web-01", DefaultTTL); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("the second Exchange = %v, want ErrUnauthenticated", err)
	}
}

func TestConcurrentExchangesProduceExactlyOneSession(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindBootstrap)

	bootstrap, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}

	const racers = 16
	var group sync.WaitGroup
	results := make(chan error, racers)
	start := make(chan struct{})

	for range racers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := manager.Exchange(t.Context(), bootstrap.Value, "web-01", DefaultTTL)
			results <- err
		}()
	}

	close(start)
	group.Wait()
	close(results)

	var succeeded int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrUnauthenticated):
		default:
			t.Errorf("a racer failed with an unexpected error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent exchanges succeeded, want exactly 1", succeeded, racers)
	}
}

func TestExchangeRejectsAConsumedOrExpiredBootstrap(t *testing.T) {
	manager, tick, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindBootstrap)

	expired, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}
	revoked, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}
	if err := manager.Revoke(t.Context(), revoked.Value); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}

	tick.advance(2 * BootstrapTTL)

	cases := map[string]crypto.Sensitive{
		"expired":      expired.Value,
		"revoked":      revoked.Value,
		"never issued": crypto.Sensitive(tokenPrefix + strings.Repeat("B", 43)),
		"malformed":    crypto.Sensitive("mss_short"),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := manager.Exchange(t.Context(), token, "web-01", DefaultTTL); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Exchange = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestExchangeRejectsABadSessionTTL(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindBootstrap)

	bootstrap, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}

	if _, err := manager.Exchange(t.Context(), bootstrap.Value, "web-01", MaximumTTL+time.Second); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("Exchange with an oversized ttl = %v, want ErrInvalidTTL", err)
	}
	if _, err := manager.Exchange(t.Context(), bootstrap.Value, "web-01", DefaultTTL); err != nil {
		t.Fatalf("the rejected ttl consumed the bootstrap token: %v", err)
	}
}

func TestExchangeForADisabledIdentityFails(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindBootstrap)

	bootstrap, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}
	if err := manager.DisableIdentity(t.Context(), "instance/web-01"); err != nil {
		t.Fatalf("DisableIdentity returned error: %v", err)
	}

	if _, err := manager.Exchange(t.Context(), bootstrap.Value, "web-01", DefaultTTL); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Exchange for a disabled identity = %v, want ErrUnauthenticated", err)
	}
}

func TestExchangedSessionsCarryTheRequestedBinding(t *testing.T) {
	manager, _, _ := newTestManager(t)
	registered(t, manager, "instance/web-01", KindBootstrap)

	bootstrap, err := manager.IssueBootstrap(t.Context(), "instance/web-01", BootstrapTTL)
	if err != nil {
		t.Fatalf("IssueBootstrap returned error: %v", err)
	}
	session, err := manager.Exchange(t.Context(), bootstrap.Value, "web-01", DefaultTTL)
	if err != nil {
		t.Fatalf("Exchange returned error: %v", err)
	}

	if _, err := manager.Authenticate(t.Context(), session.Value, "web-02"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the session token works at another binding: %v", err)
	}
}
