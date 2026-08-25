package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/jwt"
)

const (
	controlIssuer   = "https://control.marstack.internal"
	controlAudience = "marstack-secrets"
	controlKeyID    = "cp-2026-08"
)

type controlPlane struct {
	private  ed25519.PrivateKey
	verifier *jwt.Verifier
	nextID   int
}

func newControlPlane(t *testing.T, now func() time.Time) *controlPlane {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	verifier, err := jwt.NewVerifier(jwt.Options{
		Keys:     jwt.StaticKeys{controlKeyID: public},
		Issuer:   controlIssuer,
		Audience: controlAudience,
		Skew:     30 * time.Second,
		Now:      now,
	})
	if err != nil {
		t.Fatalf("NewVerifier returned error: %v", err)
	}
	return &controlPlane{private: private, verifier: verifier}
}

func (c *controlPlane) assert(t *testing.T, instance, tenant string, at time.Time) []byte {
	t.Helper()
	c.nextID++
	return c.assertWithID(t, instance, tenant, fmt.Sprintf("assertion-%d", c.nextID), at)
}

func (c *controlPlane) assertWithID(t *testing.T, instance, tenant, id string, at time.Time) []byte {
	t.Helper()
	return c.sign(t, map[string]any{
		"iss":    controlIssuer,
		"sub":    instance,
		"aud":    controlAudience,
		"exp":    at.Add(2 * time.Minute).Unix(),
		"iat":    at.Unix(),
		"jti":    id,
		"tenant": tenant,
	})
}

func (c *controlPlane) sign(t *testing.T, claims map[string]any) []byte {
	t.Helper()

	segment := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("encoding: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	signed := segment(map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": controlKeyID}) +
		"." + segment(claims)
	signature := ed25519.Sign(c.private, []byte(signed))
	return []byte(signed + "." + base64.RawURLEncoding.EncodeToString(signature))
}

func instanceSetup(t *testing.T) (*Manager, *clock, *controlPlane) {
	t.Helper()
	manager, tick, _ := newTestManager(t)
	return manager, tick, newControlPlane(t, tick.now)
}

func TestAnInstanceAssertionBuysASessionToken(t *testing.T) {
	manager, tick, control := instanceSetup(t)

	token, err := manager.LoginInstance(t.Context(), control.verifier,
		control.assert(t, "instance/web-01", "prod", tick.at))
	if err != nil {
		t.Fatalf("LoginInstance returned error: %v", err)
	}
	if token.Identity.ID != "instance/web-01" || token.Identity.Tenant != "prod" {
		t.Errorf("token identity = %+v", token.Identity)
	}
	if token.Identity.Kind != authn.KindInstance {
		t.Errorf("kind = %q, want %q", token.Identity.Kind, authn.KindInstance)
	}

	identity, err := manager.Authenticate(t.Context(), token.Value, NoBinding)
	if err != nil {
		t.Fatalf("the session token does not authenticate: %v", err)
	}
	if identity.ID != "instance/web-01" {
		t.Errorf("Authenticate() = %+v", identity)
	}
}

func TestAnInstanceSessionIsNotBoundYet(t *testing.T) {
	manager, tick, control := instanceSetup(t)

	token, err := manager.LoginInstance(t.Context(), control.verifier,
		control.assert(t, "instance/web-01", "prod", tick.at))
	if err != nil {
		t.Fatalf("LoginInstance returned error: %v", err)
	}

	if _, err := manager.Authenticate(t.Context(), token.Value, NoBinding); err != nil {
		t.Fatalf("an instance session must be usable over plain HTTP for now: %v", err)
	}
	if _, err := manager.Authenticate(t.Context(), token.Value, "instance/web-01"); !errors.Is(err, ErrUnauthenticated) {
		t.Error("a binding was recorded that nothing can present")
	}
}

func TestTheFirstLoginEnrolsTheInstance(t *testing.T) {
	manager, tick, control := instanceSetup(t)

	if _, err := manager.Identity(t.Context(), "instance/web-01"); !errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("the instance should be unknown before its first login: %v", err)
	}

	if _, err := manager.LoginInstance(t.Context(), control.verifier,
		control.assert(t, "instance/web-01", "prod", tick.at)); err != nil {
		t.Fatalf("LoginInstance returned error: %v", err)
	}

	identity, err := manager.Identity(t.Context(), "instance/web-01")
	if err != nil {
		t.Fatalf("Identity returned error: %v", err)
	}
	if identity.Kind != authn.KindInstance || identity.Tenant != "prod" {
		t.Errorf("Identity() = %+v", identity)
	}
}

func TestAnAssertionCannotBeReplayed(t *testing.T) {
	manager, tick, control := instanceSetup(t)
	assertion := control.assert(t, "instance/web-01", "prod", tick.at)

	if _, err := manager.LoginInstance(t.Context(), control.verifier, assertion); err != nil {
		t.Fatalf("the first login returned error: %v", err)
	}
	if _, err := manager.LoginInstance(t.Context(), control.verifier, assertion); !errors.Is(err, ErrReplayed) {
		t.Fatalf("the second login = %v, want ErrReplayed", err)
	}
}

func TestConcurrentReplaysProduceExactlyOneSession(t *testing.T) {
	manager, tick, control := instanceSetup(t)
	assertion := control.assert(t, "instance/web-01", "prod", tick.at)

	const racers = 16
	var group sync.WaitGroup
	results := make(chan error, racers)
	start := make(chan struct{})

	for range racers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := manager.LoginInstance(t.Context(), control.verifier, assertion)
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
		case errors.Is(err, ErrReplayed):
		default:
			t.Errorf("a racer failed unexpectedly: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent logins succeeded, want exactly 1", succeeded, racers)
	}
}

func TestADistinctAssertionForTheSameInstanceIsFine(t *testing.T) {
	manager, tick, control := instanceSetup(t)

	for range 3 {
		if _, err := manager.LoginInstance(t.Context(), control.verifier,
			control.assert(t, "instance/web-01", "prod", tick.at)); err != nil {
			t.Fatalf("LoginInstance returned error: %v", err)
		}
	}
}

func TestAnInstanceCannotChangeTenant(t *testing.T) {
	manager, tick, control := instanceSetup(t)

	if _, err := manager.LoginInstance(t.Context(), control.verifier,
		control.assert(t, "instance/web-01", "prod", tick.at)); err != nil {
		t.Fatalf("LoginInstance returned error: %v", err)
	}

	_, err := manager.LoginInstance(t.Context(), control.verifier,
		control.assert(t, "instance/web-01", "staging", tick.at))
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("LoginInstance = %v, want ErrTenantMismatch", err)
	}
}

func TestAnInstanceCannotReuseABootstrapIdentityName(t *testing.T) {
	manager, tick, control := instanceSetup(t)
	registered(t, manager, "instance/web-01", authn.KindBootstrap)

	_, err := manager.LoginInstance(t.Context(), control.verifier,
		control.assert(t, "instance/web-01", "prod", tick.at))
	if !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("LoginInstance = %v, want ErrKindMismatch", err)
	}
}

func TestADisabledInstanceCannotLogIn(t *testing.T) {
	manager, tick, control := instanceSetup(t)

	if _, err := manager.LoginInstance(t.Context(), control.verifier,
		control.assert(t, "instance/web-01", "prod", tick.at)); err != nil {
		t.Fatalf("LoginInstance returned error: %v", err)
	}
	if err := manager.DisableIdentity(t.Context(), "instance/web-01"); err != nil {
		t.Fatalf("DisableIdentity returned error: %v", err)
	}

	_, err := manager.LoginInstance(t.Context(), control.verifier,
		control.assert(t, "instance/web-01", "prod", tick.at))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("LoginInstance = %v, want ErrUnauthenticated", err)
	}
}

func TestAnUnverifiableAssertionIsRefused(t *testing.T) {
	manager, tick, control := instanceSetup(t)
	impostor := newControlPlane(t, tick.now)

	cases := map[string][]byte{
		"signed by another control plane": impostor.assert(t, "instance/web-01", "prod", tick.at),
		"not a token":                     []byte("nonsense"),
		"empty":                           nil,
		"expired": control.sign(t, map[string]any{
			"iss": controlIssuer, "sub": "instance/web-01", "aud": controlAudience,
			"exp": tick.at.Add(-time.Hour).Unix(), "jti": "old", "tenant": "prod",
		}),
		"missing tenant": control.sign(t, map[string]any{
			"iss": controlIssuer, "sub": "instance/web-01", "aud": controlAudience,
			"exp": tick.at.Add(time.Hour).Unix(), "jti": "no-tenant",
		}),
		"missing assertion id": control.sign(t, map[string]any{
			"iss": controlIssuer, "sub": "instance/web-01", "aud": controlAudience,
			"exp": tick.at.Add(time.Hour).Unix(), "tenant": "prod",
		}),
		"wrong audience": control.sign(t, map[string]any{
			"iss": controlIssuer, "sub": "instance/web-01", "aud": "someone-else",
			"exp": tick.at.Add(time.Hour).Unix(), "jti": "wrong-aud", "tenant": "prod",
		}),
	}
	for name, assertion := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := manager.LoginInstance(t.Context(), control.verifier, assertion); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("LoginInstance = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestARefusedAssertionEnrolsNothing(t *testing.T) {
	manager, tick, control := instanceSetup(t)
	impostor := newControlPlane(t, tick.now)

	if _, err := manager.LoginInstance(t.Context(), control.verifier,
		impostor.assert(t, "instance/web-01", "prod", tick.at)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("LoginInstance = %v, want ErrUnauthenticated", err)
	}
	if _, err := manager.Identity(t.Context(), "instance/web-01"); !errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("a refused assertion enrolled the instance: %v", err)
	}
}

func TestAReplayedAssertionForAMismatchedTenantEnrolsNothing(t *testing.T) {
	manager, tick, control := instanceSetup(t)

	if _, err := manager.LoginInstance(t.Context(), control.verifier,
		control.assert(t, "instance/web-01", "prod", tick.at)); err != nil {
		t.Fatalf("LoginInstance returned error: %v", err)
	}

	rejected := control.assert(t, "instance/web-01", "staging", tick.at)
	if _, err := manager.LoginInstance(t.Context(), control.verifier, rejected); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("LoginInstance = %v, want ErrTenantMismatch", err)
	}

	identity, err := manager.Identity(t.Context(), "instance/web-01")
	if err != nil {
		t.Fatalf("Identity returned error: %v", err)
	}
	if identity.Tenant != "prod" {
		t.Errorf("tenant = %q, want it unchanged at prod", identity.Tenant)
	}
	if _, err := manager.LoginInstance(t.Context(), control.verifier, rejected); !errors.Is(err, ErrTenantMismatch) {
		t.Errorf("the rejected assertion was consumed: %v", err)
	}
}

func TestPurgeSpentAssertionsForgetsOnlyExpiredOnes(t *testing.T) {
	manager, tick, control := instanceSetup(t)

	short := control.assert(t, "instance/web-01", "prod", tick.at)
	if _, err := manager.LoginInstance(t.Context(), control.verifier, short); err != nil {
		t.Fatalf("LoginInstance returned error: %v", err)
	}

	tick.advance(10 * time.Minute)
	long := control.assert(t, "instance/web-02", "prod", tick.at)
	if _, err := manager.LoginInstance(t.Context(), control.verifier, long); err != nil {
		t.Fatalf("LoginInstance returned error: %v", err)
	}

	removed, err := manager.PurgeSpentAssertions(t.Context())
	if err != nil {
		t.Fatalf("PurgeSpentAssertions returned error: %v", err)
	}
	if removed != 1 {
		t.Errorf("PurgeSpentAssertions removed %d rows, want 1", removed)
	}
	if _, err := manager.LoginInstance(t.Context(), control.verifier, long); !errors.Is(err, ErrReplayed) {
		t.Errorf("a still valid assertion was forgotten: %v", err)
	}
}
