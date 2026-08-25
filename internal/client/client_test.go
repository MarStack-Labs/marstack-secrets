package client

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()

	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	made, err := New(Options{Address: server.URL, RootCAs: roots})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return made, server
}

func TestPlaintextNeedsAnExplicitOptIn(t *testing.T) {
	if _, err := New(Options{Address: "http://127.0.0.1:8200"}); !errors.Is(err, ErrPlaintext) {
		t.Fatalf("New = %v, want ErrPlaintext", err)
	}
	if _, err := New(Options{Address: "http://127.0.0.1:8200", AllowPlainHTTP: true}); err != nil {
		t.Errorf("New with the opt-in returned error: %v", err)
	}
	if _, err := New(Options{Address: "https://127.0.0.1:8200"}); err != nil {
		t.Errorf("New over https returned error: %v", err)
	}
}

func TestUnusableAddressesAreRefused(t *testing.T) {
	cases := map[string]struct {
		address string
		want    error
	}{
		"empty":       {address: "", want: ErrNoAddress},
		"no scheme":   {address: "127.0.0.1:8200", want: ErrBadAddress},
		"no host":     {address: "https://", want: ErrBadAddress},
		"odd scheme":  {address: "ftp://example.internal", want: ErrBadAddress},
		"just a word": {address: "nonsense", want: ErrBadAddress},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(Options{Address: tc.address}); !errors.Is(err, tc.want) {
				t.Fatalf("New = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAnUntrustedServerCertificateIsRefused(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	made, err := New(Options{Address: server.URL})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if _, err := made.SealStatus(t.Context()); err == nil {
		t.Fatal("the client accepted a certificate it had no reason to trust")
	}
}

func TestTheTokenTravelsAsABearerCredential(t *testing.T) {
	var seen string
	made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"value":"v","version":1}`))
	}))

	made.SetToken(crypto.Sensitive("mss_" + strings.Repeat("A", 43)))
	if _, err := made.ReadSecret(t.Context(), "prod", "db", 0); err != nil {
		t.Fatalf("ReadSecret returned error: %v", err)
	}

	if !strings.HasPrefix(seen, "Bearer mss_") {
		t.Errorf("Authorization = %q", seen)
	}
}

func TestACallThatNeedsATokenSaysSo(t *testing.T) {
	made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the client made a request without a token")
	}))

	if _, err := made.ReadSecret(t.Context(), "prod", "db", 0); !errors.Is(err, ErrNoToken) {
		t.Fatalf("ReadSecret = %v, want ErrNoToken", err)
	}
}

func TestLoginKeepsTheTokenForLaterCalls(t *testing.T) {
	made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/bootstrap/login" {
			_, _ = w.Write([]byte(`{"token":"mss_issued","expires_at":"2026-08-25T13:00:00Z"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer mss_issued" {
			t.Errorf("the follow-up call carried %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"value":"v","version":2,"lease_id":"secret/prod/db/AB","lease_ttl":1800}`))
	}))

	session, err := made.LoginBootstrap(t.Context(), crypto.Sensitive("mss_bootstrap"))
	if err != nil {
		t.Fatalf("LoginBootstrap returned error: %v", err)
	}
	if string(session.Token) != "mss_issued" || session.ExpiresAt.IsZero() {
		t.Fatalf("session = %+v", session)
	}

	found, err := made.ReadSecret(t.Context(), "prod", "db", 0)
	if err != nil {
		t.Fatalf("ReadSecret returned error: %v", err)
	}
	if string(found.Value) != "v" || found.Version != 2 {
		t.Errorf("secret = %+v", found)
	}
	if found.LeaseID != "secret/prod/db/AB" || found.LeaseTTL != 30*time.Minute {
		t.Errorf("lease = %q for %v", found.LeaseID, found.LeaseTTL)
	}
}

func TestStatusCodesBecomeNamedErrors(t *testing.T) {
	cases := map[int]struct {
		body string
		want error
	}{
		http.StatusUnauthorized:       {body: `{"error":{"code":"unauthenticated"}}`, want: ErrUnauthorized},
		http.StatusForbidden:          {body: `{"error":{"code":"forbidden"}}`, want: ErrForbidden},
		http.StatusNotFound:           {body: `{"error":{"code":"not_found"}}`, want: ErrNotFound},
		http.StatusConflict:           {body: `{"error":{"code":"version_conflict"}}`, want: ErrConflict},
		http.StatusTooManyRequests:    {body: `{"error":{"code":"rate_limited"}}`, want: ErrRateLimited},
		http.StatusServiceUnavailable: {body: `{"error":{"code":"sealed"}}`, want: ErrSealed},
	}

	for status, tc := range cases {
		t.Run(http.StatusText(status), func(t *testing.T) {
			made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(tc.body))
			}))
			made.SetToken(crypto.Sensitive("mss_token"))

			if _, err := made.ReadSecret(t.Context(), "prod", "db", 0); !errors.Is(err, tc.want) {
				t.Fatalf("ReadSecret = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestASealedStoreIsDistinguishableFromOtherOutages(t *testing.T) {
	made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"audit_unavailable"}}`))
	}))
	made.SetToken(crypto.Sensitive("mss_token"))

	err := made.callErr(t)
	if errors.Is(err, ErrSealed) {
		t.Fatal("an audit outage was reported as a sealed store")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func (c *Client) callErr(t *testing.T) error {
	t.Helper()
	_, err := c.ReadSecret(t.Context(), "prod", "db", 0)
	return err
}

func TestAnOversizedResponseIsRefused(t *testing.T) {
	made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":"` + strings.Repeat("a", maxResponseSize+16) + `"}`))
	}))
	made.SetToken(crypto.Sensitive("mss_token"))

	if _, err := made.ReadSecret(t.Context(), "prod", "db", 0); !errors.Is(err, ErrResponseLarge) {
		t.Fatalf("ReadSecret = %v, want ErrResponseLarge", err)
	}
}

func TestVersionAndPathReachTheRequest(t *testing.T) {
	var path, query string
	made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, query = r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(`{"value":"v","version":3}`))
	}))
	made.SetToken(crypto.Sensitive("mss_token"))

	if _, err := made.ReadSecret(t.Context(), "prod", "apps/payment/db", 3); err != nil {
		t.Fatalf("ReadSecret returned error: %v", err)
	}
	if path != "/v1/secret/data/prod/apps/payment/db" {
		t.Errorf("path = %q", path)
	}
	if query != "version=3" {
		t.Errorf("query = %q", query)
	}
}

func TestWritingSendsCheckAndSetOnlyWhenAsked(t *testing.T) {
	var bodies []string
	made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 256)
		n, _ := r.Body.Read(raw)
		bodies = append(bodies, string(raw[:n]))
		_, _ = w.Write([]byte(`{"version":1}`))
	}))
	made.SetToken(crypto.Sensitive("mss_token"))

	if _, err := made.WriteSecret(t.Context(), "prod", "db", crypto.Sensitive("v"), nil); err != nil {
		t.Fatalf("WriteSecret returned error: %v", err)
	}
	expected := 2
	if _, err := made.WriteSecret(t.Context(), "prod", "db", crypto.Sensitive("v"), &expected); err != nil {
		t.Fatalf("WriteSecret returned error: %v", err)
	}

	if strings.Contains(bodies[0], "cas") {
		t.Errorf("the first write carried a cas field: %s", bodies[0])
	}
	if !strings.Contains(bodies[1], `"cas":2`) {
		t.Errorf("the second write did not carry the expectation: %s", bodies[1])
	}
}

func TestForgetClearsTheToken(t *testing.T) {
	made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	token := crypto.Sensitive("mss_" + strings.Repeat("A", 43))
	made.SetToken(token)
	made.Forget()

	if len(made.Token()) != 0 {
		t.Error("the client kept its token")
	}
	if strings.Trim(string(token), "\x00") != "" {
		t.Error("the caller's copy was not cleared")
	}
}

func TestAParameterCarriesItsProvenance(t *testing.T) {
	made, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"path":"apps/db_url","resolved_from":"db_url","inherited":true,
			"kind":"string","value":"postgres://x","sensitive":true,"references":["secret/prod/db"]}`))
	}))
	made.SetToken(crypto.Sensitive("mss_token"))

	found, err := made.ReadParameter(t.Context(), "prod", "apps/db_url")
	if err != nil {
		t.Fatalf("ReadParameter returned error: %v", err)
	}
	if !found.Inherited || found.ResolvedFrom != "db_url" || !found.Sensitive {
		t.Errorf("parameter = %+v", found)
	}
	if len(found.References) != 1 {
		t.Errorf("References = %v", found.References)
	}
}
