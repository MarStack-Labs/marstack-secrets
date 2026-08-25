package jwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer   = "https://control.marstack.internal"
	testAudience = "marstack-secrets"
	testKeyID    = "cp-2026-08"
)

var testNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

type signer struct {
	keyID   string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func newSigner(t *testing.T, keyID string) *signer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return &signer{keyID: keyID, private: private, public: public}
}

func encode(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (s *signer) mint(t *testing.T, head map[string]any, claims map[string]any) []byte {
	t.Helper()
	signed := encode(t, head) + "." + encode(t, claims)
	signature := ed25519.Sign(s.private, []byte(signed))
	return []byte(signed + "." + base64.RawURLEncoding.EncodeToString(signature))
}

func defaultHeader() map[string]any {
	return map[string]any{"alg": algorithmEdDSA, "typ": typeJWT, "kid": testKeyID}
}

func defaultClaims() map[string]any {
	return map[string]any{
		"iss":    testIssuer,
		"sub":    "instance/web-01",
		"aud":    testAudience,
		"exp":    testNow.Add(time.Hour).Unix(),
		"nbf":    testNow.Add(-time.Minute).Unix(),
		"iat":    testNow.Add(-time.Minute).Unix(),
		"jti":    "7c1e2f80",
		"tenant": "prod",
	}
}

func newVerifier(t *testing.T, keys KeySource) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(Options{
		Keys:     keys,
		Issuer:   testIssuer,
		Audience: testAudience,
		Skew:     30 * time.Second,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier returned error: %v", err)
	}
	return verifier
}

func setup(t *testing.T) (*signer, *Verifier) {
	t.Helper()
	control := newSigner(t, testKeyID)
	return control, newVerifier(t, StaticKeys{testKeyID: control.public})
}

func TestAValidTokenVerifies(t *testing.T) {
	control, verifier := setup(t)

	claims, err := verifier.Verify(t.Context(), control.mint(t, defaultHeader(), defaultClaims()))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if claims.Subject != "instance/web-01" || claims.Tenant != "prod" || claims.ID != "7c1e2f80" {
		t.Errorf("Verify() = %+v", claims)
	}
}

func TestAnHMACTokenIsRejected(t *testing.T) {
	control, verifier := setup(t)

	head := map[string]any{"alg": "HS256", "typ": typeJWT, "kid": testKeyID}
	signed := encode(t, head) + "." + encode(t, defaultClaims())
	mac := hmac.New(sha256.New, control.public)
	mac.Write([]byte(signed))
	forged := []byte(signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))

	if _, err := verifier.Verify(t.Context(), forged); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("Verify = %v, want ErrAlgorithm", err)
	}
}

func TestAnUnsignedTokenIsRejected(t *testing.T) {
	control, verifier := setup(t)

	for name, head := range map[string]map[string]any{
		"alg none":    {"alg": "none", "typ": typeJWT, "kid": testKeyID},
		"alg empty":   {"alg": "", "typ": typeJWT, "kid": testKeyID},
		"alg missing": {"typ": typeJWT, "kid": testKeyID},
		"alg ed25519": {"alg": "Ed25519", "typ": typeJWT, "kid": testKeyID},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(t.Context(), control.mint(t, head, defaultClaims())); !errors.Is(err, ErrAlgorithm) {
				t.Fatalf("Verify = %v, want ErrAlgorithm", err)
			}
		})
	}
}

func TestAnEmptySignatureIsRejected(t *testing.T) {
	_, verifier := setup(t)

	unsigned := encode(t, defaultHeader()) + "." + encode(t, defaultClaims()) + "."
	if _, err := verifier.Verify(t.Context(), []byte(unsigned)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Verify = %v, want ErrMalformed", err)
	}
}

func TestATokenSignedByAnotherKeyIsRejected(t *testing.T) {
	_, verifier := setup(t)
	impostor := newSigner(t, testKeyID)

	if _, err := verifier.Verify(t.Context(), impostor.mint(t, defaultHeader(), defaultClaims())); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify = %v, want ErrSignature", err)
	}
}

func TestAnUnknownKeyIDIsRejected(t *testing.T) {
	control, verifier := setup(t)

	head := defaultHeader()
	head["kid"] = "cp-2020-01"
	if _, err := verifier.Verify(t.Context(), control.mint(t, head, defaultClaims())); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Verify = %v, want ErrUnknownKey", err)
	}
}

func TestTamperingWithTheClaimsIsRejected(t *testing.T) {
	control, verifier := setup(t)
	token := control.mint(t, defaultHeader(), defaultClaims())

	parts := bytes.Split(token, []byte("."))
	forgedClaims := defaultClaims()
	forgedClaims["tenant"] = "staging"
	parts[1] = []byte(encode(t, forgedClaims))
	forged := bytes.Join(parts, []byte("."))

	if _, err := verifier.Verify(t.Context(), forged); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify = %v, want ErrSignature", err)
	}
}

func TestTimeBounds(t *testing.T) {
	control, verifier := setup(t)

	cases := map[string]struct {
		mutate func(map[string]any)
		want   error
	}{
		"expired well past the skew": {
			mutate: func(c map[string]any) { c["exp"] = testNow.Add(-time.Hour).Unix() },
			want:   ErrExpired,
		},
		"expired inside the skew": {
			mutate: func(c map[string]any) { c["exp"] = testNow.Add(-10 * time.Second).Unix() },
			want:   nil,
		},
		"expires exactly now": {
			mutate: func(c map[string]any) { c["exp"] = testNow.Unix() },
			want:   nil,
		},
		"no expiry": {
			mutate: func(c map[string]any) { delete(c, "exp") },
			want:   ErrNoExpiry,
		},
		"not valid yet": {
			mutate: func(c map[string]any) { c["nbf"] = testNow.Add(time.Hour).Unix() },
			want:   ErrNotYetValid,
		},
		"not valid yet inside the skew": {
			mutate: func(c map[string]any) { c["nbf"] = testNow.Add(10 * time.Second).Unix() },
			want:   nil,
		},
		"issued in the future": {
			mutate: func(c map[string]any) { c["iat"] = testNow.Add(time.Hour).Unix() },
			want:   ErrIssuedInFuture,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			claims := defaultClaims()
			tc.mutate(claims)

			_, err := verifier.Verify(t.Context(), control.mint(t, defaultHeader(), claims))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Verify returned error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRequiredClaims(t *testing.T) {
	control, verifier := setup(t)

	cases := map[string]struct {
		mutate func(map[string]any)
		want   error
	}{
		"wrong issuer":     {mutate: func(c map[string]any) { c["iss"] = "https://evil.example" }, want: ErrIssuer},
		"missing issuer":   {mutate: func(c map[string]any) { delete(c, "iss") }, want: ErrIssuer},
		"wrong audience":   {mutate: func(c map[string]any) { c["aud"] = "someone-else" }, want: ErrAudience},
		"missing audience": {mutate: func(c map[string]any) { delete(c, "aud") }, want: ErrAudience},
		"missing subject":  {mutate: func(c map[string]any) { delete(c, "sub") }, want: ErrSubject},
		"empty subject":    {mutate: func(c map[string]any) { c["sub"] = "" }, want: ErrSubject},
		"missing jti":      {mutate: func(c map[string]any) { delete(c, "jti") }, want: ErrTokenID},
		"missing tenant":   {mutate: func(c map[string]any) { delete(c, "tenant") }, want: ErrTenant},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			claims := defaultClaims()
			tc.mutate(claims)

			if _, err := verifier.Verify(t.Context(), control.mint(t, defaultHeader(), claims)); !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAudienceAcceptsBothShapes(t *testing.T) {
	control, verifier := setup(t)

	for name, audience := range map[string]any{
		"single string":  testAudience,
		"array with one": []string{testAudience},
		"array with two": []string{"other", testAudience},
	} {
		t.Run(name, func(t *testing.T) {
			claims := defaultClaims()
			claims["aud"] = audience

			if _, err := verifier.Verify(t.Context(), control.mint(t, defaultHeader(), claims)); err != nil {
				t.Fatalf("Verify returned error: %v", err)
			}
		})
	}

	claims := defaultClaims()
	claims["aud"] = []string{"one", "two"}
	if _, err := verifier.Verify(t.Context(), control.mint(t, defaultHeader(), claims)); !errors.Is(err, ErrAudience) {
		t.Errorf("Verify with an array that omits us = %v, want ErrAudience", err)
	}
}

func TestMalformedTokensAreRejected(t *testing.T) {
	_, verifier := setup(t)

	cases := map[string][]byte{
		"empty":           {},
		"one segment":     []byte("abc"),
		"two segments":    []byte("abc.def"),
		"four segments":   []byte("a.b.c.d"),
		"empty header":    []byte(".b.c"),
		"empty payload":   []byte("a..c"),
		"not base64":      []byte("!!!.!!!.!!!"),
		"padded base64":   []byte("YWJj==.YWJj==.YWJj=="),
		"header not json": []byte(base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".YWJj.YWJj"),
		"too large":       bytes.Repeat([]byte("a"), MaxTokenBytes+1),
		"trailing json":   []byte(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}{}`)) + ".YWJj.YWJj"),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(t.Context(), token); err == nil {
				t.Fatal("expected the token to be rejected")
			}
		})
	}

	if _, err := verifier.Verify(t.Context(), bytes.Repeat([]byte("a"), MaxTokenBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("an oversized token = %v, want ErrTooLarge", err)
	}
}

func TestCriticalHeaderExtensionsAreRejected(t *testing.T) {
	control, verifier := setup(t)

	head := defaultHeader()
	head["crit"] = []string{"exp"}
	if _, err := verifier.Verify(t.Context(), control.mint(t, head, defaultClaims())); !errors.Is(err, ErrCritical) {
		t.Fatalf("Verify = %v, want ErrCritical", err)
	}
}

func TestATypeOtherThanJWTIsRejected(t *testing.T) {
	control, verifier := setup(t)

	head := defaultHeader()
	head["typ"] = "at+jwt"
	if _, err := verifier.Verify(t.Context(), control.mint(t, head, defaultClaims())); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Verify = %v, want ErrMalformed", err)
	}

	head = defaultHeader()
	delete(head, "typ")
	if _, err := verifier.Verify(t.Context(), control.mint(t, head, defaultClaims())); err != nil {
		t.Errorf("a token without a type should still verify: %v", err)
	}
}

func TestNewVerifierValidatesItsOptions(t *testing.T) {
	keys := StaticKeys{}

	cases := map[string]struct {
		opts Options
		want error
	}{
		"no keys":       {opts: Options{Issuer: testIssuer, Audience: testAudience}, want: ErrNoKeySource},
		"no issuer":     {opts: Options{Keys: keys, Audience: testAudience}, want: ErrNoIssuer},
		"no audience":   {opts: Options{Keys: keys, Issuer: testIssuer}, want: ErrNoAudience},
		"negative skew": {opts: Options{Keys: keys, Issuer: testIssuer, Audience: testAudience, Skew: -time.Second}, want: ErrNegativeSkew},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewVerifier(tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("NewVerifier = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSkewIsCapped(t *testing.T) {
	control := newSigner(t, testKeyID)
	verifier, err := NewVerifier(Options{
		Keys:     StaticKeys{testKeyID: control.public},
		Issuer:   testIssuer,
		Audience: testAudience,
		Skew:     24 * time.Hour,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier returned error: %v", err)
	}

	claims := defaultClaims()
	claims["exp"] = testNow.Add(-2 * time.Minute).Unix()
	if _, err := verifier.Verify(t.Context(), control.mint(t, defaultHeader(), claims)); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify = %v, want ErrExpired: a huge skew must be capped", err)
	}
}

func TestAKeyOfTheWrongSizeIsRejected(t *testing.T) {
	control := newSigner(t, testKeyID)
	verifier := newVerifier(t, StaticKeys{testKeyID: ed25519.PublicKey(strings.Repeat("x", 16))})

	if _, err := verifier.Verify(t.Context(), control.mint(t, defaultHeader(), defaultClaims())); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Verify = %v, want ErrUnknownKey", err)
	}
}
