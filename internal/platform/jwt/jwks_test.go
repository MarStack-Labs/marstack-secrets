package jwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
)

func publicKeyMaterial(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return public, base64.RawURLEncoding.EncodeToString(public)
}

func TestParseJWKSReadsEd25519Keys(t *testing.T) {
	first, firstEncoded := publicKeyMaterial(t)
	second, secondEncoded := publicKeyMaterial(t)

	raw := fmt.Sprintf(`{"keys":[
		{"kty":"OKP","crv":"Ed25519","kid":"cp-2026-08","x":%q,"use":"sig","alg":"EdDSA"},
		{"kty":"OKP","crv":"Ed25519","kid":"cp-2026-09","x":%q}
	]}`, firstEncoded, secondEncoded)

	keys, err := ParseJWKS([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJWKS returned error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("ParseJWKS returned %d keys, want 2", len(keys))
	}
	if !bytes.Equal(keys["cp-2026-08"], first) || !bytes.Equal(keys["cp-2026-09"], second) {
		t.Error("the parsed keys do not match the originals")
	}
}

func TestParseJWKSSkipsKeysItCannotUse(t *testing.T) {
	usableKey, encoded := publicKeyMaterial(t)

	raw := fmt.Sprintf(`{"keys":[
		{"kty":"RSA","kid":"rsa-1","n":"abc","e":"AQAB"},
		{"kty":"OKP","crv":"X25519","kid":"exchange-1","x":%q},
		{"kty":"OKP","crv":"Ed25519","kid":"encryption-1","x":%q,"use":"enc"},
		{"kty":"OKP","crv":"Ed25519","kid":"wrong-alg","x":%q,"alg":"HS256"},
		{"kty":"OKP","crv":"Ed25519","kid":"","x":%q},
		{"kty":"OKP","crv":"Ed25519","kid":"short","x":"YWJj"},
		{"kty":"OKP","crv":"Ed25519","kid":"not-base64","x":"!!!"},
		{"kty":"OKP","crv":"Ed25519","kid":"good","x":%q}
	]}`, encoded, encoded, encoded, encoded, encoded)

	keys, err := ParseJWKS([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJWKS returned error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("ParseJWKS returned %d keys, want only the usable one: %v", len(keys), keys)
	}
	if !bytes.Equal(keys["good"], usableKey) {
		t.Error("the surviving key is not the one that should have survived")
	}
}

func TestParseJWKSRejectsUnusableSets(t *testing.T) {
	_, encoded := publicKeyMaterial(t)

	cases := map[string]struct {
		raw  []byte
		want error
	}{
		"not json":      {raw: []byte("nope"), want: ErrJWKSMalformed},
		"trailing json": {raw: []byte(`{"keys":[]}{}`), want: ErrJWKSMalformed},
		"no keys":       {raw: []byte(`{"keys":[]}`), want: ErrJWKSEmpty},
		"only unusable": {raw: []byte(`{"keys":[{"kty":"RSA","kid":"rsa-1"}]}`), want: ErrJWKSEmpty},
		"too large":     {raw: bytes.Repeat([]byte("a"), MaxJWKSBytes+1), want: ErrJWKSTooLarge},
		"duplicate kid": {
			raw: []byte(fmt.Sprintf(`{"keys":[
				{"kty":"OKP","crv":"Ed25519","kid":"same","x":%q},
				{"kty":"OKP","crv":"Ed25519","kid":"same","x":%q}
			]}`, encoded, encoded)),
			want: ErrJWKSDuplicate,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJWKS(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("ParseJWKS = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAParsedKeySetVerifiesARealToken(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	raw := fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":%q,"x":%q}]}`,
		testKeyID, base64.RawURLEncoding.EncodeToString(public))

	keys, err := ParseJWKS([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJWKS returned error: %v", err)
	}

	control := &signer{keyID: testKeyID, private: private, public: public}
	verifier := newVerifier(t, keys)

	if _, err := verifier.Verify(t.Context(), control.mint(t, defaultHeader(), defaultClaims())); err != nil {
		t.Fatalf("a token signed by the published key did not verify: %v", err)
	}
}
