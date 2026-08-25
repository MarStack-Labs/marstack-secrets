package jwt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	algorithmEdDSA = "EdDSA"
	typeJWT        = "JWT"
	MaxTokenBytes  = 8 << 10
	MaxSkew        = time.Minute
)

type KeySource interface {
	PublicKey(ctx context.Context, keyID string) (ed25519.PublicKey, error)
}

type StaticKeys map[string]ed25519.PublicKey

func (s StaticKeys) PublicKey(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	key, known := s[keyID]
	if !known {
		return nil, ErrUnknownKey
	}
	return key, nil
}

type Audience []string

func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return ErrMalformed
	}
	*a = many
	return nil
}

func (a Audience) contains(value string) bool {
	for _, entry := range a {
		if entry == value {
			return true
		}
	}
	return false
}

type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	ID        string   `json:"jti"`
	Tenant    string   `json:"tenant"`
}

type header struct {
	Algorithm string   `json:"alg"`
	Type      string   `json:"typ"`
	KeyID     string   `json:"kid"`
	Critical  []string `json:"crit"`
}

type Options struct {
	Keys     KeySource
	Issuer   string
	Audience string
	Skew     time.Duration
	Now      func() time.Time
}

type Verifier struct {
	keys     KeySource
	issuer   string
	audience string
	skew     time.Duration
	now      func() time.Time
}

func NewVerifier(opts Options) (*Verifier, error) {
	switch {
	case opts.Keys == nil:
		return nil, ErrNoKeySource
	case opts.Issuer == "":
		return nil, ErrNoIssuer
	case opts.Audience == "":
		return nil, ErrNoAudience
	case opts.Skew < 0:
		return nil, ErrNegativeSkew
	}

	verifier := &Verifier{
		keys:     opts.Keys,
		issuer:   opts.Issuer,
		audience: opts.Audience,
		skew:     opts.Skew,
		now:      opts.Now,
	}
	if verifier.skew > MaxSkew {
		verifier.skew = MaxSkew
	}
	if verifier.now == nil {
		verifier.now = time.Now
	}
	return verifier, nil
}

func (v *Verifier) Verify(ctx context.Context, token []byte) (Claims, error) {
	if len(token) > MaxTokenBytes {
		return Claims{}, ErrTooLarge
	}

	parts, err := split(token)
	if err != nil {
		return Claims{}, err
	}

	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return Claims{}, err
	}
	head, err := decodeHeader(rawHeader)
	if err != nil {
		return Claims{}, err
	}

	signature, err := decodeSegment(parts[2])
	if err != nil {
		return Claims{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return Claims{}, ErrSignature
	}
	signed := token[:len(parts[0])+1+len(parts[1])]

	key, err := v.keys.PublicKey(ctx, head.KeyID)
	if err != nil {
		return Claims{}, err
	}
	if len(key) != ed25519.PublicKeySize {
		return Claims{}, ErrUnknownKey
	}
	if !ed25519.Verify(key, signed, signature) {
		return Claims{}, ErrSignature
	}

	rawClaims, err := decodeSegment(parts[1])
	if err != nil {
		return Claims{}, err
	}

	var claims Claims
	if err := strictUnmarshal(rawClaims, &claims); err != nil {
		return Claims{}, ErrMalformed
	}
	if err := v.check(claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func (v *Verifier) check(claims Claims) error {
	now := v.now().UTC()

	switch {
	case claims.ExpiresAt == 0:
		return ErrNoExpiry
	case claims.Subject == "":
		return ErrSubject
	case claims.ID == "":
		return ErrTokenID
	case claims.Tenant == "":
		return ErrTenant
	case claims.Issuer != v.issuer:
		return ErrIssuer
	case !claims.Audience.contains(v.audience):
		return ErrAudience
	}

	if !now.Add(-v.skew).Before(time.Unix(claims.ExpiresAt, 0).UTC()) {
		return ErrExpired
	}
	if claims.NotBefore != 0 && now.Add(v.skew).Before(time.Unix(claims.NotBefore, 0).UTC()) {
		return ErrNotYetValid
	}
	if claims.IssuedAt != 0 && now.Add(v.skew).Before(time.Unix(claims.IssuedAt, 0).UTC()) {
		return ErrIssuedInFuture
	}
	return nil
}

func split(token []byte) ([][]byte, error) {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	for _, part := range parts {
		if len(part) == 0 {
			return nil, ErrMalformed
		}
	}
	return parts, nil
}

func decodeSegment(segment []byte) ([]byte, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(segment)))
	written, err := base64.RawURLEncoding.Decode(decoded, segment)
	if err != nil {
		return nil, ErrMalformed
	}
	return decoded[:written], nil
}

func decodeHeader(raw []byte) (header, error) {
	var head header
	if err := strictUnmarshal(raw, &head); err != nil {
		return header{}, ErrMalformed
	}
	if head.Algorithm != algorithmEdDSA {
		return header{}, fmt.Errorf("%w: %q", ErrAlgorithm, head.Algorithm)
	}
	if head.Type != "" && head.Type != typeJWT {
		return header{}, ErrMalformed
	}
	if len(head.Critical) != 0 {
		return header{}, ErrCritical
	}
	return head, nil
}

func strictUnmarshal(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return ErrMalformed
	}
	return nil
}
