package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

const (
	keyTypeOKP   = "OKP"
	curveEd25519 = "Ed25519"
	useSignature = "sig"
	MaxJWKSBytes = 64 << 10
	maxKeysInSet = 32
)

var (
	ErrJWKSMalformed = errors.New("jwt: key set is malformed")
	ErrJWKSEmpty     = errors.New("jwt: key set contains no usable Ed25519 signing key")
	ErrJWKSTooLarge  = errors.New("jwt: key set is larger than the accepted maximum")
	ErrJWKSDuplicate = errors.New("jwt: key set repeats a key id")
)

type jsonWebKey struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	KeyID     string `json:"kid"`
	PublicKey string `json:"x"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

func ParseJWKS(raw []byte) (StaticKeys, error) {
	if len(raw) > MaxJWKSBytes {
		return nil, ErrJWKSTooLarge
	}

	var set jsonWebKeySet
	if err := strictUnmarshal(raw, &set); err != nil {
		return nil, ErrJWKSMalformed
	}
	if len(set.Keys) > maxKeysInSet {
		return nil, ErrJWKSTooLarge
	}

	keys := make(StaticKeys)
	for _, candidate := range set.Keys {
		if !usable(candidate) {
			continue
		}
		material, err := base64.RawURLEncoding.DecodeString(candidate.PublicKey)
		if err != nil || len(material) != ed25519.PublicKeySize {
			continue
		}
		if _, repeated := keys[candidate.KeyID]; repeated {
			return nil, ErrJWKSDuplicate
		}
		keys[candidate.KeyID] = ed25519.PublicKey(material)
	}

	if len(keys) == 0 {
		return nil, ErrJWKSEmpty
	}
	return keys, nil
}

func usable(candidate jsonWebKey) bool {
	switch {
	case candidate.KeyID == "":
		return false
	case candidate.KeyType != keyTypeOKP:
		return false
	case candidate.Curve != curveEd25519:
		return false
	case candidate.Use != "" && candidate.Use != useSignature:
		return false
	case candidate.Algorithm != "" && candidate.Algorithm != algorithmEdDSA:
		return false
	}
	return true
}
