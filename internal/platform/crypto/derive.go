package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
)

const keyCheckLabel = "marstack-secrets/key-check/v1"

var (
	ErrEmptyLabel = errors.New("crypto: derivation label must not be empty")
	ErrKeyCheck   = errors.New("crypto: key check value does not match")
)

func DeriveKey(root Key, label string) (Key, error) {
	if err := root.Validate(); err != nil {
		return nil, err
	}
	if label == "" {
		return nil, ErrEmptyLabel
	}
	derived, err := hkdf.Key(sha256.New, root, nil, label, KeySize)
	if err != nil {
		return nil, err
	}
	return Key(derived), nil
}

func Label(parts ...string) string {
	encoded := make([]byte, 0, 32)
	for _, part := range parts {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(part)))
		encoded = append(encoded, part...)
	}
	return string(encoded)
}

func LabelInt(value int) string {
	return strconv.Itoa(value)
}

func KeyCheckValue(root Key) ([]byte, error) {
	if err := root.Validate(); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, root)
	mac.Write([]byte(keyCheckLabel))
	return mac.Sum(nil), nil
}

func VerifyKeyCheckValue(root Key, expected []byte) error {
	actual, err := KeyCheckValue(root)
	if err != nil {
		return err
	}
	if !hmac.Equal(actual, expected) {
		return ErrKeyCheck
	}
	return nil
}
