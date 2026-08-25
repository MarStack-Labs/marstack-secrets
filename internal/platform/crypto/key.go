package crypto

import (
	"crypto/rand"
	"errors"
	"log/slog"
)

const KeySize = 32

const redacted = "[redacted]"

var ErrKeySize = errors.New("crypto: key must be 32 bytes")

type Key []byte

func NewKey() (Key, error) {
	key := make(Key, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func (k Key) Validate() error {
	if len(k) != KeySize {
		return ErrKeySize
	}
	return nil
}

func (k Key) Zero() {
	for i := range k {
		k[i] = 0
	}
}

func (k Key) String() string {
	return redacted
}

func (k Key) GoString() string {
	return redacted
}

func (k Key) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

func (k Key) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}
