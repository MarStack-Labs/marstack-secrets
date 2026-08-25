package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

var ErrDecrypt = errors.New("crypto: decryption failed")

type Envelope struct {
	KEKVersion int
	WrappedDEK []byte
	Ciphertext []byte
}

func Seal(kek Key, kekVersion int, plaintext []byte, aad AAD) (Envelope, error) {
	if err := kek.Validate(); err != nil {
		return Envelope{}, err
	}
	if kekVersion < 1 {
		return Envelope{}, ErrKEKVersion
	}
	encodedAAD, err := aad.encode()
	if err != nil {
		return Envelope{}, err
	}

	dek, err := NewKey()
	if err != nil {
		return Envelope{}, err
	}
	defer dek.Zero()

	ciphertext, err := sealWith(dek, plaintext, encodedAAD)
	if err != nil {
		return Envelope{}, err
	}
	wrappedDEK, err := sealWith(kek, dek, encodedAAD)
	if err != nil {
		return Envelope{}, err
	}

	return Envelope{
		KEKVersion: kekVersion,
		WrappedDEK: wrappedDEK,
		Ciphertext: ciphertext,
	}, nil
}

func Open(kek Key, envelope Envelope, aad AAD) ([]byte, error) {
	if err := kek.Validate(); err != nil {
		return nil, err
	}
	encodedAAD, err := aad.encode()
	if err != nil {
		return nil, err
	}

	dek, err := unwrapDEK(kek, envelope.WrappedDEK, encodedAAD)
	if err != nil {
		return nil, err
	}
	defer dek.Zero()

	return openWith(dek, envelope.Ciphertext, encodedAAD)
}

func Rewrap(current Key, next Key, nextVersion int, envelope Envelope, aad AAD) (Envelope, error) {
	if err := current.Validate(); err != nil {
		return Envelope{}, err
	}
	if err := next.Validate(); err != nil {
		return Envelope{}, err
	}
	if nextVersion < 1 {
		return Envelope{}, ErrKEKVersion
	}
	encodedAAD, err := aad.encode()
	if err != nil {
		return Envelope{}, err
	}

	dek, err := unwrapDEK(current, envelope.WrappedDEK, encodedAAD)
	if err != nil {
		return Envelope{}, err
	}
	defer dek.Zero()

	wrappedDEK, err := sealWith(next, dek, encodedAAD)
	if err != nil {
		return Envelope{}, err
	}

	return Envelope{
		KEKVersion: nextVersion,
		WrappedDEK: wrappedDEK,
		Ciphertext: envelope.Ciphertext,
	}, nil
}

func unwrapDEK(kek Key, wrapped []byte, encodedAAD []byte) (Key, error) {
	plaintext, err := openWith(kek, wrapped, encodedAAD)
	if err != nil {
		return nil, err
	}
	dek := Key(plaintext)
	if err := dek.Validate(); err != nil {
		dek.Zero()
		return nil, ErrDecrypt
	}
	return dek, nil
}

func sealWith(key Key, plaintext []byte, encodedAAD []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, encodedAAD), nil
}

func openWith(key Key, blob []byte, encodedAAD []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDecrypt
	}
	nonce, ciphertext := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, encodedAAD)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

func newAEAD(key Key) (cipher.AEAD, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
