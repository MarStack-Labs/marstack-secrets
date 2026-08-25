package seal

import (
	"context"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

type Cipher struct {
	manager *Manager
}

func (c *Cipher) Seal(_ context.Context, tenant string, plaintext []byte, aad crypto.AAD) (crypto.Envelope, error) {
	kek, err := c.manager.deriveKEK(tenant, currentKEKVersion)
	if err != nil {
		return crypto.Envelope{}, err
	}
	defer kek.Zero()

	return crypto.Seal(kek, currentKEKVersion, plaintext, aad)
}

func (c *Cipher) Open(_ context.Context, tenant string, envelope crypto.Envelope, aad crypto.AAD) (crypto.Sensitive, error) {
	if envelope.KEKVersion < 1 {
		return nil, crypto.ErrDecrypt
	}

	kek, err := c.manager.deriveKEK(tenant, envelope.KEKVersion)
	if err != nil {
		return nil, err
	}
	defer kek.Zero()

	plaintext, err := crypto.Open(kek, envelope, aad)
	if err != nil {
		return nil, err
	}
	return crypto.Sensitive(plaintext), nil
}
