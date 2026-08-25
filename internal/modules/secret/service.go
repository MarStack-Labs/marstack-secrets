package secret

import (
	"context"
	"log/slog"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

type Cipher interface {
	Seal(ctx context.Context, tenant string, plaintext []byte, aad crypto.AAD) (crypto.Envelope, error)
	Open(ctx context.Context, tenant string, envelope crypto.Envelope, aad crypto.AAD) (crypto.Sensitive, error)
}

type Value struct {
	Tenant    string
	Path      string
	Version   int
	Data      crypto.Sensitive
	CreatedAt time.Time
}

func (v Value) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("tenant", v.Tenant),
		slog.String("path", v.Path),
		slog.Int("version", v.Version),
	)
}

type Service struct {
	store  *Store
	cipher Cipher
}

func NewService(store *Store, cipher Cipher) (*Service, error) {
	if store == nil {
		return nil, ErrNoStore
	}
	if cipher == nil {
		return nil, ErrNoCipher
	}
	return &Service{store: store, cipher: cipher}, nil
}

func (s *Service) Migrate(ctx context.Context) error {
	return s.store.Migrate(ctx)
}

func (s *Service) Put(ctx context.Context, tenant, path string, plaintext []byte, expect Expectation) (int, error) {
	if err := validateLocation(tenant, path); err != nil {
		return 0, err
	}
	return s.store.Put(ctx, tenant, path, expect, func(version int) (crypto.Envelope, error) {
		return s.cipher.Seal(ctx, tenant, plaintext, locate(tenant, path, version))
	})
}

func (s *Service) Get(ctx context.Context, tenant, path string, version int) (Value, error) {
	record, err := s.store.Get(ctx, tenant, path, version)
	if err != nil {
		return Value{}, err
	}

	plaintext, err := s.cipher.Open(ctx, tenant, record.Envelope, locate(tenant, path, record.Version))
	if err != nil {
		return Value{}, err
	}

	return Value{
		Tenant:    record.Tenant,
		Path:      record.Path,
		Version:   record.Version,
		Data:      plaintext,
		CreatedAt: record.CreatedAt,
	}, nil
}

func (s *Service) Metadata(ctx context.Context, tenant, path string) (Metadata, error) {
	return s.store.Metadata(ctx, tenant, path)
}

func (s *Service) Delete(ctx context.Context, tenant, path string, versions ...int) error {
	return s.store.Delete(ctx, tenant, path, versions...)
}

func (s *Service) Undelete(ctx context.Context, tenant, path string, versions ...int) error {
	return s.store.Undelete(ctx, tenant, path, versions...)
}

func (s *Service) Destroy(ctx context.Context, tenant, path string, versions ...int) error {
	return s.store.Destroy(ctx, tenant, path, versions...)
}

func locate(tenant, path string, version int) crypto.AAD {
	return crypto.AAD{Tenant: tenant, Path: path, Version: version}
}
