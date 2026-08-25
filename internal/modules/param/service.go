package param

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authn"
	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

const (
	maxReferences   = 8
	secretNamespace = "secret"
)

var (
	ErrNoStore            = errors.New("param: a store is required")
	ErrNoAuthorizer       = errors.New("param: an authorizer is required")
	ErrNoSecrets          = errors.New("param: a secret reader is required")
	ErrBadReference       = errors.New("param: a reference must name a secret in the same tenant")
	ErrTooManyReferences  = errors.New("param: too many references in one value")
	ErrReferenceForbidden = errors.New("param: the caller may not read a referenced secret")
	ErrReferenceMissing   = errors.New("param: a referenced secret does not exist")
)

var reference = regexp.MustCompile(`\$\{([^{}$]+)\}`)

type Secrets interface {
	Reveal(ctx context.Context, tenant, path string) (crypto.Sensitive, int, error)
}

type Authorizer interface {
	Authorize(ctx context.Context, identity authn.Identity, tenant, path string, capability authz.Capability) (authz.Decision, error)
}

type Resolved struct {
	Parameter
	Sensitive  bool
	References []string
}

type Service struct {
	store      *Store
	authorizer Authorizer
	secrets    Secrets
}

func NewService(store *Store, authorizer Authorizer, secrets Secrets) (*Service, error) {
	switch {
	case store == nil:
		return nil, ErrNoStore
	case authorizer == nil:
		return nil, ErrNoAuthorizer
	case secrets == nil:
		return nil, ErrNoSecrets
	}
	return &Service{store: store, authorizer: authorizer, secrets: secrets}, nil
}

func (s *Service) Store() *Store {
	return s.store
}

func (s *Service) Resolve(ctx context.Context, identity authn.Identity, tenant, path string) (Resolved, error) {
	found, err := s.store.Resolve(ctx, tenant, path)
	if err != nil {
		return Resolved{}, err
	}

	matches := reference.FindAllStringSubmatch(found.Value, -1)
	if len(matches) == 0 {
		return Resolved{Parameter: found}, nil
	}
	if len(matches) > maxReferences {
		return Resolved{}, ErrTooManyReferences
	}

	resolved := Resolved{Parameter: found, Sensitive: true}
	value := found.Value

	for _, match := range matches {
		target := strings.TrimSpace(match[1])
		if err := acceptable(tenant, target); err != nil {
			return Resolved{}, fmt.Errorf("%w: %q", err, target)
		}

		decision, err := s.authorizer.Authorize(ctx, identity, tenant, target, authz.Read)
		if err != nil {
			return Resolved{}, err
		}
		if !decision.Allowed {
			return Resolved{}, fmt.Errorf("%w: %q", ErrReferenceForbidden, target)
		}

		plaintext, _, err := s.secrets.Reveal(ctx, tenant, strings.TrimPrefix(target, secretNamespace+"/"+tenant+"/"))
		if err != nil {
			return Resolved{}, errors.Join(ErrReferenceMissing, err)
		}

		value = strings.ReplaceAll(value, match[0], string(plaintext))
		plaintext.Zero()
		resolved.References = append(resolved.References, target)
	}

	resolved.Value = value
	return resolved, nil
}

func acceptable(tenant, target string) error {
	prefix := secretNamespace + "/" + tenant + "/"
	if !strings.HasPrefix(target, prefix) {
		return ErrBadReference
	}
	if !safePath(strings.TrimPrefix(target, prefix)) {
		return ErrBadReference
	}
	return nil
}
