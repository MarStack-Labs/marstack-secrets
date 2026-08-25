package auth

import "github.com/marstack-labs/marstack-secrets/internal/platform/authn"

const (
	maxIdentityLen = 128
	maxTenantLen   = 64
)

func validateIdentity(id string, kind authn.Kind, tenant string) error {
	switch {
	case id == "" || len(id) > maxIdentityLen:
		return ErrInvalidIdentity
	case !kind.Valid():
		return ErrInvalidKind
	case tenant == "" || len(tenant) > maxTenantLen:
		return ErrInvalidTenant
	}
	return nil
}
