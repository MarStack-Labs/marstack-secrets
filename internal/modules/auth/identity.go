package auth

import (
	"log/slog"
	"time"
)

const (
	maxIdentityLen = 128
	maxTenantLen   = 64
)

type Kind string

const (
	KindBootstrap Kind = "bootstrap"
	KindInstance  Kind = "instance"
	KindOIDC      Kind = "oidc"
	KindService   Kind = "service"
)

var kinds = map[Kind]struct{}{
	KindBootstrap: {},
	KindInstance:  {},
	KindOIDC:      {},
	KindService:   {},
}

func (k Kind) Valid() bool {
	_, known := kinds[k]
	return known
}

type Identity struct {
	ID        string
	Kind      Kind
	Tenant    string
	CreatedAt time.Time
	Disabled  bool
}

func (i Identity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", i.ID),
		slog.String("kind", string(i.Kind)),
		slog.String("tenant", i.Tenant),
	)
}

func validateIdentity(id string, kind Kind, tenant string) error {
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
