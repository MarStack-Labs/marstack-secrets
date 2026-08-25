package authn

import (
	"context"
	"log/slog"
	"time"
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

type contextKey struct{}

var identityKey contextKey

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityKey, identity)
}

func IdentityFrom(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityKey).(Identity)
	return identity, ok
}
