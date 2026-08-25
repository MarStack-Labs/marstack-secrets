package authn

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
)

func TestKindValidity(t *testing.T) {
	for _, kind := range []Kind{KindBootstrap, KindInstance, KindOIDC, KindService} {
		if !kind.Valid() {
			t.Errorf("%q should be a valid kind", kind)
		}
	}
	for _, kind := range []Kind{"", "robot", "INSTANCE"} {
		if kind.Valid() {
			t.Errorf("%q should not be a valid kind", kind)
		}
	}
}

func TestIdentityTravelsThroughTheContext(t *testing.T) {
	identity := Identity{ID: "instance/web-01", Kind: KindInstance, Tenant: "prod"}

	if _, present := IdentityFrom(context.Background()); present {
		t.Fatal("an empty context should carry no identity")
	}

	ctx := WithIdentity(context.Background(), identity)
	carried, present := IdentityFrom(ctx)
	if !present {
		t.Fatal("the identity did not survive the context")
	}
	if carried != identity {
		t.Errorf("IdentityFrom() = %+v, want %+v", carried, identity)
	}
}

func TestIdentityLogsOnlyItsDescription(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buffer, nil))

	logger.Info("request", "identity", Identity{ID: "instance/web-01", Kind: KindInstance, Tenant: "prod"})

	rendered := buffer.String()
	for _, field := range []string{"instance/web-01", "instance", "prod"} {
		if !bytes.Contains([]byte(rendered), []byte(field)) {
			t.Errorf("the log record is missing %q: %s", field, rendered)
		}
	}
}
