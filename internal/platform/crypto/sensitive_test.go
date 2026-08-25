package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
)

func TestSensitiveIsRedactedInEveryRenderingPath(t *testing.T) {
	plaintext := "db_password=s3cr3t"
	value := Sensitive(plaintext)

	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("holding a value", "secret", value)

	encoded, err := json.Marshal(struct {
		Secret Sensitive `json:"secret"`
	}{Secret: value})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	renderings := map[string]string{
		"String":  value.String(),
		"%v":      fmt.Sprintf("%v", value),
		"%s":      fmt.Sprintf("%s", value),
		"%#v":     fmt.Sprintf("%#v", value),
		"slog":    logged.String(),
		"json":    string(encoded),
		"wrapped": fmt.Sprintf("%v", struct{ Secret Sensitive }{Secret: value}),
	}

	for name, rendering := range renderings {
		if rendering == "" {
			t.Errorf("%s produced an empty rendering", name)
		}
		if bytes.Contains([]byte(rendering), []byte(plaintext)) {
			t.Errorf("%s leaked the value: %s", name, rendering)
		}
	}
}

func TestSensitiveZeroClearsTheValue(t *testing.T) {
	value := Sensitive("db_password=s3cr3t")
	value.Zero()
	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("Zero did not clear the value")
	}
}

func TestSensitiveStillCarriesItsBytes(t *testing.T) {
	value := Sensitive("db_password=s3cr3t")
	if string(value) != "db_password=s3cr3t" {
		t.Fatalf("the underlying bytes changed: %q", string(value))
	}
}
