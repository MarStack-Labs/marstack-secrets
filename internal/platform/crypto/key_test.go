package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"
)

func TestNewKeyIsFullLengthAndRandom(t *testing.T) {
	seen := make(map[string]struct{})
	for range 64 {
		key, err := NewKey()
		if err != nil {
			t.Fatalf("NewKey returned error: %v", err)
		}
		if len(key) != KeySize {
			t.Fatalf("key length = %d, want %d", len(key), KeySize)
		}
		if bytes.Equal(key, make([]byte, KeySize)) {
			t.Fatal("key is all zeroes")
		}
		seen[string(key)] = struct{}{}
	}
	if len(seen) != 64 {
		t.Fatalf("got %d distinct keys out of 64", len(seen))
	}
}

func TestValidateRejectsWrongLength(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		if err := make(Key, size).Validate(); !errors.Is(err, ErrKeySize) {
			t.Errorf("Validate() on a %d byte key = %v, want ErrKeySize", size, err)
		}
	}
}

func TestZeroClearsKeyMaterial(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey returned error: %v", err)
	}
	key.Zero()
	if !bytes.Equal(key, make([]byte, KeySize)) {
		t.Fatal("Zero did not clear the key")
	}
}

func TestKeyIsRedactedInEveryRenderingPath(t *testing.T) {
	key := Key(bytes.Repeat([]byte{0xAB}, KeySize))
	material := "abababab"

	renderings := map[string]string{
		"String":  key.String(),
		"%v":      fmt.Sprintf("%v", key),
		"%s":      fmt.Sprintf("%s", key),
		"%#v":     fmt.Sprintf("%#v", key),
		"slog":    logKey(t, key),
		"json":    marshalKey(t, key),
		"wrapped": fmt.Sprintf("%v", struct{ Secret Key }{Secret: key}),
	}

	for name, rendering := range renderings {
		if rendering == "" {
			t.Errorf("%s produced an empty rendering", name)
		}
		if bytes.Contains([]byte(rendering), []byte(material)) {
			t.Errorf("%s leaked key material: %s", name, rendering)
		}
		if bytes.Contains([]byte(rendering), key) {
			t.Errorf("%s leaked raw key bytes: %q", name, rendering)
		}
	}
}

func logKey(t *testing.T, key Key) string {
	t.Helper()
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("holding a key", "kek", key)
	return buf.String()
}

func marshalKey(t *testing.T, key Key) string {
	t.Helper()
	encoded, err := json.Marshal(struct {
		KEK Key `json:"kek"`
	}{KEK: key})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	return string(encoded)
}
