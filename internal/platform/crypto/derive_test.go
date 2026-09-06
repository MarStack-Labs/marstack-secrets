package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDeriveKeyIsDeterministic(t *testing.T) {
	root := testKey(t)

	first, err := DeriveKey(root, "kek/prod/1")
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}
	second, err := DeriveKey(root, "kek/prod/1")
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatal("the same root and label produced different keys")
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("the derived key is not usable: %v", err)
	}
}

func TestDeriveKeySeparatesLabelsAndRoots(t *testing.T) {
	root := testKey(t)
	other := testKey(t)

	prod, err := DeriveKey(root, "kek/prod/1")
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}
	staging, err := DeriveKey(root, "kek/staging/1")
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}
	rotated, err := DeriveKey(root, "kek/prod/2")
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}
	elsewhere, err := DeriveKey(other, "kek/prod/1")
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}

	distinct := map[string]Key{
		"another tenant":  staging,
		"another version": rotated,
		"another root":    elsewhere,
	}
	for name, key := range distinct {
		if bytes.Equal(prod, key) {
			t.Errorf("%s produced the same key", name)
		}
	}
	if bytes.Equal(prod, root) {
		t.Error("the derived key is the root key")
	}
}

func TestDeriveKeyRejectsInvalidInput(t *testing.T) {
	if _, err := DeriveKey(make(Key, 16), "kek/prod/1"); !errors.Is(err, ErrKeySize) {
		t.Errorf("DeriveKey with a short root = %v, want ErrKeySize", err)
	}
	if _, err := DeriveKey(testKey(t), ""); !errors.Is(err, ErrEmptyLabel) {
		t.Errorf("DeriveKey with an empty label = %v, want ErrEmptyLabel", err)
	}
}

func label(t *testing.T, parts ...string) string {
	t.Helper()

	made, err := Label(parts...)
	if err != nil {
		t.Fatalf("Label(%q) returned error: %v", parts, err)
	}
	return made
}

func TestLabelIsUnambiguous(t *testing.T) {
	if label(t, "a", "bc") == label(t, "ab", "c") {
		t.Fatal("differently split parts produced the same label")
	}
	if label(t, "kek", "prod", LabelInt(1)) == label(t, "kek", "prod", LabelInt(11)) {
		t.Fatal("different versions produced the same label")
	}
}

func TestLabelRefusesAPartItCannotPrefixHonestly(t *testing.T) {
	if _, err := Label("kek", strings.Repeat("x", maxFieldLen+1)); !errors.Is(err, ErrLabelPart) {
		t.Fatalf("Label with an over long part = %v, want ErrLabelPart", err)
	}
	if _, err := Label("kek", strings.Repeat("x", maxFieldLen)); err != nil {
		t.Fatalf("Label at the limit returned error: %v", err)
	}
}

func TestKeyCheckValueVerifiesTheRightKey(t *testing.T) {
	root := testKey(t)

	check, err := KeyCheckValue(root)
	if err != nil {
		t.Fatalf("KeyCheckValue returned error: %v", err)
	}
	if len(check) == 0 {
		t.Fatal("the key check value is empty")
	}
	if bytes.Contains(check, root) {
		t.Fatal("the key check value contains the key")
	}

	if err := VerifyKeyCheckValue(root, check); err != nil {
		t.Fatalf("VerifyKeyCheckValue on the right key returned error: %v", err)
	}
	if err := VerifyKeyCheckValue(testKey(t), check); !errors.Is(err, ErrKeyCheck) {
		t.Errorf("VerifyKeyCheckValue on another key = %v, want ErrKeyCheck", err)
	}

	tampered := bytes.Clone(check)
	tampered[0] ^= 0x01
	if err := VerifyKeyCheckValue(root, tampered); !errors.Is(err, ErrKeyCheck) {
		t.Errorf("VerifyKeyCheckValue on a tampered value = %v, want ErrKeyCheck", err)
	}
	if err := VerifyKeyCheckValue(root, nil); !errors.Is(err, ErrKeyCheck) {
		t.Errorf("VerifyKeyCheckValue on an empty value = %v, want ErrKeyCheck", err)
	}
}

func TestKeyCheckValueIsStableAcrossCalls(t *testing.T) {
	root := testKey(t)

	first, err := KeyCheckValue(root)
	if err != nil {
		t.Fatalf("KeyCheckValue returned error: %v", err)
	}
	second, err := KeyCheckValue(root)
	if err != nil {
		t.Fatalf("KeyCheckValue returned error: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("the key check value changed between calls")
	}
}
