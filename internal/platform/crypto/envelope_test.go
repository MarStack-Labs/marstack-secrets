package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func testKey(t *testing.T) Key {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey returned error: %v", err)
	}
	return key
}

func testAAD() AAD {
	return AAD{Tenant: "prod", Path: "secret/prod/payment-api", Version: 5}
}

func TestSealOpenRoundTrip(t *testing.T) {
	kek := testKey(t)
	plaintext := []byte("db_password=s3cr3t")

	envelope, err := Seal(kek, 1, plaintext, testAAD())
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	if envelope.KEKVersion != 1 {
		t.Errorf("KEKVersion = %d, want 1", envelope.KEKVersion)
	}
	if bytes.Contains(envelope.Ciphertext, plaintext) {
		t.Fatal("plaintext appears in the ciphertext")
	}
	if bytes.Contains(envelope.WrappedDEK, kek) {
		t.Fatal("the kek appears in the wrapped dek")
	}

	opened, err := Open(kek, envelope, testAAD())
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("Open() = %q, want %q", opened, plaintext)
	}
}

func TestSealHandlesEmptyPlaintext(t *testing.T) {
	kek := testKey(t)
	envelope, err := Seal(kek, 1, nil, testAAD())
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	opened, err := Open(kek, envelope, testAAD())
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if len(opened) != 0 {
		t.Errorf("Open() = %q, want empty", opened)
	}
}

func TestSealIsNonDeterministic(t *testing.T) {
	kek := testKey(t)
	plaintext := []byte("same value every time")

	first, err := Seal(kek, 1, plaintext, testAAD())
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	second, err := Seal(kek, 1, plaintext, testAAD())
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("sealing the same plaintext twice produced identical ciphertext")
	}
	if bytes.Equal(first.WrappedDEK, second.WrappedDEK) {
		t.Fatal("sealing twice reused the same data encryption key")
	}
}

func TestOpenRejectsAMovedCiphertext(t *testing.T) {
	kek := testKey(t)
	envelope, err := Seal(kek, 1, []byte("value"), testAAD())
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	elsewhere := map[string]AAD{
		"different tenant":  {Tenant: "staging", Path: "secret/prod/payment-api", Version: 5},
		"different path":    {Tenant: "prod", Path: "secret/prod/other", Version: 5},
		"different version": {Tenant: "prod", Path: "secret/prod/payment-api", Version: 6},
	}
	for name, aad := range elsewhere {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(kek, envelope, aad); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("Open with %s = %v, want ErrDecrypt", name, err)
			}
		})
	}
}

func TestAADEncodingIsUnambiguous(t *testing.T) {
	kek := testKey(t)
	left := AAD{Tenant: "a", Path: "bc", Version: 1}
	right := AAD{Tenant: "ab", Path: "c", Version: 1}

	envelope, err := Seal(kek, 1, []byte("value"), left)
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	if _, err := Open(kek, envelope, right); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Open with a differently split tenant and path = %v, want ErrDecrypt", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	kek := testKey(t)
	build := func(t *testing.T) Envelope {
		t.Helper()
		envelope, err := Seal(kek, 1, []byte("value"), testAAD())
		if err != nil {
			t.Fatalf("Seal returned error: %v", err)
		}
		return envelope
	}

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		envelope := build(t)
		envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 0x01
		if _, err := Open(kek, envelope, testAAD()); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Open = %v, want ErrDecrypt", err)
		}
	})

	t.Run("flipped nonce bit", func(t *testing.T) {
		envelope := build(t)
		envelope.Ciphertext[0] ^= 0x01
		if _, err := Open(kek, envelope, testAAD()); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Open = %v, want ErrDecrypt", err)
		}
	})

	t.Run("flipped wrapped dek bit", func(t *testing.T) {
		envelope := build(t)
		envelope.WrappedDEK[len(envelope.WrappedDEK)-1] ^= 0x01
		if _, err := Open(kek, envelope, testAAD()); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Open = %v, want ErrDecrypt", err)
		}
	})

	t.Run("truncated ciphertext", func(t *testing.T) {
		envelope := build(t)
		envelope.Ciphertext = envelope.Ciphertext[:4]
		if _, err := Open(kek, envelope, testAAD()); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Open = %v, want ErrDecrypt", err)
		}
	})

	t.Run("empty envelope", func(t *testing.T) {
		if _, err := Open(kek, Envelope{}, testAAD()); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Open = %v, want ErrDecrypt", err)
		}
	})

	t.Run("swapped wrapped dek and ciphertext", func(t *testing.T) {
		envelope := build(t)
		envelope.WrappedDEK, envelope.Ciphertext = envelope.Ciphertext, envelope.WrappedDEK
		if _, err := Open(kek, envelope, testAAD()); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Open = %v, want ErrDecrypt", err)
		}
	})
}

func TestOpenRejectsTheWrongKEK(t *testing.T) {
	envelope, err := Seal(testKey(t), 1, []byte("value"), testAAD())
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	if _, err := Open(testKey(t), envelope, testAAD()); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Open with an unrelated kek = %v, want ErrDecrypt", err)
	}
}

func TestRewrapLeavesTheCiphertextUntouched(t *testing.T) {
	current, next := testKey(t), testKey(t)
	plaintext := []byte("db_password=s3cr3t")

	envelope, err := Seal(current, 1, plaintext, testAAD())
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	before := bytes.Clone(envelope.Ciphertext)

	rotated, err := Rewrap(current, next, 2, envelope, testAAD())
	if err != nil {
		t.Fatalf("Rewrap returned error: %v", err)
	}

	if !bytes.Equal(rotated.Ciphertext, before) {
		t.Fatal("rotation re-encrypted the payload instead of only rewrapping the key")
	}
	if rotated.KEKVersion != 2 {
		t.Errorf("KEKVersion = %d, want 2", rotated.KEKVersion)
	}
	if bytes.Equal(rotated.WrappedDEK, envelope.WrappedDEK) {
		t.Fatal("the wrapped dek did not change")
	}

	opened, err := Open(next, rotated, testAAD())
	if err != nil {
		t.Fatalf("Open with the new kek returned error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("Open() = %q, want %q", opened, plaintext)
	}
	if _, err := Open(current, rotated, testAAD()); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Open with the retired kek = %v, want ErrDecrypt", err)
	}
}

func TestRewrapRejectsTheWrongCurrentKEK(t *testing.T) {
	envelope, err := Seal(testKey(t), 1, []byte("value"), testAAD())
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	if _, err := Rewrap(testKey(t), testKey(t), 2, envelope, testAAD()); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Rewrap with an unrelated kek = %v, want ErrDecrypt", err)
	}
}

func TestSealRejectsInvalidInput(t *testing.T) {
	valid := testKey(t)
	cases := map[string]struct {
		kek     Key
		version int
		aad     AAD
		want    error
	}{
		"short kek":        {kek: make(Key, 16), version: 1, aad: testAAD(), want: ErrKeySize},
		"zero kek version": {kek: valid, version: 0, aad: testAAD(), want: ErrKEKVersion},
		"empty tenant":     {kek: valid, version: 1, aad: AAD{Path: "p", Version: 1}, want: ErrEmptyTenant},
		"empty path":       {kek: valid, version: 1, aad: AAD{Tenant: "t", Version: 1}, want: ErrEmptyPath},
		"zero version":     {kek: valid, version: 1, aad: AAD{Tenant: "t", Path: "p"}, want: ErrBadVersion},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Seal(tc.kek, tc.version, []byte("value"), tc.aad); !errors.Is(err, tc.want) {
				t.Fatalf("Seal = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestOpenRejectsInvalidInput(t *testing.T) {
	if _, err := Open(make(Key, 16), Envelope{}, testAAD()); !errors.Is(err, ErrKeySize) {
		t.Errorf("Open with a short kek = %v, want ErrKeySize", err)
	}
	if _, err := Open(testKey(t), Envelope{}, AAD{}); !errors.Is(err, ErrEmptyTenant) {
		t.Errorf("Open with an empty aad = %v, want ErrEmptyTenant", err)
	}
}
