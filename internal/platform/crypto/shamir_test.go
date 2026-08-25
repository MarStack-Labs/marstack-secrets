package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func combinations(pool []Sensitive, pick int) [][]Sensitive {
	if pick == 0 {
		return [][]Sensitive{{}}
	}
	var result [][]Sensitive
	for index := range pool {
		if len(pool)-index < pick {
			break
		}
		for _, rest := range combinations(pool[index+1:], pick-1) {
			result = append(result, append([]Sensitive{pool[index]}, rest...))
		}
	}
	return result
}

func TestAnyThresholdSubsetReconstructsTheSecret(t *testing.T) {
	secret := Sensitive("a 32 byte root key for testing!!")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split returned error: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("Split returned %d shares, want 5", len(shares))
	}

	subsets := combinations(shares, 3)
	if len(subsets) != 10 {
		t.Fatalf("expected 10 subsets of three shares, got %d", len(subsets))
	}
	for _, subset := range subsets {
		recovered, err := Combine(subset)
		if err != nil {
			t.Fatalf("Combine returned error: %v", err)
		}
		if !bytes.Equal(recovered, secret) {
			t.Fatalf("Combine() = %q, want %q", string(recovered), string(secret))
		}
	}
}

func TestMoreSharesThanTheThresholdStillWork(t *testing.T) {
	secret := Sensitive("a 32 byte root key for testing!!")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split returned error: %v", err)
	}

	recovered, err := Combine(shares)
	if err != nil {
		t.Fatalf("Combine returned error: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Errorf("Combine() with every share = %q, want %q", string(recovered), string(secret))
	}
}

func TestFewerSharesThanTheThresholdRevealNothing(t *testing.T) {
	secret := Sensitive("a 32 byte root key for testing!!")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split returned error: %v", err)
	}

	for _, subset := range combinations(shares, 2) {
		recovered, err := Combine(subset)
		if err != nil {
			t.Fatalf("Combine returned error: %v", err)
		}
		if bytes.Equal(recovered, secret) {
			t.Fatal("two shares reconstructed a secret that needs three")
		}
	}
}

func TestASingleShareRevealsNothing(t *testing.T) {
	secret := Sensitive("a 32 byte root key for testing!!")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split returned error: %v", err)
	}

	for index, share := range shares {
		if bytes.Contains(share, secret) {
			t.Fatalf("share %d contains the secret", index+1)
		}
		if bytes.Equal(share[:len(secret)], secret) {
			t.Fatalf("share %d is the secret", index+1)
		}
	}
}

func TestSharesAreDistinctAndCarryTheirIndex(t *testing.T) {
	shares, err := Split(Sensitive("a 32 byte root key for testing!!"), 5, 3)
	if err != nil {
		t.Fatalf("Split returned error: %v", err)
	}

	seen := make(map[string]struct{})
	for index, share := range shares {
		if got := share[len(share)-1]; got != byte(index+1) {
			t.Errorf("share %d carries index %d", index+1, got)
		}
		seen[string(share)] = struct{}{}
	}
	if len(seen) != len(shares) {
		t.Errorf("got %d distinct shares out of %d", len(seen), len(shares))
	}
}

func TestSplitIsNotDeterministic(t *testing.T) {
	secret := Sensitive("a 32 byte root key for testing!!")

	first, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split returned error: %v", err)
	}
	second, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split returned error: %v", err)
	}

	for index := range first {
		if bytes.Equal(first[index], second[index]) {
			t.Fatalf("share %d is identical across two splits", index+1)
		}
	}
}

func TestSplitHandlesTheBoundaries(t *testing.T) {
	secret := Sensitive{0x00, 0xFF, 0x01}

	shares, err := Split(secret, 255, 2)
	if err != nil {
		t.Fatalf("Split with the maximum share count returned error: %v", err)
	}
	recovered, err := Combine(shares[:2])
	if err != nil {
		t.Fatalf("Combine returned error: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Errorf("Combine() = %v, want %v", recovered, secret)
	}

	all, err := Split(secret, 3, 3)
	if err != nil {
		t.Fatalf("Split where the threshold equals the share count returned error: %v", err)
	}
	recovered, err = Combine(all)
	if err != nil {
		t.Fatalf("Combine returned error: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Errorf("Combine() = %v, want %v", recovered, secret)
	}
}

func TestSplitRejectsInvalidParameters(t *testing.T) {
	secret := Sensitive("a 32 byte root key for testing!!")

	cases := map[string]struct {
		secret    Sensitive
		shares    int
		threshold int
		want      error
	}{
		"empty secret":           {secret: nil, shares: 5, threshold: 3, want: ErrEmptySecret},
		"one share":              {secret: secret, shares: 1, threshold: 1, want: ErrShareCount},
		"too many shares":        {secret: secret, shares: 256, threshold: 3, want: ErrShareCount},
		"threshold below two":    {secret: secret, shares: 5, threshold: 1, want: ErrThreshold},
		"threshold above shares": {secret: secret, shares: 3, threshold: 4, want: ErrThreshold},
		"negative threshold":     {secret: secret, shares: 5, threshold: -1, want: ErrThreshold},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Split(tc.secret, tc.shares, tc.threshold); !errors.Is(err, tc.want) {
				t.Fatalf("Split = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCombineRejectsMalformedInput(t *testing.T) {
	shares, err := Split(Sensitive("a 32 byte root key for testing!!"), 5, 3)
	if err != nil {
		t.Fatalf("Split returned error: %v", err)
	}

	zeroIndex := bytes.Clone(shares[0])
	zeroIndex[len(zeroIndex)-1] = 0

	cases := map[string]struct {
		shares []Sensitive
		want   error
	}{
		"one share":        {shares: shares[:1], want: ErrTooFewShares},
		"no shares":        {shares: nil, want: ErrTooFewShares},
		"duplicate share":  {shares: []Sensitive{shares[0], shares[0]}, want: ErrDuplicateShare},
		"mismatched width": {shares: []Sensitive{shares[0], shares[1][:8]}, want: ErrShareLength},
		"index zero":       {shares: []Sensitive{Sensitive(zeroIndex), shares[1]}, want: ErrMalformedShare},
		"share too short":  {shares: []Sensitive{{0x01}, {0x02}}, want: ErrMalformedShare},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Combine(tc.shares); !errors.Is(err, tc.want) {
				t.Fatalf("Combine = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSplitAndCombineCarryARealKey(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey returned error: %v", err)
	}

	shares, err := Split(Sensitive(key), 5, 3)
	if err != nil {
		t.Fatalf("Split returned error: %v", err)
	}
	recovered, err := Combine([]Sensitive{shares[4], shares[1], shares[2]})
	if err != nil {
		t.Fatalf("Combine returned error: %v", err)
	}
	if !bytes.Equal(recovered, key) {
		t.Fatal("the reconstructed key does not match the original")
	}

	restored := Key(recovered)
	if err := restored.Validate(); err != nil {
		t.Fatalf("the reconstructed key is not usable: %v", err)
	}
	envelope, err := Seal(restored, 1, []byte("value"), testAAD())
	if err != nil {
		t.Fatalf("Seal with the reconstructed key returned error: %v", err)
	}
	if _, err := Open(key, envelope, testAAD()); err != nil {
		t.Fatalf("the original key could not open what the reconstructed key sealed: %v", err)
	}
}

func TestFieldArithmetic(t *testing.T) {
	for value := 1; value < 256; value++ {
		a := byte(value)
		inverse := fieldInverse(a)
		if product := fieldMul(a, inverse); product != 1 {
			t.Fatalf("fieldMul(%d, fieldInverse(%d)) = %d, want 1", a, a, product)
		}
		if quotient := fieldDiv(a, a); quotient != 1 {
			t.Fatalf("fieldDiv(%d, %d) = %d, want 1", a, a, quotient)
		}
	}
	if got := fieldMul(0, 42); got != 0 {
		t.Errorf("fieldMul(0, 42) = %d, want 0", got)
	}
	if got := fieldMul(42, 0); got != 0 {
		t.Errorf("fieldMul(42, 0) = %d, want 0", got)
	}
}
