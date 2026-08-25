package crypto

import (
	"crypto/rand"
	"errors"
)

const (
	MinShares = 2
	MaxShares = 255
)

var (
	ErrShareCount     = errors.New("crypto: share count must be between 2 and 255")
	ErrThreshold      = errors.New("crypto: threshold must be between 2 and the share count")
	ErrEmptySecret    = errors.New("crypto: secret must not be empty")
	ErrShareLength    = errors.New("crypto: every share must have the same length")
	ErrMalformedShare = errors.New("crypto: share is malformed")
	ErrDuplicateShare = errors.New("crypto: the same share was supplied twice")
	ErrTooFewShares   = errors.New("crypto: at least two shares are required")
)

func Split(secret Sensitive, shares, threshold int) ([]Sensitive, error) {
	switch {
	case len(secret) == 0:
		return nil, ErrEmptySecret
	case shares < MinShares || shares > MaxShares:
		return nil, ErrShareCount
	case threshold < MinShares || threshold > shares:
		return nil, ErrThreshold
	}

	split := make([]Sensitive, shares)
	for index := range split {
		split[index] = make(Sensitive, len(secret)+1)
		split[index][len(secret)] = byte(index + 1)
	}

	coefficients := make([]byte, threshold)
	defer Sensitive(coefficients).Zero()

	for position, value := range secret {
		if _, err := rand.Read(coefficients[1:]); err != nil {
			return nil, err
		}
		coefficients[0] = value

		for index := range split {
			split[index][position] = evaluate(coefficients, byte(index+1))
		}
	}
	return split, nil
}

func Combine(shares []Sensitive) (Sensitive, error) {
	if len(shares) < MinShares {
		return nil, ErrTooFewShares
	}

	width := len(shares[0])
	if width < 2 {
		return nil, ErrMalformedShare
	}

	xs := make([]byte, len(shares))
	seen := make(map[byte]struct{}, len(shares))
	for index, share := range shares {
		if len(share) != width {
			return nil, ErrShareLength
		}
		x := share[width-1]
		if x == 0 {
			return nil, ErrMalformedShare
		}
		if _, duplicate := seen[x]; duplicate {
			return nil, ErrDuplicateShare
		}
		seen[x] = struct{}{}
		xs[index] = x
	}

	secret := make(Sensitive, width-1)
	ys := make([]byte, len(shares))
	defer Sensitive(ys).Zero()

	for position := range secret {
		for index, share := range shares {
			ys[index] = share[position]
		}
		secret[position] = interpolate(xs, ys)
	}
	return secret, nil
}

func evaluate(coefficients []byte, x byte) byte {
	result := coefficients[len(coefficients)-1]
	for index := len(coefficients) - 2; index >= 0; index-- {
		result = fieldMul(result, x) ^ coefficients[index]
	}
	return result
}

func interpolate(xs, ys []byte) byte {
	var result byte
	for i := range xs {
		basis := byte(1)
		for j := range xs {
			if i == j {
				continue
			}
			basis = fieldMul(basis, fieldDiv(xs[j], xs[i]^xs[j]))
		}
		result ^= fieldMul(ys[i], basis)
	}
	return result
}

func fieldMul(a, b byte) byte {
	var product byte
	for range 8 {
		product ^= a & -(b & 1)
		high := -((a >> 7) & 1)
		a <<= 1
		a ^= 0x1b & high
		b >>= 1
	}
	return product
}

func fieldDiv(a, b byte) byte {
	return fieldMul(a, fieldInverse(b))
}

func fieldInverse(a byte) byte {
	result := byte(1)
	base := a
	for exponent := 254; exponent > 0; exponent >>= 1 {
		if exponent&1 == 1 {
			result = fieldMul(result, base)
		}
		base = fieldMul(base, base)
	}
	return result
}
