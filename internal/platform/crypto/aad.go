package crypto

import (
	"encoding/binary"
	"errors"
)

var (
	ErrEmptyTenant  = errors.New("crypto: tenant must not be empty")
	ErrEmptyPath    = errors.New("crypto: path must not be empty")
	ErrBadVersion   = errors.New("crypto: version must be greater than zero")
	ErrKEKVersion   = errors.New("crypto: kek version must be greater than zero")
	ErrFieldTooLong = errors.New("crypto: tenant or path exceeds the encodable length")
)

const maxFieldLen = 1 << 20

type AAD struct {
	Tenant  string
	Path    string
	Version int
}

func (a AAD) Validate() error {
	switch {
	case a.Tenant == "":
		return ErrEmptyTenant
	case a.Path == "":
		return ErrEmptyPath
	case a.Version < 1:
		return ErrBadVersion
	case len(a.Tenant) > maxFieldLen || len(a.Path) > maxFieldLen:
		return ErrFieldTooLong
	}
	return nil
}

func (a AAD) encode() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, 4+len(a.Tenant)+4+len(a.Path)+8)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(a.Tenant)))
	encoded = append(encoded, a.Tenant...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(a.Path)))
	encoded = append(encoded, a.Path...)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(a.Version))
	return encoded, nil
}
