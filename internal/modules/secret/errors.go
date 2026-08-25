package secret

import "errors"

var (
	ErrNotFound       = errors.New("secret: not found")
	ErrConflict       = errors.New("secret: the expected version does not match the current version")
	ErrDeleted        = errors.New("secret: version is deleted")
	ErrDestroyed      = errors.New("secret: version is destroyed")
	ErrInvalidTenant  = errors.New("secret: tenant is empty or too long")
	ErrInvalidPath    = errors.New("secret: path is empty or too long")
	ErrInvalidVersion = errors.New("secret: version must not be negative")
	ErrMaxVersions    = errors.New("secret: max versions must be greater than zero")
	ErrNoSealer       = errors.New("secret: a sealer is required to write a version")
)
