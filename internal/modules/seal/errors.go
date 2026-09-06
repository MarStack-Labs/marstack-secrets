package seal

import "errors"

var (
	ErrNoDatabase         = errors.New("seal: a database is required")
	ErrAlreadyInitialized = errors.New("seal: the store is already initialized")
	ErrNotInitialized     = errors.New("seal: the store is not initialized")
	ErrSealed             = errors.New("seal: the store is sealed")
	ErrUnsealFailed       = errors.New("seal: the supplied shares do not reconstruct the root key")
	ErrInvalidShare       = errors.New("seal: share is empty or malformed")
	ErrKEKVersion         = errors.New("seal: key encryption key version is out of range")
)
