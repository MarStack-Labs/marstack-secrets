package auth

import "errors"

var (
	ErrNoDatabase       = errors.New("auth: a database is required")
	ErrUnauthenticated  = errors.New("auth: the presented credential is not valid")
	ErrUnknownIdentity  = errors.New("auth: no such identity")
	ErrIdentityExists   = errors.New("auth: identity already registered")
	ErrInvalidIdentity  = errors.New("auth: identity name is empty or too long")
	ErrInvalidKind      = errors.New("auth: unknown identity kind")
	ErrInvalidTenant    = errors.New("auth: tenant is empty or too long")
	ErrInvalidTTL       = errors.New("auth: time to live must be positive and within the maximum")
	ErrIdentityDisabled = errors.New("auth: identity is disabled")
)
