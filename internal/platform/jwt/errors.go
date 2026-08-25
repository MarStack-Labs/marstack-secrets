package jwt

import "errors"

var (
	ErrMalformed      = errors.New("jwt: token is malformed")
	ErrTooLarge       = errors.New("jwt: token is larger than the accepted maximum")
	ErrAlgorithm      = errors.New("jwt: unsupported signing algorithm")
	ErrCritical       = errors.New("jwt: token declares header extensions that are not understood")
	ErrUnknownKey     = errors.New("jwt: no verification key for the declared key id")
	ErrSignature      = errors.New("jwt: signature does not verify")
	ErrExpired        = errors.New("jwt: token has expired")
	ErrNotYetValid    = errors.New("jwt: token is not valid yet")
	ErrIssuedInFuture = errors.New("jwt: token claims to be issued in the future")
	ErrIssuer         = errors.New("jwt: unexpected issuer")
	ErrAudience       = errors.New("jwt: token is not addressed to this store")
	ErrSubject        = errors.New("jwt: token carries no subject")
	ErrTokenID        = errors.New("jwt: token carries no identifier")
	ErrTenant         = errors.New("jwt: token carries no tenant")
	ErrNoExpiry       = errors.New("jwt: token carries no expiry")
	ErrNoKeySource    = errors.New("jwt: a key source is required")
	ErrNoIssuer       = errors.New("jwt: an expected issuer is required")
	ErrNoAudience     = errors.New("jwt: an expected audience is required")
	ErrNegativeSkew   = errors.New("jwt: clock skew must not be negative")
)
