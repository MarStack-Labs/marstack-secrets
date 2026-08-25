package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

const (
	tokenPrefix    = "mss_"
	tokenBytes     = 32
	DefaultTTL     = time.Hour
	MaximumTTL     = 30 * 24 * time.Hour
	NoBinding      = ""
	minTokenLength = len(tokenPrefix) + 43
)

type Token struct {
	Value     crypto.Sensitive
	Identity  Identity
	ExpiresAt time.Time
}

func newTokenValue() (crypto.Sensitive, error) {
	material := make([]byte, tokenBytes)
	if _, err := rand.Read(material); err != nil {
		return nil, err
	}
	defer crypto.Sensitive(material).Zero()

	return crypto.Sensitive(tokenPrefix + base64.RawURLEncoding.EncodeToString(material)), nil
}

func fingerprint(presented crypto.Sensitive) []byte {
	sum := sha256.Sum256(presented)
	return sum[:]
}

func looksLikeToken(presented crypto.Sensitive) bool {
	return len(presented) >= minTokenLength && strings.HasPrefix(string(presented), tokenPrefix)
}

const (
	reusable  = 0
	singleUse = 1
)

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type executor interface {
	querier
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}
