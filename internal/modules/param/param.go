package param

import (
	"errors"
	"strconv"
	"strings"
)

const (
	KindString     Kind = "string"
	KindInt        Kind = "int"
	KindBool       Kind = "bool"
	KindStringList Kind = "stringlist"

	Namespace     = "param"
	maxTenantLen  = 64
	maxPathLen    = 512
	maxValueBytes = 64 << 10
	listSeparator = ","
)

var (
	ErrNoDatabase    = errors.New("param: a database is required")
	ErrNoCipher      = errors.New("param: a cipher is required")
	ErrNotFound      = errors.New("param: no such parameter")
	ErrInvalidTenant = errors.New("param: tenant is empty or too long")
	ErrInvalidPath   = errors.New("param: path is empty, too long, or contains a traversal")
	ErrInvalidKind   = errors.New("param: unknown parameter kind")
	ErrInvalidValue  = errors.New("param: the value does not match its declared kind")
	ErrValueTooLarge = errors.New("param: the value is larger than the accepted maximum")
)

type Kind string

var kinds = map[Kind]struct{}{
	KindString:     {},
	KindInt:        {},
	KindBool:       {},
	KindStringList: {},
}

func (k Kind) Valid() bool {
	_, known := kinds[k]
	return known
}

func (k Kind) accepts(raw string) error {
	switch k {
	case KindString:
		return nil
	case KindInt:
		if _, err := strconv.Atoi(strings.TrimSpace(raw)); err != nil {
			return ErrInvalidValue
		}
		return nil
	case KindBool:
		if _, err := strconv.ParseBool(strings.TrimSpace(raw)); err != nil {
			return ErrInvalidValue
		}
		return nil
	case KindStringList:
		for _, entry := range strings.Split(raw, listSeparator) {
			if strings.TrimSpace(entry) == "" {
				return ErrInvalidValue
			}
		}
		return nil
	default:
		return ErrInvalidKind
	}
}

func validate(tenant, path string, kind Kind, raw string) error {
	switch {
	case tenant == "" || len(tenant) > maxTenantLen:
		return ErrInvalidTenant
	case !safePath(path):
		return ErrInvalidPath
	case !kind.Valid():
		return ErrInvalidKind
	case len(raw) > maxValueBytes:
		return ErrValueTooLarge
	}
	return kind.accepts(raw)
}

func safePath(path string) bool {
	if path == "" || len(path) > maxPathLen {
		return false
	}
	if strings.HasPrefix(path, "/") || strings.Contains(path, "//") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		if strings.TrimSpace(segment) != segment {
			return false
		}
	}
	return true
}

func inheritanceChain(path string) []string {
	segments := strings.Split(path, "/")
	leaf := segments[len(segments)-1]

	chain := []string{path}
	for depth := len(segments) - 1; depth > 0; depth-- {
		candidate := strings.Join(append(append([]string{}, segments[:depth-1]...), leaf), "/")
		if candidate != chain[len(chain)-1] {
			chain = append(chain, candidate)
		}
	}
	return chain
}

func PolicyPath(tenant, path string) string {
	return Namespace + "/" + tenant + "/" + path
}
