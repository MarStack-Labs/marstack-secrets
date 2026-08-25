package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
)

const (
	maxNameLen    = 128
	maxPatternLen = 512
	maxRules      = 256
	wildcard      = "*"
)

var (
	ErrEmptyName       = errors.New("policy: name must not be empty")
	ErrLongName        = errors.New("policy: name is too long")
	ErrNoRules         = errors.New("policy: at least one rule is required")
	ErrTooManyRules    = errors.New("policy: too many rules")
	ErrEmptyPattern    = errors.New("policy: rule path must not be empty")
	ErrLongPattern     = errors.New("policy: rule path is too long")
	ErrBadPattern      = errors.New("policy: rule path may only use a trailing wildcard")
	ErrTraversal       = errors.New("policy: rule path must not contain a traversal or an empty segment")
	ErrNoCapabilities  = errors.New("policy: rule grants no capabilities")
	ErrBadCapability   = errors.New("policy: unknown capability")
	ErrDenyWithGrant   = errors.New("policy: a rule that denies must not also grant")
	ErrDuplicatePath   = errors.New("policy: the same path appears twice in one policy")
	ErrInvalidPath     = errors.New("policy: path is empty, too long, or contains a traversal")
	ErrBadRequestedCap = errors.New("policy: deny is not a capability that can be requested")
)

type Rule struct {
	Path         string
	Capabilities []authz.Capability
}

type Policy struct {
	Name  string
	Rules []Rule
}

type Set []Policy

func New(name string, rules []Rule) (Policy, error) {
	switch {
	case name == "":
		return Policy{}, ErrEmptyName
	case len(name) > maxNameLen:
		return Policy{}, ErrLongName
	case len(rules) == 0:
		return Policy{}, ErrNoRules
	case len(rules) > maxRules:
		return Policy{}, ErrTooManyRules
	}

	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if err := validateRule(rule); err != nil {
			return Policy{}, fmt.Errorf("%w: %q", err, rule.Path)
		}
		if _, repeated := seen[rule.Path]; repeated {
			return Policy{}, fmt.Errorf("%w: %q", ErrDuplicatePath, rule.Path)
		}
		seen[rule.Path] = struct{}{}
	}

	return Policy{Name: name, Rules: rules}, nil
}

func (s Set) Evaluate(path string, requested authz.Capability) authz.Decision {
	if !requested.Grantable() {
		return authz.Decision{Reason: "the requested capability cannot be granted"}
	}
	if err := ValidatePath(path); err != nil {
		return authz.Decision{Reason: "the requested path is not acceptable"}
	}

	var best *candidate

	for _, policy := range s {
		for _, rule := range policy.Rules {
			if !matches(rule.Path, path) {
				continue
			}
			if grants(rule, authz.Deny) {
				return authz.Decision{
					Policy: policy.Name,
					Rule:   rule.Path,
					Reason: "an explicitly denying rule matched, and denial always wins",
				}
			}
			current := candidate{policy: policy.Name, rule: rule}
			if best == nil || current.beats(*best) {
				best = &current
			}
		}
	}

	if best == nil {
		return authz.Decision{Reason: "no rule matched, and the default is to deny"}
	}
	if !grants(best.rule, requested) {
		return authz.Decision{
			Policy: best.policy,
			Rule:   best.rule.Path,
			Reason: fmt.Sprintf("the most specific matching rule does not grant %q", requested),
		}
	}

	return authz.Decision{
		Allowed: true,
		Policy:  best.policy,
		Rule:    best.rule.Path,
		Reason:  fmt.Sprintf("the most specific matching rule grants %q", requested),
	}
}

type candidate struct {
	policy string
	rule   Rule
}

func (c candidate) exact() bool {
	return !strings.HasSuffix(c.rule.Path, wildcard)
}

func (c candidate) reach() int {
	return len(strings.TrimSuffix(c.rule.Path, wildcard))
}

func (c candidate) beats(other candidate) bool {
	switch {
	case c.exact() != other.exact():
		return c.exact()
	case c.reach() != other.reach():
		return c.reach() > other.reach()
	default:
		return false
	}
}

func matches(pattern, path string) bool {
	if prefix, wild := strings.CutSuffix(pattern, wildcard); wild {
		return strings.HasPrefix(path, prefix)
	}
	return pattern == path
}

func grants(rule Rule, requested authz.Capability) bool {
	for _, granted := range rule.Capabilities {
		if granted == requested {
			return true
		}
	}
	return false
}

func ValidatePath(path string) error {
	if path == "" || len(path) > maxPatternLen || !safeSegments(path) {
		return ErrInvalidPath
	}
	return nil
}

func validateRule(rule Rule) error {
	pattern := rule.Path

	switch {
	case pattern == "":
		return ErrEmptyPattern
	case len(pattern) > maxPatternLen:
		return ErrLongPattern
	case strings.Count(pattern, wildcard) > 1:
		return ErrBadPattern
	case strings.Contains(pattern, wildcard) && !strings.HasSuffix(pattern, wildcard):
		return ErrBadPattern
	case !safeSegments(strings.TrimSuffix(pattern, wildcard)):
		return ErrTraversal
	case len(rule.Capabilities) == 0:
		return ErrNoCapabilities
	}

	denies := false
	grantsSomething := false
	for _, capability := range rule.Capabilities {
		if !capability.Valid() {
			return ErrBadCapability
		}
		if capability == authz.Deny {
			denies = true
			continue
		}
		grantsSomething = true
	}
	if denies && grantsSomething {
		return ErrDenyWithGrant
	}
	return nil
}

func safeSegments(path string) bool {
	if path == "" {
		return true
	}
	if strings.Contains(path, "//") || strings.HasPrefix(path, "/") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == ".." || segment == "." {
			return false
		}
		if strings.TrimSpace(segment) != segment {
			return false
		}
	}
	return true
}
