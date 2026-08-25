package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-secrets/internal/platform/authz"
)

func must(t *testing.T, name string, rules ...Rule) Policy {
	t.Helper()
	policy, err := New(name, rules)
	if err != nil {
		t.Fatalf("New(%q) returned error: %v", name, err)
	}
	return policy
}

func rule(path string, capabilities ...authz.Capability) Rule {
	return Rule{Path: path, Capabilities: capabilities}
}

func TestAnEmptySetDeniesEverything(t *testing.T) {
	decision := Set{}.Evaluate("secret/prod/payment-api", authz.Read)

	if decision.Allowed {
		t.Fatal("an empty policy set allowed a read")
	}
	if !strings.Contains(decision.Reason, "default is to deny") {
		t.Errorf("reason = %q", decision.Reason)
	}
}

func TestAnExactRuleGrantsOnlyWhatItLists(t *testing.T) {
	set := Set{must(t, "payment", rule("secret/prod/payment-api", authz.Read))}

	granted := set.Evaluate("secret/prod/payment-api", authz.Read)
	if !granted.Allowed {
		t.Fatalf("read was denied: %s", granted.Reason)
	}
	if granted.Policy != "payment" || granted.Rule != "secret/prod/payment-api" {
		t.Errorf("decision = %+v", granted)
	}

	refused := set.Evaluate("secret/prod/payment-api", authz.Write)
	if refused.Allowed {
		t.Fatal("write was allowed by a read-only rule")
	}
	if !strings.Contains(refused.Reason, "does not grant") {
		t.Errorf("reason = %q", refused.Reason)
	}
}

func TestAWildcardMatchesByPrefix(t *testing.T) {
	set := Set{must(t, "reader", rule("secret/prod/*", authz.Read, authz.List))}

	for _, path := range []string{"secret/prod/payment-api", "secret/prod/a/b/c", "secret/prod/"} {
		if decision := set.Evaluate(path, authz.Read); !decision.Allowed {
			t.Errorf("%s was denied: %s", path, decision.Reason)
		}
	}
	for _, path := range []string{"secret/staging/payment-api", "param/prod/log_level", "secret/pro"} {
		if decision := set.Evaluate(path, authz.Read); decision.Allowed {
			t.Errorf("%s was allowed by a rule for secret/prod/*", path)
		}
	}
}

func TestDenialAlwaysWins(t *testing.T) {
	set := Set{
		must(t, "reader", rule("secret/prod/payment-api", authz.Read)),
		must(t, "guard", rule("secret/prod/*", authz.Deny)),
	}

	decision := set.Evaluate("secret/prod/payment-api", authz.Read)
	if decision.Allowed {
		t.Fatal("an exact grant beat an explicit denial")
	}
	if decision.Policy != "guard" {
		t.Errorf("policy = %q, want the denying policy to be named", decision.Policy)
	}
	if !strings.Contains(decision.Reason, "denial always wins") {
		t.Errorf("reason = %q", decision.Reason)
	}
}

func TestDenialWinsRegardlessOfRuleOrder(t *testing.T) {
	forwards := Set{must(t, "mixed",
		rule("secret/prod/*", authz.Deny),
		rule("secret/prod/payment-api", authz.Read),
	)}
	backwards := Set{must(t, "mixed",
		rule("secret/prod/payment-api", authz.Read),
		rule("secret/prod/*", authz.Deny),
	)}

	for name, set := range map[string]Set{"deny first": forwards, "deny last": backwards} {
		if set.Evaluate("secret/prod/payment-api", authz.Read).Allowed {
			t.Errorf("%s: the denial was skipped", name)
		}
	}
}

func TestTheMostSpecificRuleDecides(t *testing.T) {
	set := Set{must(t, "layered",
		rule("secret/*", authz.Read),
		rule("secret/prod/*", authz.Read, authz.Write),
		rule("secret/prod/payment-api", authz.Read),
	)}

	if decision := set.Evaluate("secret/prod/other", authz.Write); !decision.Allowed {
		t.Errorf("write on secret/prod/other was denied: %s", decision.Reason)
	}
	if decision := set.Evaluate("secret/prod/payment-api", authz.Write); decision.Allowed {
		t.Error("the exact read-only rule was overruled by a broader wildcard")
	}
	if decision := set.Evaluate("secret/staging/x", authz.Write); decision.Allowed {
		t.Error("write was allowed by the widest rule")
	}
}

func TestALongerPrefixBeatsAShorterOne(t *testing.T) {
	set := Set{must(t, "layered",
		rule("secret/*", authz.Read, authz.Write),
		rule("secret/prod/locked/*", authz.Read),
	)}

	if decision := set.Evaluate("secret/prod/locked/db", authz.Write); decision.Allowed {
		t.Errorf("the longer prefix did not win: %+v", decision)
	}
	if decision := set.Evaluate("secret/prod/open/db", authz.Write); !decision.Allowed {
		t.Errorf("the shorter prefix should still apply elsewhere: %s", decision.Reason)
	}
}

func TestSpecificityIsIndependentOfPolicyOrder(t *testing.T) {
	narrow := must(t, "narrow", rule("secret/prod/locked/*", authz.Read))
	wide := must(t, "wide", rule("secret/*", authz.Read, authz.Write))

	for name, set := range map[string]Set{
		"narrow first": {narrow, wide},
		"wide first":   {wide, narrow},
	} {
		if decision := set.Evaluate("secret/prod/locked/db", authz.Write); decision.Allowed {
			t.Errorf("%s: the narrower rule lost to ordering", name)
		}
	}
}

func TestDenyCannotBeRequested(t *testing.T) {
	set := Set{must(t, "guard", rule("secret/prod/*", authz.Deny))}

	decision := set.Evaluate("secret/prod/payment-api", authz.Deny)
	if decision.Allowed {
		t.Fatal("deny was granted as if it were a capability")
	}
	if !strings.Contains(decision.Reason, "cannot be granted") {
		t.Errorf("reason = %q", decision.Reason)
	}
}

func TestAnUnknownCapabilityIsRefused(t *testing.T) {
	set := Set{must(t, "reader", rule("secret/prod/*", authz.Read))}

	if set.Evaluate("secret/prod/payment-api", authz.Capability("sudo")).Allowed {
		t.Fatal("an unknown capability was granted")
	}
}

func TestTraversalCannotEscapeAPrefix(t *testing.T) {
	set := Set{must(t, "reader", rule("secret/prod/*", authz.Read))}

	for _, path := range []string{
		"secret/prod/../staging/db",
		"secret/prod/./db",
		"secret/prod//db",
		"",
		strings.Repeat("a", maxPatternLen+1),
	} {
		if decision := set.Evaluate(path, authz.Read); decision.Allowed {
			t.Errorf("%q was allowed", path)
		}
	}
}

func TestNewRejectsUnusableRules(t *testing.T) {
	cases := map[string]struct {
		name  string
		rules []Rule
		want  error
	}{
		"no name":            {name: "", rules: []Rule{rule("secret/*", authz.Read)}, want: ErrEmptyName},
		"long name":          {name: strings.Repeat("a", maxNameLen+1), rules: []Rule{rule("secret/*", authz.Read)}, want: ErrLongName},
		"no rules":           {name: "empty", rules: nil, want: ErrNoRules},
		"empty path":         {name: "p", rules: []Rule{rule("", authz.Read)}, want: ErrEmptyPattern},
		"long path":          {name: "p", rules: []Rule{rule(strings.Repeat("a", maxPatternLen+1), authz.Read)}, want: ErrLongPattern},
		"inner wildcard":     {name: "p", rules: []Rule{rule("secret/*/db", authz.Read)}, want: ErrBadPattern},
		"two wildcards":      {name: "p", rules: []Rule{rule("secret/*/*", authz.Read)}, want: ErrBadPattern},
		"traversal":          {name: "p", rules: []Rule{rule("secret/../etc/*", authz.Read)}, want: ErrTraversal},
		"absolute":           {name: "p", rules: []Rule{rule("/secret/*", authz.Read)}, want: ErrTraversal},
		"double slash":       {name: "p", rules: []Rule{rule("secret//db", authz.Read)}, want: ErrTraversal},
		"no capabilities":    {name: "p", rules: []Rule{rule("secret/*")}, want: ErrNoCapabilities},
		"unknown capability": {name: "p", rules: []Rule{rule("secret/*", authz.Capability("sudo"))}, want: ErrBadCapability},
		"deny with grant":    {name: "p", rules: []Rule{rule("secret/*", authz.Deny, authz.Read)}, want: ErrDenyWithGrant},
		"duplicate path": {
			name:  "p",
			rules: []Rule{rule("secret/*", authz.Read), rule("secret/*", authz.Write)},
			want:  ErrDuplicatePath,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(tc.name, tc.rules); !errors.Is(err, tc.want) {
				t.Fatalf("New = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewAcceptsAWholeStoreWildcard(t *testing.T) {
	set := Set{must(t, "root", rule("*", authz.Read, authz.Write, authz.List, authz.Delete, authz.Destroy))}

	for _, path := range []string{"secret/prod/db", "param/prod/log_level", "anything"} {
		if decision := set.Evaluate(path, authz.Write); !decision.Allowed {
			t.Errorf("%s was denied by a store-wide rule: %s", path, decision.Reason)
		}
	}
}

func TestEveryDecisionExplainsItself(t *testing.T) {
	set := Set{
		must(t, "reader", rule("secret/prod/*", authz.Read)),
		must(t, "guard", rule("secret/prod/locked/*", authz.Deny)),
	}

	for name, decision := range map[string]authz.Decision{
		"granted":     set.Evaluate("secret/prod/db", authz.Read),
		"not granted": set.Evaluate("secret/prod/db", authz.Write),
		"denied":      set.Evaluate("secret/prod/locked/db", authz.Read),
		"unmatched":   set.Evaluate("param/prod/x", authz.Read),
		"bad request": set.Evaluate("secret/prod/db", authz.Deny),
		"bad path":    set.Evaluate("secret/prod/../x", authz.Read),
	} {
		if decision.Reason == "" {
			t.Errorf("the %s decision carries no reason", name)
		}
	}
}
