package main

import (
	"bytes"
	"strings"
	"testing"
)

func operator(t *testing.T, dataDir string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runOperator(t.Context(), &out, append(args, "--data-dir", dataDir))
	return out.String(), err
}

func TestOperatorRegistersAnIdentityAndIssuesABootstrapToken(t *testing.T) {
	dataDir := t.TempDir()

	output, err := operator(t, dataDir, "identity", "add", "instance/web-01", "--tenant", "prod")
	if err != nil {
		t.Fatalf("identity add returned error: %v (%s)", err, output)
	}
	if !strings.Contains(output, "instance/web-01") {
		t.Errorf("output = %q", output)
	}

	output, err = operator(t, dataDir, "bootstrap", "instance/web-01")
	if err != nil {
		t.Fatalf("bootstrap returned error: %v (%s)", err, output)
	}
	token := strings.TrimSpace(output)
	if !strings.HasPrefix(token, "mss_") {
		t.Fatalf("bootstrap printed %q", output)
	}

	second, err := operator(t, dataDir, "bootstrap", "instance/web-01")
	if err != nil {
		t.Fatalf("a second bootstrap returned error: %v", err)
	}
	if strings.TrimSpace(second) == token {
		t.Error("two bootstrap tokens are identical")
	}
}

func TestOperatorRejectsBadInput(t *testing.T) {
	dataDir := t.TempDir()

	cases := map[string][]string{
		"unknown subcommand":   {"nonsense"},
		"identity without id":  {"identity", "add", "--tenant", "prod"},
		"identity no tenant":   {"identity", "add", "instance/web-01"},
		"unknown kind":         {"identity", "add", "instance/web-01", "--tenant", "prod", "--kind", "robot"},
		"bootstrap unknown":    {"bootstrap", "instance/nobody"},
		"bootstrap without id": {"bootstrap"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := operator(t, dataDir, args...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestOperatorDisableRevokesTokens(t *testing.T) {
	dataDir := t.TempDir()

	if _, err := operator(t, dataDir, "identity", "add", "instance/web-01", "--tenant", "prod"); err != nil {
		t.Fatalf("identity add returned error: %v", err)
	}
	if _, err := operator(t, dataDir, "bootstrap", "instance/web-01"); err != nil {
		t.Fatalf("bootstrap returned error: %v", err)
	}

	output, err := operator(t, dataDir, "identity", "disable", "instance/web-01")
	if err != nil {
		t.Fatalf("identity disable returned error: %v", err)
	}
	if !strings.Contains(output, "revoked 1 token") {
		t.Errorf("output = %q, want it to report one revoked token", output)
	}

	if _, err := operator(t, dataDir, "bootstrap", "instance/web-01"); err == nil {
		t.Error("a disabled identity still got a bootstrap token")
	}
}
