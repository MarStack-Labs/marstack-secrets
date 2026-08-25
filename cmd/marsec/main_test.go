package main

import (
	"strings"
	"testing"
)

func TestRunRequiresACommand(t *testing.T) {
	err := run(nil)
	if err == nil {
		t.Fatal("expected an error when no command is given")
	}
	if !strings.Contains(err.Error(), "missing command") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	err := run([]string{"unseal"})
	if err == nil {
		t.Fatal("expected an error for an unknown command")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunHandlesHelp(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		if err := run([]string{arg}); err != nil {
			t.Errorf("run(%q) returned error: %v", arg, err)
		}
	}
}

func TestRunPrintsVersion(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("run(version) returned error: %v", err)
	}
	if version == "" {
		t.Error("version should never be empty")
	}
}
