package hardening

import (
	"bytes"
	"errors"
	"log/slog"
	"runtime"
	"testing"
)

func TestApplyMatchesThePlatform(t *testing.T) {
	report, err := Apply()

	if runtime.GOOS != "linux" {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Apply on %s = %v, want ErrUnsupported", runtime.GOOS, err)
		}
		if report.MemoryLocked || report.CoreDumpsDisabled || report.ProcessNotDumpable {
			t.Errorf("Apply on %s reported %+v, want nothing applied", runtime.GOOS, report)
		}
		return
	}

	if !report.CoreDumpsDisabled {
		t.Errorf("core dumps were not disabled on linux: %v", err)
	}
	if !report.ProcessNotDumpable {
		t.Errorf("the process was not made undumpable on linux: %v", err)
	}
	if !report.MemoryLocked {
		t.Logf("memory was not locked, which needs CAP_IPC_LOCK or an unlimited memlock rlimit: %v", err)
	}
}

func TestReportIsLoggedAsAGroup(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buffer, nil))

	logger.Info("applied", "hardening", Report{MemoryLocked: true})

	rendered := buffer.String()
	for _, field := range []string{"memory_locked", "core_dumps_disabled", "process_not_dumpable"} {
		if !bytes.Contains([]byte(rendered), []byte(field)) {
			t.Errorf("the log record is missing %q: %s", field, rendered)
		}
	}
}
