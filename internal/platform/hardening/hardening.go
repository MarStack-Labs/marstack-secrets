package hardening

import (
	"errors"
	"fmt"
	"log/slog"
)

var ErrUnsupported = errors.New("hardening: process protections are not available on this platform")

type Report struct {
	MemoryLocked       bool
	CoreDumpsDisabled  bool
	ProcessNotDumpable bool
}

func (r Report) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("memory_locked", r.MemoryLocked),
		slog.Bool("core_dumps_disabled", r.CoreDumpsDisabled),
		slog.Bool("process_not_dumpable", r.ProcessNotDumpable),
	)
}

func Apply() (Report, error) {
	var report Report
	var problems []error

	if err := lockMemory(); err != nil {
		problems = append(problems, fmt.Errorf("locking memory: %w", err))
	} else {
		report.MemoryLocked = true
	}

	if err := disableCoreDumps(); err != nil {
		problems = append(problems, fmt.Errorf("disabling core dumps: %w", err))
	} else {
		report.CoreDumpsDisabled = true
	}

	if err := hideProcessMemory(); err != nil {
		problems = append(problems, fmt.Errorf("making the process undumpable: %w", err))
	} else {
		report.ProcessNotDumpable = true
	}

	return report, errors.Join(problems...)
}
