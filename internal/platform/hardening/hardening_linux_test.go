//go:build linux

package hardening

import (
	"syscall"
	"testing"
)

const prGetDumpable = 3

func TestCoreDumpsAreActuallyDisabled(t *testing.T) {
	if err := disableCoreDumps(); err != nil {
		t.Fatalf("disableCoreDumps returned error: %v", err)
	}

	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &limit); err != nil {
		t.Fatalf("reading the core dump limit: %v", err)
	}
	if limit.Cur != 0 || limit.Max != 0 {
		t.Errorf("core dump limit = %+v, want both bounds at zero", limit)
	}
}

func TestTheProcessIsActuallyUndumpable(t *testing.T) {
	if err := hideProcessMemory(); err != nil {
		t.Fatalf("hideProcessMemory returned error: %v", err)
	}

	value, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 {
		t.Fatalf("reading the dumpable flag: %v", errno)
	}
	if value != 0 {
		t.Errorf("dumpable = %d, want 0", value)
	}
}

func TestLockMemoryReportsWhyItFailed(t *testing.T) {
	err := lockMemory()
	if err == nil {
		return
	}
	if err != syscall.ENOMEM && err != syscall.EPERM {
		t.Fatalf("lockMemory failed with an unexpected error: %v", err)
	}
	t.Logf("memory could not be locked in this environment: %v", err)
}
