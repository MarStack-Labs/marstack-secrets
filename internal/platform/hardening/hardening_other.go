//go:build !linux

package hardening

func lockMemory() error {
	return ErrUnsupported
}

func disableCoreDumps() error {
	return ErrUnsupported
}

func hideProcessMemory() error {
	return ErrUnsupported
}
