//go:build !darwin && !linux

package sandbox

import "os/exec"

func osBackend() Backend { return unsupportedBackend{} }

// unsupportedBackend is the OS sandbox on platforms without one (e.g. Windows). Preflight reports
// unsupported so the run command errors unless the user passed --no-sandbox (which selects the
// passthrough backend instead and never reaches here).
type unsupportedBackend struct{}

func (unsupportedBackend) Preflight(SandboxSpec) (PreflightResult, error) {
	return PreflightResult{
		Supported: false,
		Reason:    "the OS sandbox is not available on this platform (macOS and Linux only in v1); re-run with --no-sandbox to run uncontained",
	}, nil
}

func (unsupportedBackend) Wrap(SandboxSpec, []string) (*exec.Cmd, error) {
	return nil, errUnsupportedPlatform
}
