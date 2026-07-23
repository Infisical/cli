//go:build !darwin && !linux

package sandbox

import "os/exec"

func osBackend() Backend { return unsupportedBackend{} }

// unsupportedBackend is used on platforms without an OS sandbox (e.g. Windows).
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
