//go:build !darwin && !linux

package sandbox

import (
	"errors"
	"os/exec"
)

var errUnsupportedPlatform = errors.New("sandbox: unsupported platform")

func osBackend() Backend { return unsupportedBackend{} }

// unsupportedBackend is used on platforms without an OS sandbox (e.g. Windows).
type unsupportedBackend struct{}

func (unsupportedBackend) Preflight(Spec) (PreflightResult, error) {
	return PreflightResult{
		Supported: false,
		Reason:    "the OS sandbox is not available on this platform (macOS and Linux only in v1); re-run with --no-sandbox to run uncontained",
	}, nil
}

func (unsupportedBackend) Wrap(Spec, []string) (*exec.Cmd, error) {
	return nil, errUnsupportedPlatform
}
