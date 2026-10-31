//go:build !darwin && !linux

package sandbox

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
)

var errUnsupportedPlatform = errors.New("sandbox: unsupported platform")

func osBackend() Backend { return unsupportedBackend{} }

// unsupportedBackend is used on platforms without an OS sandbox (e.g. Windows).
type unsupportedBackend struct{}

func (unsupportedBackend) Preflight(Spec) (PreflightResult, error) {
	return PreflightResult{
		Supported: false,
		Reason: fmt.Sprintf("the OS sandbox is not available on %s; re-run with --no-sandbox to run the "+
			"agent uncontained (credentials are still brokered and the environment is still scrubbed)", runtime.GOOS),
	}, nil
}

func (unsupportedBackend) Wrap(Spec, []string) (*exec.Cmd, error) {
	return nil, errUnsupportedPlatform
}
