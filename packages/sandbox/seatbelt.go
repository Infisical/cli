//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

const sandboxExecPath = "/usr/bin/sandbox-exec"

func osBackend() Backend { return seatbeltBackend{} }

type seatbeltBackend struct{}

func (seatbeltBackend) Preflight(Spec) (PreflightResult, error) {
	if _, err := os.Stat(sandboxExecPath); err != nil {
		return PreflightResult{
			Supported: false,
			Reason:    fmt.Sprintf("unable to find %s, so the sandbox cannot start on this host", sandboxExecPath),
		}, nil
	}
	return PreflightResult{Supported: true}, nil
}

// Wrap builds `sandbox-exec -p <profile> <argv...>`; the profile is passed inline, never on disk.
func (seatbeltBackend) Wrap(spec Spec, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, errEmptyCommand
	}
	profile := generateSeatbeltProfile(spec)
	full := append([]string{sandboxExecPath, "-p", profile}, argv...)
	return newInheritedCmd(full, spec.Env), nil
}
