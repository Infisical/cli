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

func (seatbeltBackend) Preflight(SandboxSpec) (PreflightResult, error) {
	if _, err := os.Stat(sandboxExecPath); err != nil {
		return PreflightResult{
			Supported: false,
			Reason:    fmt.Sprintf("%s not found; cannot sandbox on this macOS host", sandboxExecPath),
		}, nil
	}
	return PreflightResult{Supported: true}, nil
}

// Wrap builds: sandbox-exec -p <profile> <argv...>. sandbox-exec takes the command directly (no --
// separator). The profile is passed inline via -p, never written to disk. Stdio is inherited so the
// interactive TUI works.
func (seatbeltBackend) Wrap(spec SandboxSpec, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("sandbox: empty command")
	}
	profile := generateSeatbeltProfile(spec)
	args := append([]string{"-p", profile}, argv...)
	// #nosec G204 -- the command is provided directly by the operator running the CLI
	cmd := exec.Command(sandboxExecPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = spec.Env
	return cmd, nil
}
