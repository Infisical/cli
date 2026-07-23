//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

func osBackend() Backend { return bwrapBackend{} }

func regularFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

type bwrapBackend struct{}

// Preflight checks bwrap is present and probes (by executing an empty-netns bwrap) whether the hard
// fence works here; if not (e.g. Ubuntu 24.04 userns restriction) it falls back to shared net.
func (bwrapBackend) Preflight(spec SandboxSpec) (PreflightResult, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return PreflightResult{
			Supported: false,
			Reason:    "bubblewrap (bwrap) is not installed; install it (e.g. `apt install bubblewrap`) or re-run with --no-sandbox",
		}, nil
	}

	if spec.NetMode == SharedNet {
		// Caller already asked for shared net; nothing to probe.
		return PreflightResult{Supported: true, UsesBridge: false}, nil
	}

	if hardFenceWorks(bwrapPath) {
		return PreflightResult{Supported: true, UsesBridge: true}, nil
	}

	// Empty-netns hard fence unavailable (most commonly the Ubuntu 24.04 userns restriction). Fall back
	// to shared host networking. Credential controls are unaffected; only the network fence weakens.
	return PreflightResult{
		Supported:           true,
		FallbackToSharedNet: true,
		UsesBridge:          false,
		Reason:              "unprivileged user namespaces appear restricted (e.g. Ubuntu 24.04 AppArmor). To restore the hard fence, install an AppArmor profile allowing bwrap userns or set kernel.apparmor_restrict_unprivileged_userns=0",
	}, nil
}

// hardFenceWorks probes whether an empty-netns bwrap can start and bring loopback up.
func hardFenceWorks(bwrapPath string) bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	// #nosec G204 -- fixed argv, no user input
	cmd := exec.Command(bwrapPath,
		"--unshare-all", "--die-with-parent",
		"--ro-bind", "/", "/",
		"--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
		"--", self, SupervisorSubcommand, "--probe",
	)
	return cmd.Run() == nil
}

func (bwrapBackend) Wrap(spec SandboxSpec, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("sandbox: empty command")
	}
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bubblewrap (bwrap) is not installed: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot resolve own executable for the sandbox supervisor: %w", err)
	}

	full := buildBwrapArgv(spec, self, argv, regularFileExists)
	// #nosec G204 -- the wrapped command is provided directly by the operator running the CLI
	cmd := exec.Command(bwrapPath, full[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = spec.Env
	return cmd, nil
}
