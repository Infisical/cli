//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

func osBackend() Backend { return bwrapBackend{} }

// statDenyPath reports whether a deny path exists and, if so, whether it is a regular file. A missing
// path is skipped by buildBwrapArgv (nothing to hide, and the mountpoint can't be created under the
// read-only root bind).
func statDenyPath(path string) (exists, isFile bool) {
	info, err := os.Stat(path)
	if err != nil {
		return false, false
	}
	return true, info.Mode().IsRegular()
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

	// The hard fence probe failed. Before downgrading to shared net, check whether bwrap can create a
	// user namespace at all: if it cannot (e.g. Ubuntu 24.04 with unprivileged userns fully restricted),
	// the shared-net fallback would also die at "setting up uid map", so falling back would only trade a
	// clear error for a raw bwrap crash. In that case report unsupported with actionable guidance.
	if !sharedNetWorks(bwrapPath) {
		return PreflightResult{
			Supported: false,
			Reason: "the OS sandbox cannot start: unprivileged user namespaces are restricted on this host " +
				"(e.g. Ubuntu 24.04 AppArmor). Allow them with `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` " +
				"(or install an AppArmor profile permitting bwrap user namespaces), or re-run with --no-sandbox to skip the sandbox.",
		}, nil
	}

	// User namespaces work but the empty-netns hard fence does not. Fall back to shared host networking.
	// Credential controls are unaffected; only the network fence weakens.
	return PreflightResult{
		Supported:           true,
		FallbackToSharedNet: true,
		UsesBridge:          false,
		Reason:              "the empty-netns hard fence is unavailable on this host. To restore it, install an AppArmor profile allowing bwrap user namespaces or set kernel.apparmor_restrict_unprivileged_userns=0",
	}, nil
}

// sharedNetWorks probes whether bwrap can start a user-namespaced sandbox that shares host networking.
// It mirrors the shared-net fallback's own bwrap flags, so a success here means the fallback can run.
func sharedNetWorks(bwrapPath string) bool {
	// #nosec G204 -- fixed argv, no user input
	cmd := exec.Command(bwrapPath,
		"--unshare-all", "--share-net", "--die-with-parent",
		"--ro-bind", "/", "/",
		"--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
		"--", "true",
	)
	return cmd.Run() == nil
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

	full := buildBwrapArgv(spec, self, argv, statDenyPath)
	// #nosec G204 -- the wrapped command is provided directly by the operator running the CLI
	cmd := exec.Command(bwrapPath, full[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = spec.Env
	return cmd, nil
}
