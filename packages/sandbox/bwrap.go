//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

func osBackend() Backend { return bwrapBackend{} }

// statDenyPath reports whether a deny path exists and whether it is a regular file. buildBwrapArgv
// skips missing paths: nothing to hide, and the mountpoint cannot be created under the ro root bind.
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
func (bwrapBackend) Preflight(spec Spec) (PreflightResult, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return PreflightResult{
			Supported: false,
			Reason:    "bubblewrap is not installed; install it with your package manager or re-run with --no-sandbox",
		}, nil
	}

	if spec.NetMode == SharedNet {
		// Caller already asked for shared net; nothing to probe.
		return PreflightResult{Supported: true, UsesBridge: false}, nil
	}

	if hardFenceWorks(bwrapPath) {
		return PreflightResult{Supported: true, UsesBridge: true}, nil
	}

	// Before downgrading, check whether bwrap can make a user namespace at all. If it cannot (stock
	// Ubuntu 24.04 restricts this), the shared-net fallback would also die at "setting up uid map", so
	// falling back would swap a clear error for a raw bwrap crash. Report unsupported instead.
	if !sharedNetWorks(bwrapPath) {
		return PreflightResult{
			Supported: false,
			Reason: "the OS sandbox cannot start because unprivileged user namespaces are restricted on this host; " +
				"allow them in your system settings or re-run with --no-sandbox",
		}, nil
	}

	// User namespaces work but the empty-netns hard fence does not. Fall back to shared host networking.
	// Credential controls are unaffected; only the network fence weakens.
	return PreflightResult{
		Supported:           true,
		FallbackToSharedNet: true,
		UsesBridge:          false,
		Reason:              "a private network namespace is unavailable on this host",
	}, nil
}

// probeBwrap runs bwrap with the shared base flags plus extra, and reports whether it exited cleanly.
func probeBwrap(bwrapPath string, extra []string, command ...string) bool {
	args := append(bwrapBaseArgs(), extra...)
	args = append(append(args, "--"), command...)
	// #nosec G204 -- base flags are fixed and the command is one of this file's own literals
	return exec.Command(bwrapPath, args...).Run() == nil
}

// sharedNetWorks probes whether bwrap can start a user-namespaced sandbox that shares host networking.
// It reuses the real argv's base flags, so a success here means the fallback can run.
func sharedNetWorks(bwrapPath string) bool {
	return probeBwrap(bwrapPath, []string{"--share-net"}, "true")
}

// hardFenceWorks probes whether an empty-netns bwrap can start and bring loopback up.
func hardFenceWorks(bwrapPath string) bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	return probeBwrap(bwrapPath, nil, self, SupervisorSubcommand, "--probe")
}

func (bwrapBackend) Wrap(spec Spec, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, errEmptyCommand
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
	full[0] = bwrapPath
	return newInheritedCmd(full, spec.Env), nil
}
