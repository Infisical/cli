//go:build !windows

package pam

import (
	"os"
	"os/exec"
	"syscall"
)

// Without a terminal nothing relies on the foreground process group, so the command gets a group of
// its own and stopping it also stops anything it started.
func startInOwnGroup(child *exec.Cmd) {
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func signalCommand(child *exec.Cmd, sig os.Signal, ownGroup bool) {
	if s, ok := sig.(syscall.Signal); ok && ownGroup {
		_ = syscall.Kill(-child.Process.Pid, s)
		return
	}
	_ = child.Process.Signal(sig)
}

func killCommand(child *exec.Cmd, ownGroup bool) {
	signalCommand(child, syscall.SIGKILL, ownGroup)
}
