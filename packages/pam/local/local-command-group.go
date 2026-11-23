//go:build !windows

package pam

import (
	"os"
	"os/exec"
	"syscall"
)

// Without a controlling terminal nothing relies on the foreground process group, so the command gets
// a group of its own and stopping it also stops anything it started.
func startInOwnGroup(child *exec.Cmd) {
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	setParentDeathSignal(child.SysProcAttr)
}

// hasControllingTerminal also catches a terminal reachable only through /dev/tty, where a child in
// a background group would be stopped the moment it prompted.
func hasControllingTerminal() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	tty.Close()
	return true
}

func personAtTerminal() bool {
	return hasControllingTerminal()
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
