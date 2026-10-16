//go:build unix

package cdp

import (
	"os/exec"
	"syscall"
)

// Chromium forks a zygote and renderers; its own process group lets Stop kill them all.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
