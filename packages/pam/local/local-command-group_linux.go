package pam

import "syscall"

// A group of its own no longer dies with a SIGKILL sent to this process's group.
func setParentDeathSignal(attr *syscall.SysProcAttr) {
	attr.Pdeathsig = syscall.SIGKILL
}
