//go:build !windows && !linux

package pam

import "syscall"

func setParentDeathSignal(*syscall.SysProcAttr) {}
