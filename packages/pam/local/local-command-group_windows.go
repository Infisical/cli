package pam

import (
	"os"
	"os/exec"
)

func startInOwnGroup(*exec.Cmd) {}

func hasControllingTerminal() bool {
	return true
}

func signalCommand(child *exec.Cmd, sig os.Signal, _ bool) {
	_ = child.Process.Signal(sig)
}

func killCommand(child *exec.Cmd, _ bool) {
	_ = child.Process.Kill()
}
