package pam

import (
	"os"
	"os/exec"

	"github.com/mattn/go-isatty"
)

func startInOwnGroup(*exec.Cmd) {}

func hasControllingTerminal() bool {
	return true
}

// Windows has no controlling terminal; output to a console or Git Bash (mintty) stands in for one.
func personAtTerminal() bool {
	for _, fd := range []uintptr{os.Stdout.Fd(), os.Stderr.Fd()} {
		if isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd) {
			return true
		}
	}
	return false
}

func signalCommand(child *exec.Cmd, sig os.Signal, _ bool) {
	_ = child.Process.Signal(sig)
}

func killCommand(child *exec.Cmd, _ bool) {
	_ = child.Process.Kill()
}
