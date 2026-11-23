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

// Windows has no controlling terminal; a console or Git Bash (mintty) on stdin stands in for one.
func personAtTerminal() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func signalCommand(child *exec.Cmd, sig os.Signal, _ bool) {
	_ = child.Process.Signal(sig)
}

func killCommand(child *exec.Cmd, _ bool) {
	_ = child.Process.Kill()
}
