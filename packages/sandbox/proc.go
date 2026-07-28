package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

var errEmptyCommand = errors.New("sandbox: empty command")

// newInheritedCmd returns an *exec.Cmd for full argv with the caller's stdio inherited and the given
// environment, ready to Start.
func newInheritedCmd(argv []string, env []string) *exec.Cmd {
	// #nosec G204 -- the wrapped command is provided directly by the operator running the CLI
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	return cmd
}

// ForwardTerminationSignals relays SIGINT/SIGTERM/SIGHUP/SIGQUIT to cmd until stop is called.
// Only these: notifying on ALL signals also delivers SIGURG (Go's async-preemption signal, fired
// constantly) and SIGCHLD, which race the child's exit path and corrupt its status into 255.
// Terminal signals like Ctrl-C reach the child directly through the shared foreground group.
func ForwardTerminationSignals(cmd *exec.Cmd) (stop func()) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(sigCh)
	}
}

// WaitExitCode maps Wait's error to the child's exit code. ok is false when the error is not an exit
// status at all (never started, or wait itself failed); the code is then 1 for the caller to report.
func WaitExitCode(err error) (code int, ok bool) {
	if err == nil {
		return 0, true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, wsOk := exitErr.Sys().(syscall.WaitStatus); wsOk {
			return ws.ExitStatus(), true
		}
	}
	return 1, false
}
