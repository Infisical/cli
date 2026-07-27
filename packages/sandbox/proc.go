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

// ForwardTerminationSignals relays process-directed termination signals (SIGINT, SIGTERM, SIGHUP,
// SIGQUIT) to cmd's process until the returned stop func is called. Forward only these: notifying on
// ALL signals also delivers SIGURG (the Go runtime's async-preemption signal, fired constantly) and
// SIGCHLD, which would be spammed at the child and race its exit path, intermittently corrupting its
// exit status into 255. Terminal-generated signals (Ctrl-C, SIGWINCH, Ctrl-Z) reach the child
// directly: it shares the controlling terminal's foreground process group.
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

// WaitExitCode maps (*exec.Cmd).Wait's error to the child's exit code. ok is false when the error is
// not an exit status (e.g. the process never started or wait itself failed); the code is then 1 and
// the caller decides how to report the error.
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
