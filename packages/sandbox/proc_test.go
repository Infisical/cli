//go:build !windows

package sandbox

import (
	"os/exec"
	"syscall"
	"testing"
)

// A signalled child has no exit status of its own, so ExitStatus is -1 and a shell shows 255 whatever
// the signal was. Every caller hands this straight to os.Exit, so it reports what a shell would.
func TestWaitExitCodeReportsTheSignal(t *testing.T) {
	for _, tc := range []struct {
		name string
		sig  syscall.Signal
		want int
	}{
		{"SIGTERM", syscall.SIGTERM, 143},
		{"SIGINT", syscall.SIGINT, 130},
		{"SIGKILL", syscall.SIGKILL, 137},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sleep", "30")
			if err := cmd.Start(); err != nil {
				t.Fatalf("start: %v", err)
			}
			if err := cmd.Process.Signal(tc.sig); err != nil {
				t.Fatalf("signal: %v", err)
			}
			code, ok := WaitExitCode(cmd.Wait())
			if !ok || code != tc.want {
				t.Fatalf("got %d ok=%v, want %d", code, ok, tc.want)
			}
		})
	}
}

func TestWaitExitCodeKeepsAnOrdinaryStatus(t *testing.T) {
	if code, ok := WaitExitCode(exec.Command("sh", "-c", "exit 7").Run()); !ok || code != 7 {
		t.Fatalf("got %d ok=%v, want 7", code, ok)
	}
	if code, ok := WaitExitCode(nil); !ok || code != 0 {
		t.Fatalf("got %d ok=%v, want 0", code, ok)
	}
}
