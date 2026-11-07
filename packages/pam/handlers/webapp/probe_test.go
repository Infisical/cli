package webapp

import (
	"context"
	"errors"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

type probeDocker struct {
	dockerSpy
	run     []string
	output  string
	runErr  error
	cleaned bool
}

func (d *probeDocker) Command(ctx context.Context, args ...string) (string, error) {
	if args[0] == "run" {
		d.run = append([]string{}, args...)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 20*time.Second {
			return "", errors.New("missing probe deadline")
		}
		index := slices.Index(args, "--cidfile")
		if index < 0 {
			return "", errors.New("missing container ID receipt")
		}
		if err := os.WriteFile(args[index+1], []byte("recorded-probe-id"), 0600); err != nil {
			return "", err
		}
		return d.output, d.runErr
	}
	if args[0] == "rm" && args[2] == "recorded-probe-id" {
		d.cleaned = true
	}
	return "", nil
}
func TestWorkerNetworkProbeContract(t *testing.T) {
	prior := session.GetSessionRecordingDir()
	session.SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { session.SetSessionRecordingPath(prior) })
	for _, success := range []bool{true, false} {
		d := &probeDocker{output: `{"ok":true}`}
		if !success {
			d.output = "{\"ok\":false,\"message\":\"fixture.pam.local: no such host\"}\nDocker exit 1"
			d.runErr = errors.New("Docker exit 1")
		}
		options := DefaultOptions()
		options.Image = "task-image"
		options.EgressNetwork = "task-network"
		err := probeFromNetwork(t.Context(), d, options, "task-gateway", "fixture.pam.local", 8081)
		if success && err != nil {
			t.Fatal(err)
		}
		if !success && (err == nil || err.Error() != "fixture.pam.local: no such host") {
			t.Fatalf("probe error: %v", err)
		}
		command := strings.Join(d.run, " ")
		for _, required := range []string{"--network task-network", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--memory 64m", "--pids-limit 32", "infisical.pam.gateway=task-gateway", "infisical.pam.session=", "infisical.pam.probe=1", "pam browser-connector --probe fixture.pam.local:8081"} {
			if !strings.Contains(command, required) {
				t.Errorf("missing %q in %q", required, command)
			}
		}
		if !d.cleaned {
			t.Fatal("probe cleanup did not use recorded container ID")
		}
	}
}
